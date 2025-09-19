from uuid import UUID
from venv import logger

from django.conf import settings
from django.shortcuts import render,  redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.urls import reverse, reverse_lazy
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth import views as auth_views, logout, get_user_model
from django.db.models import Count, Q
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from django.contrib.admin.views.decorators import staff_member_required
from django.utils import timezone
from datetime import timedelta, datetime
from django.contrib.auth.views import LoginView
from django.contrib.auth import login
import jwt

from reportlab.lib.units import cm

from . import models
from .models import InviteLink, RegisteredPerson, InviteUsageLog, StaffProfile
from .forms import RegisteredPersonForm, InviteEntryForm, CreateInviteForm, InviteLinkForm


class StaffLoginView(LoginView):
    """Custom login view for staff members"""
    template_name = 'invites/login.html'
    redirect_authenticated_user = True

    def get_success_url(self):
        """Redirect to dashboard after successful login"""
        user = self.request.user
        if hasattr(user, 'staffprofile'):
            messages.success(
                self.request,
                f'Welcome back, {user.get_full_name() or user.username}!'
            )
            return reverse_lazy('dashboard')
        else:
            messages.warning(self.request, 'Staff profile not found. Contact administrator.')
            return reverse_lazy('login')

    def form_invalid(self, form):
        """Handle invalid login attempts"""
        messages.error(self.request, 'Invalid username or password. Please try again.')
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            if hasattr(user, 'staffprofile'):
                return redirect('dashboard')
            else:
                logout(request)  # Log them out first
                #messages.warning(request, 'Access denied. Staff profile not found.')
                return redirect('login')
        return super().dispatch(request, *args, **kwargs)


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def register_with_invite(request, token):
    """Public registration view using invite token"""

    invite = get_object_or_404(InviteLink, token=token)
    
    # Log the invite usage attempt
    usage_log = InviteUsageLog.objects.create(
        invite=invite,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        successful_registration=False
    )
    
    # Check if invite is usable
    if not invite.is_usable:
        messages.error(request, 'This invitation link is no longer valid or has expired.')
        return render(request, 'invites/invite_expired.html', {'invite': invite})
    
    if request.method == 'POST':
        form = RegisteredPersonForm(request.POST)
        if form.is_valid():
            # Save the registration
            person = form.save(commit=False)
            person.invite = invite
            person.registration_ip = get_client_ip(request)
            person.save()
            
            # Mark invite as used
            invite.use_invite()
            
            # Update usage log
            usage_log.successful_registration = True
            usage_log.registered_person = person
            usage_log.save()
            
            messages.success(request, 'Registration completed successfully!')
            return redirect('reg_page')
    else:
        form = RegisteredPersonForm()
    
    return render(request, 'invites/register.html', {
        'form': form,
        'invite': invite
    })


def invite_entry(request, token=None):
    """Email gate before accessing the registration form for a specific invite token"""
    # Require a token to proceed with gating tied to a specific invite
    if token is None:
        messages.error(request, 'An invitation link is required to continue.')
    
    if request.method == 'POST':
        form = InviteEntryForm(request.POST)
        if form.is_valid():
            if token is None:
                # Cannot proceed without a token
                return render(request, 'invite_entry.html', {'form': form})
            email = form.cleaned_data['email']
            # If already registered with this invite token and email, block access
            if RegisteredPerson.objects.filter(email=email, invite__token=token).exists():
                messages.error(request, 'You have already registered using this invitation link.')
                return redirect('invite_entry_with_token', token=token)
            try:
                invite = InviteLink.objects.get(token=token)
            except InviteLink.DoesNotExist:
                messages.error(request, 'Invalid invitation link. Please check and try again.')
                return redirect('invite_entry_with_token', token=token)

            # Log the usage attempt
            InviteUsageLog.objects.create(
                invite=invite,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            # Check if the invite is usable
            if invite.is_usable:
                # Store both the token and the email in session to enforce gating
                request.session['invite_token'] = str(invite.token)
                request.session['invite_email'] = email
                return redirect('register_person')
            else:
                if invite.is_expired:
                    messages.error(request, 'This invitation link has expired.')
                else:
                    messages.error(request, 'This invitation link is no longer active.')
                return redirect('invite_entry_with_token', token=token)
    else:
        form = InviteEntryForm()

    return render(request, 'invite_entry.html', {'form': form})
@login_required
def custom_logout(request):
    """Custom logout view"""
    user_name = request.user.get_full_name() or request.user.username
    logout(request)
    messages.info(request, f'You have been logged out successfully. Goodbye, {user_name}!')
    return redirect('login')



def register_person(request):
    """Registration form view - requires valid invite in session and prior email gate"""
    invite_token = request.session.get('invite_token')
    if not invite_token:
        messages.error(request, 'Please enter your email via the invitation link first.')
        return redirect('invite_entry')
    
    try:
        invite = InviteLink.objects.get(token=invite_token)
        if not invite.is_usable:
            messages.error(request, 'This invitation is no longer valid.')
            if 'invite_token' in request.session:
                del request.session['invite_token']
            if 'invite_email' in request.session:
                del request.session['invite_email']
            return redirect('invite_entry_with_token', token=invite_token)
    except InviteLink.DoesNotExist:
        messages.error(request, 'Invalid invitation.')
        if 'invite_token' in request.session:
            del request.session['invite_token']
        if 'invite_email' in request.session:
            del request.session['invite_email']
        return redirect('invite_entry')
    
    gated_email = request.session.get('invite_email')
    
    if request.method == 'POST':
        form = RegisteredPersonForm(request.POST)
        if form.is_valid():
            # Enforce that the email used matches the gated email (if present)
            if gated_email and form.cleaned_data['email'].lower().strip() != gated_email.lower().strip():
                messages.error(request, 'Please use the same email you provided to access this form.')
            # Check duplicates
            elif RegisteredPerson.objects.filter(email=form.cleaned_data['email']).exists():
                messages.error(request, 'A person with this email is already registered.')
            elif RegisteredPerson.objects.filter(id_number=form.cleaned_data['id_number']).exists():
                messages.error(request, 'A person with this ID number is already registered.')
            else:
                # Create the registration
                registration = form.save(commit=False)
                registration.invite = invite
                registration.registration_ip = get_client_ip(request)
                registration.save()
                
                # Mark invite as used and log successful registration
                try:
                    invite.use_invite()
                except Exception:
                    pass

                # Update usage log if exists
                usage_log = getattr(invite, 'usage_logs', None)
                if usage_log is not None:
                    usage_log = invite.usage_logs.filter(
                        ip_address=get_client_ip(request),
                        successful_registration=False
                    ).first()
                    if usage_log:
                        usage_log.successful_registration = True
                        usage_log.registered_person = registration
                        usage_log.save()
                
                # Clear session
                for key in ('invite_token', 'invite_email'):
                    if key in request.session:
                        del request.session[key]
                
                messages.success(request, 'Registration completed successfully!')
                return redirect('reg_page')
    else:
        initial = {}
        if gated_email:
            initial['email'] = gated_email
        form = RegisteredPersonForm(initial=initial)
    
    return render(request, 'invites/register.html', {
        'form': form,
        'invite': invite
    })


def reg_page(request):
    return render(request, 'reg_page.html')

def invite_entry_page(request):
    if request.method == 'POST':
        invite_code = request.POST.get('invite_code', '').strip()

        try:
            # Try to validate that it's a UUID
            UUID(invite_code)
            return redirect('register_with_invite', invite_uuid=invite_code)
        except ValueError:
            messages.error(request, 'Invalid invite code. Please check and try again.')

    return render(request, 'invite_entry.html')



@login_required
def manage_invites(request):
    """Staff view to manage invitation links"""
    # Check if user has staff profile
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('invite_entry')
    
    if not staff_profile.can_create_invites:
        messages.error(request, 'You do not have permission to create invites.')
        return redirect('invite_entry')
    
    # Get invites (staff can see all or just their own based on permissions)
    if request.user.has_perm('main.can_manage_all_invites'):
        invites = InviteLink.objects.all()
    else:
        invites = InviteLink.objects.filter(created_by_user=request.user)
    
    # Get statistics
    today = timezone.now().date()
    stats = {
        'total_invites': invites.count(),
        'active_invites': invites.filter(is_active=True, expires_at__gt=timezone.now()).count(),
        'used_invites': invites.filter(current_uses__gte=models.F('max_uses')).count(),
        'expired_invites': invites.filter(expires_at__lte=timezone.now()).count(),
        'todays_invites': invites.filter(created_at__date=today).count(),
        'remaining_daily_limit': staff_profile.max_invites_per_day - staff_profile.invites_created_today,
    }
    
    create_form = CreateInviteForm()
    
    return render(request, 'manage_invites.html', {
        'invites': invites,
        'create_form': create_form,
        'stats': stats,
        'staff_profile': staff_profile
    })
User = get_user_model()

def sso_login(request):
    token = request.GET.get("token")
    if not token:
        return HttpResponseForbidden("Missing token")

    try:
        data = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        email = data.get("email")
        user = User.objects.get(email=email)

        login(request, user)  # create session
        return redirect("dashboard")  # or wherever you want them to land
    except jwt.ExpiredSignatureError:
        # token expired: redirect back to App A to get a new one
        next_url = f"http://localhost:8001/sso-login/"
        return redirect(f"https://192.168.100.187:8000/users/sso-redirect/?next={next_url}")
    except (jwt.InvalidTokenError, User.DoesNotExist):
        return HttpResponseForbidden("Invalid token")

@login_required
def sso_redirect_to_a(request):
    payload = {
        "username": request.user.username,
        "exp": datetime.utcnow() + timedelta(seconds=3600),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return redirect(f"http://192.168.100.187:8000/users/login/?token={token}")
@login_required
@require_http_methods(["POST"])
def create_invite(request):
    """Create a new invitation link"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'No permission'})
    
    if not staff_profile.can_create_more_invites:
        return JsonResponse({
            'success': False, 
            'error': f'Daily limit reached ({staff_profile.max_invites_per_day} invites per day)'
        })
    
    form = CreateInviteForm(request.POST)
    if form.is_valid():
        invite = InviteLink.create_invite(
            created_by=form.cleaned_data['created_by'] or request.user.get_full_name() or request.user.username,
            created_by_user=request.user,
            days_valid=form.cleaned_data['days_valid'],
            max_uses=form.cleaned_data['max_uses'],
            description=form.cleaned_data['description'],
            title=form.cleaned_data.get('title', '')
        )
        
        # Generate the full URL
        invite_url = request.build_absolute_uri(
            reverse('register_with_token', kwargs={'token': invite.token})
        )
        print(invite_url)
        return JsonResponse({
            'success': True,
            'invite_url': invite_url,
            'token': str(invite.token),
            'expires_at': invite.expires_at.strftime('%Y-%m-%d %H:%M'),
            'remaining_limit': staff_profile.max_invites_per_day - staff_profile.invites_created_today - 1
        })
    
    return JsonResponse({'success': False, 'errors': form.errors})

def register_with_token(request, token):
    """Direct registration with token in URL - redirect to email gate first"""
    # Always force the email entry step for this token
    return redirect('invite_entry_with_token', token=token)

@login_required
@permission_required('main.can_view_invite_stats')
def invite_statistics(request):
    """View invitation statistics"""
    # Get various statistics
    total_invites = InviteLink.objects.count()
    total_registrations = RegisteredPerson.objects.count()
    
    # Recent activity (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_invites = InviteLink.objects.filter(created_at__gte=thirty_days_ago)
    recent_registrations = RegisteredPerson.objects.filter(registered_at__gte=thirty_days_ago)
    
    # Usage statistics
    active_invites = InviteLink.objects.filter(is_active=True, expires_at__gt=timezone.now())
    expired_invites = InviteLink.objects.filter(expires_at__lte=timezone.now())
    fully_used_invites = InviteLink.objects.filter(current_uses__gte=models.F('max_uses'))
    
    context = {
        'total_invites': total_invites,
        'total_registrations': total_registrations,
        'recent_invites_count': recent_invites.count(),
        'recent_registrations_count': recent_registrations.count(),
        'active_invites_count': active_invites.count(),
        'expired_invites_count': expired_invites.count(),
        'fully_used_invites_count': fully_used_invites.count(),
        'conversion_rate': (total_registrations / total_invites * 100) if total_invites > 0 else 0,
    }
    
    return render(request, 'invites/invite_statistics.html', context)



@login_required
def invite_dashboard(request):
    """Dashboard for staff to manage invites"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('login')
    
    # Statistics
    today = timezone.now().date()
    stats = {
        'total_invites': InviteLink.objects.filter(created_by_user=request.user).count(),
        'active_invites': InviteLink.objects.filter(created_by_user=request.user, is_active=True, archived=False).count(),
        'today_invites': staff_profile.invites_created_today,
        'total_registrations': RegisteredPerson.objects.filter(invite__created_by_user=request.user).count(),
        'pending_verifications': RegisteredPerson.objects.filter(
            invite__created_by_user=request.user, 
            is_verified=False
        ).count(),
    }
    
    # Recent invites
    recent_invites = InviteLink.objects.filter(
        created_by_user=request.user,
        archived=False
    ).order_by('-created_at')[:5]
    for invite in recent_invites:
        invite.link = request.build_absolute_uri(
            reverse('register_with_token', kwargs={'token': invite.token})
        )

    # Recent registrations
    recent_registrations = RegisteredPerson.objects.filter(
        invite__created_by_user=request.user
    ).order_by('-registered_at')[:5]
    
    return render(request, 'invites/dashboard.html', {
        'staff_profile': staff_profile,
        'stats': stats,
        'recent_invites': recent_invites,
        'recent_registrations': recent_registrations,
    })


@login_required
def create_invite_link(request):
    """Create new invitation link"""
    try:
        staff_profile = request.user.staffprofile
        if not staff_profile.can_create_more_invites:
            messages.error(request, 'You have reached your daily invite limit or do not have permission to create invites.')
            return redirect('dashboard')
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to create invites.')
        return redirect('login')
    
    if request.method == 'POST':
        form = InviteLinkForm(request.POST)
        if form.is_valid():
            invite = form.save(commit=False)
            invite.created_by = request.user.get_full_name() or request.user.username
            invite.created_by_user = request.user
            invite.save()
            
            messages.success(request, 'Invitation link created successfully! You can find it on your dashboard.')
            return redirect('dashboard')
    else:
        form = InviteLinkForm()
    
    return render(request, 'invites/create_invite.html', {
        'form': form,
        'staff_profile': staff_profile,
    })


@login_required
def invite_list(request):
    """List invites created by current user. Hide archived by default; show all when requested."""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin:index')
    
    show_param = request.GET.get('show')
    show_all = show_param == 'all'

    invites = InviteLink.objects.filter(created_by_user=request.user)
    if not show_all:
        invites = invites.filter(archived=False)
    invites = invites.order_by('-created_at')
    for invite in invites:
        invite.link = request.build_absolute_uri(
            reverse('register_with_token', kwargs={'token': invite.token})
        )
    # Filter by status
    status_filter = request.GET.get('status')
    if status_filter == 'active':
        invites = invites.filter(is_active=True)
    elif status_filter == 'expired':
        invites = invites.filter(expires_at__lt=timezone.now())
    elif status_filter == 'used':
        invites = invites.filter(current_uses__gte=1)
    
    # Search
    search_query = request.GET.get('search')
    if search_query:
        invites = invites.filter(
            Q(description__icontains=search_query) |
            Q(target_audience__icontains=search_query) |
            Q(token__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(invites, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'invites/invite_list.html', {
        'page_obj': page_obj,
        'status_filter': status_filter,
        'search_query': search_query,
        'show_all': show_all,
    })


@login_required
def invite_details(request, token):
    """Detailed view of a specific invite"""
    invite = get_object_or_404(InviteLink, token=token, created_by_user=request.user)

    # Recent usage logs (limit to last 10)
    usage_logs = invite.usage_logs.all()[:10]

    # Build shareable link for this invite
    link = request.build_absolute_uri(
        reverse('register_with_token', kwargs={'token': invite.token})
    )

    # Gather registrations associated with this invite (may be empty)
    registrations = list(invite.registrations.all())

    return render(request, 'invites/invite_details.html', {
        'invite': invite,
        'usage_logs': usage_logs,
        'registrations': registrations,
        'link': link,
    })


@login_required
def toggle_invite_status(request, token):
    """Toggle invite active status"""
    invite = get_object_or_404(InviteLink, token=token, created_by_user=request.user)
    
    if request.method == 'POST':
        invite.is_active = not invite.is_active
        invite.save()
        
        status = 'activated' if invite.is_active else 'deactivated'
        messages.success(request, f'Invite has been {status}.')
    
    return redirect('invite_details', token=token)


@login_required
def toggle_invite_archive(request, token):
    """Toggle invite archived status"""
    invite = get_object_or_404(InviteLink, token=token, created_by_user=request.user)
    if request.method == 'POST':
        invite.archived = not invite.archived
        invite.save()
        if invite.archived:
            messages.success(request, 'Invite has been archived and will be hidden from the list by default.')
        else:
            messages.success(request, 'Invite has been unarchived and will appear in your list again.')
    # Redirect back to list keeping current filters
    referer = request.META.get('HTTP_REFERER')
    if referer:
        return redirect(referer)
    return redirect('invite_list')


@login_required
def registrations_list(request):
    """List registrations grouped by invite for current user"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('login')

    # Base queryset
    registrations_qs = (RegisteredPerson.objects
                        .select_related('invite')
                        .filter(invite__created_by_user=request.user)
                        .order_by('-registered_at'))

    # Filter by verification status
    verified_filter = request.GET.get('verified')
    if verified_filter == 'yes':
        registrations_qs = registrations_qs.filter(is_verified=True)
    elif verified_filter == 'no':
        registrations_qs = registrations_qs.filter(is_verified=False)

    # Filter by invite (group)
    selected_invite_token = request.GET.get('invite')
    if selected_invite_token:
        try:
            token_uuid = UUID(selected_invite_token)
            registrations_qs = registrations_qs.filter(invite__token=token_uuid)
        except Exception:
            # Ignore invalid token format
            pass

    # Search
    search_query = request.GET.get('search')
    if search_query:
        registrations_qs = registrations_qs.filter(
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(organisation__icontains=search_query)
        )

    # Group registrations by invite
    groups_map = {}
    for reg in registrations_qs:
        inv = reg.invite
        if not inv:
            # Skip registrations without an invite (shouldn't happen in this view)
            # Alternatively, could group under a special key
            continue
        gid = inv.pk
        if gid not in groups_map:
            groups_map[gid] = {
                'invite': inv,
                'registrations': [],
                'total': 0,
                'verified': 0,
                'pending': 0,
                'latest_registered_at': reg.registered_at,
            }
        group = groups_map[gid]
        group['registrations'].append(reg)
        group['total'] += 1
        if reg.is_verified:
            group['verified'] += 1
        else:
            group['pending'] += 1
        # Track latest registration time for sorting
        if reg.registered_at and (group['latest_registered_at'] is None or reg.registered_at > group['latest_registered_at']):
            group['latest_registered_at'] = reg.registered_at

    # Convert to list and sort by latest registration desc
    grouped_list = list(groups_map.values())
    grouped_list.sort(key=lambda g: (g['latest_registered_at'] or 0), reverse=True)

    # Pagination over groups (invites)
    paginator = Paginator(grouped_list, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Get invites list for filter select
    invites = InviteLink.objects.filter(created_by_user=request.user).order_by('-created_at')

    return render(request, 'invites/registrations_list.html', {
        'page_obj': page_obj,
        'verified_filter': verified_filter,
        'search_query': search_query,
        'is_grouped': True,
        'invites': invites,
        'selected_invite_token': selected_invite_token or '',
    })


@login_required
def verify_registration(request, pk):
    """Verify a registration"""
    registration = get_object_or_404(
        RegisteredPerson, 
        pk=pk, 
        invite__created_by_user=request.user
    )
    
    if request.method == 'POST':
        registration.is_verified = not registration.is_verified
        registration.verification_notes = request.POST.get('notes', '')
        registration.save()
        
        status = 'verified' if registration.is_verified else 'unverified'
        messages.success(request, f'Registration has been {status}.')
    
    return redirect('registrations_list')


@login_required
def usage_logs(request):
    """View usage logs for user's invites"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin:index')
    
    logs = InviteUsageLog.objects.filter(
        invite__created_by_user=request.user
    ).order_by('-used_at')
    
    # Filter by success
    success_filter = request.GET.get('success')
    if success_filter == 'yes':
        logs = logs.filter(successful_registration=True)
    elif success_filter == 'no':
        logs = logs.filter(successful_registration=False)
    
    # Pagination
    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'invites/usage_logs.html', {
        'page_obj': page_obj,
        'success_filter': success_filter,
    })



@login_required
def export_registrations_pdf(request):
    """
    Export registrations to PDF with improved error handling and formatting.
    Respects same query params as export_registrations.
    """
    # Check staff permissions
    try:
        staff_profile = request.user.staffprofile
    except AttributeError:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin:index')

    # Try to import reportlab components
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
        from reportlab.lib.units import cm
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError as e:
        logger.warning(f"PDF export failed - reportlab not available: {e}")
        messages.error(request, 'PDF export is not available (reportlab not installed).')
        referer = request.META.get('HTTP_REFERER') or reverse('registrations_list')
        return redirect(referer)

    # Build and filter queryset
    registrations = _build_registrations_queryset(request)

    if not registrations.exists():
        messages.warning(request, 'No registrations found matching your criteria.')
        referer = request.META.get('HTTP_REFERER') or reverse('registrations_list')
        return redirect(referer)

    # Generate PDF
    try:
        return _generate_pdf_response(registrations)
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        messages.error(request, 'An error occurred while generating the PDF.')
        referer = request.META.get('HTTP_REFERER') or reverse('registrations_list')
        return redirect(referer)


def _build_registrations_queryset(request):
    """Build and filter the registrations queryset based on request parameters."""
    registrations = RegisteredPerson.objects.filter(
        invite__created_by_user=request.user
    ).select_related('invite').order_by('-registered_at')

    export_all = request.GET.get('all') == '1'
    apply_filtered = request.GET.get('filtered') == '1'

    if not apply_filtered or export_all:
        return registrations

    # Apply verification filter
    verified_filter = request.GET.get('verified')
    if verified_filter in ['yes', 'no']:
        registrations = registrations.filter(is_verified=(verified_filter == 'yes'))

    # Apply invite filter
    selected_invite_token = request.GET.get('invite')
    if selected_invite_token:
        try:
            token_uuid = UUID(selected_invite_token)
            registrations = registrations.filter(invite__token=token_uuid)
        except (ValueError, TypeError):
            # Invalid UUID format - ignore this filter
            pass

    # Apply search filter
    search_query = request.GET.get('search', '').strip()
    if search_query:
        registrations = registrations.filter(
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(organisation__icontains=search_query)
        )

    return registrations


def _generate_pdf_response(registrations):
    """Generate the PDF response with registration data in table format."""
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from io import BytesIO

    # Create response
    timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="registrations_{timestamp}.pdf"'

    # Create a buffer to hold the PDF
    buffer = BytesIO()

    # Use landscape orientation to fit more columns
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4),
                            rightMargin=1 * cm, leftMargin=1 * cm,
                            topMargin=1 * cm, bottomMargin=1 * cm)

    # Build the PDF content
    story = []
    styles = getSampleStyleSheet()

    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=20,
        alignment=1  # Center alignment
    )
    story.append(Paragraph('Registration Export Report', title_style))

    # Metadata
    export_time = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=15
    )
    story.append(Paragraph(f'Generated on: {export_time} | Total Records: {registrations.count()}', meta_style))
    story.append(Spacer(1, 12))

    # Prepare table data
    table_data = _prepare_table_data(registrations)

    if table_data:
        # Create table
        table = Table(table_data, repeatRows=1)  # Repeat header row on each page

        # Apply table styling
        table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),

            # Data rows styling
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.beige, colors.white]),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))

        story.append(table)
    else:
        story.append(Paragraph('No registration data found.', styles['Normal']))

    # Build PDF
    doc.build(story)

    # Get the value of the BytesIO buffer and write it to the response
    pdf = buffer.getvalue()
    buffer.close()
    response.write(pdf)

    return response


def _prepare_table_data(registrations):
    """Prepare data for the PDF table."""
    # Define table headers
    headers = [
        'Full Name',
        'Email',
        'Phone',
        'Designation',
        'Organisation',
        'Registered At',
        'Verified',
        'Invite'
    ]

    # Start with headers
    table_data = [headers]

    # Add data rows
    for reg in registrations:
        # Format registration time
        reg_time = reg.registered_at.strftime('%Y-%m-%d\n%H:%M') if reg.registered_at else 'N/A'

        # Format verified status
        verified = 'Yes' if reg.is_verified else 'No'

        # Get invite title (truncate if too long)
        invite_title = reg.invite.title if reg.invite else 'N/A'
        if len(invite_title) > 20:
            invite_title = invite_title[:17] + '...'

        # Truncate long text fields to fit in table
        full_name = reg.full_name
        if len(full_name) > 25:
            full_name = full_name[:22] + '...'

        organisation = reg.organisation or 'N/A'
        if len(organisation) > 20:
            organisation = organisation[:17] + '...'

        designation = reg.designation or 'N/A'
        if len(designation) > 18:
            designation = designation[:15] + '...'

        row = [
            full_name,
            reg.email,
            reg.phone_number or 'N/A',
            designation,
            organisation,
            reg_time,
            verified,
            invite_title
        ]

        table_data.append(row)

    return table_data

