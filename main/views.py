from django.shortcuts import render,  redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.urls import reverse
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth import views as auth_views
from django.db.models import Count, Q
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from django.contrib.admin.views.decorators import staff_member_required
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.views import LoginView
from django.contrib.auth import login
import csv
from .models import InviteLink, RegisteredPerson, InviteUsageLog, StaffProfile
from .forms import RegisteredPersonForm,  InviteEntryForm, CreateInviteForm, InviteLinkForm, RegisteredPersonForm


class StaffLoginView(LoginView):
    """Custom login view for staff members"""
    template_name = 'login.html'
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
        """Handle already authenticated users"""
        user = request.user
        if user.is_authenticated:
            if hasattr(user, 'staffprofile'):
                return redirect('dashboard')
            else:
                messages.warning(request, 'Access denied. Staff profile not found.')
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
            return redirect('registration_success')
    else:
        form = RegisteredPersonForm()
    
    return render(request, 'invites/register.html', {
        'form': form,
        'invite': invite
    })

@login_required
def custom_logout(request):
    """Custom logout view"""
    user_name = request.user.get_full_name() or request.user.username
    logout(request)
    messages.info(request, f'You have been logged out successfully. Goodbye, {user_name}!')
    return redirect('login')

def invite_entry(request):
    """View for entering invite code"""
    if request.method == 'POST':
        form = InviteEntryForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['invite_code']
            try:
                invite = InviteLink.objects.get(token=token)
                
                # Log the usage attempt
                InviteUsageLog.objects.create(
                    invite=invite,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                if invite.is_usable:
                    request.session['invite_token'] = str(invite.token)
                    return redirect('register_person')
                else:
                    if invite.is_expired:
                        messages.error(request, 'This invitation link has expired.')
                    elif invite.current_uses >= invite.max_uses:
                        messages.error(request, 'This invitation link has been fully used.')
                    else:
                        messages.error(request, 'This invitation link is no longer active.')
            except InviteLink.DoesNotExist:
                messages.error(request, 'Invalid invitation code. Please check and try again.')
    else:
        form = InviteEntryForm()
    
    return render(request, 'invite_entry.html', {'form': form})

def register_person(request):
    """Registration form view - requires valid invite in session"""
    invite_token = request.session.get('invite_token')
    if not invite_token:
        messages.error(request, 'Please enter a valid invitation code first.')
        return redirect('invite_entry')
    
    try:
        invite = InviteLink.objects.get(token=invite_token)
        if not invite.is_usable:
            messages.error(request, 'This invitation is no longer valid.')
            del request.session['invite_token']
            return redirect('invite_entry')
    except InviteLink.DoesNotExist:
        messages.error(request, 'Invalid invitation.')
        del request.session['invite_token']
        return redirect('invite_entry')
    
    if request.method == 'POST':
        form = RegisteredPersonForm(request.POST)
        if form.is_valid():
            # Check if email already exists
            if RegisteredPerson.objects.filter(email=form.cleaned_data['email']).exists():
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
                invite.use_invite()
                
                # Update usage log
                usage_log = invite.usage_logs.filter(
                    ip_address=get_client_ip(request),
                    successful_registration=False
                ).first()
                if usage_log:
                    usage_log.successful_registration = True
                    usage_log.registered_person = registration
                    usage_log.save()
                
                # Clear session
                del request.session['invite_token']
                
                messages.success(request, 'Registration completed successfully!')
                return redirect('registration_success')
    else:
        form = RegisteredPersonForm()
    
    return render(request, 'register_person.html', {
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
            target_audience=form.cleaned_data.get('target_audience', '')
        )
        
        # Generate the full URL
        invite_url = request.build_absolute_uri(
            reverse('register_with_token', kwargs={'token': invite.token})
        )
        
        return JsonResponse({
            'success': True,
            'invite_url': invite_url,
            'token': str(invite.token),
            'expires_at': invite.expires_at.strftime('%Y-%m-%d %H:%M'),
            'remaining_limit': staff_profile.max_invites_per_day - staff_profile.invites_created_today - 1
        })
    
    return JsonResponse({'success': False, 'errors': form.errors})

def register_with_token(request, token):
    """Direct registration with token in URL"""
    try:
        invite = InviteLink.objects.get(token=token)
        
        # Log the usage attempt
        InviteUsageLog.objects.create(
            invite=invite,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        if invite.is_usable:
            request.session['invite_token'] = str(invite.token)
            return redirect('register_person')
        else:
            if invite.is_expired:
                messages.error(request, 'This invitation link has expired.')
            elif invite.current_uses >= invite.max_uses:
                messages.error(request, 'This invitation link has been fully used.')
            else:
                messages.error(request, 'This invitation link is no longer active.')
    except InviteLink.DoesNotExist:
        messages.error(request, 'Invalid invitation link.')
    
    return redirect('invite_entry')

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
    
    return render(request, 'invite_statistics.html', context)

@login_required
@permission_required('main.can_export_registrations')
def export_registrations(request):
    """Export registrations to CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="registrations.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'First Name', 'Last Name', 'Email', 'Phone', 'ID Number', 
        'Designation', 'Organisation', 'Activity', 'Bank', 'Account Number',
        'Registered At', 'Invite Created By', 'Verified'
    ])
    
    for person in RegisteredPerson.objects.select_related('invite'):
        writer.writerow([
            person.first_name,
            person.last_name,
            person.email,
            person.phone_number,
            person.id_number,
            person.designation,
            person.organisation,
            person.activity,
            person.bank,
            person.account_number,
            person.registered_at.strftime('%Y-%m-%d %H:%M:%S'),
            person.invite.created_by if person.invite else 'N/A',
            'Yes' if person.is_verified else 'No'
        ])
    
    return response


@login_required
def invite_dashboard(request):
    """Dashboard for staff to manage invites"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin:index')
    
    # Statistics
    today = timezone.now().date()
    stats = {
        'total_invites': InviteLink.objects.filter(created_by_user=request.user).count(),
        'active_invites': InviteLink.objects.filter(created_by_user=request.user, is_active=True).count(),
        'today_invites': staff_profile.invites_created_today,
        'total_registrations': RegisteredPerson.objects.filter(invite__created_by_user=request.user).count(),
        'pending_verifications': RegisteredPerson.objects.filter(
            invite__created_by_user=request.user, 
            is_verified=False
        ).count(),
    }
    
    # Recent invites
    recent_invites = InviteLink.objects.filter(
        created_by_user=request.user
    ).order_by('-created_at')[:5]
    
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
        return redirect('index')
    
    if request.method == 'POST':
        form = InviteLinkForm(request.POST)
        if form.is_valid():
            invite = form.save(commit=False)
            invite.created_by = request.user.get_full_name() or request.user.username
            invite.created_by_user = request.user
            invite.save()
            
            messages.success(request, f'Invitation link created successfully! Token: {invite.token}')
            return redirect('invite_details', token=invite.token)
    else:
        form = InviteLinkForm()
    
    return render(request, 'invites/create_invite.html', {
        'form': form,
        'staff_profile': staff_profile,
    })


@login_required
def invite_list(request):
    """List all invites created by current user"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin:index')
    
    invites = InviteLink.objects.filter(created_by_user=request.user).order_by('-created_at')
    
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
    })


@login_required
def invite_details(request, token):
    """Detailed view of a specific invite"""
    invite = get_object_or_404(InviteLink, token=token, created_by_user=request.user)
    
    # Get usage logs
    usage_logs = invite.usage_logs.all()[:10]
    
    # Get registration if exists
    registration = None
    try:
        registration = invite.registeredperson
    except RegisteredPerson.DoesNotExist:
        pass
    
    return render(request, 'invites/invite_details.html', {
        'invite': invite,
        'usage_logs': usage_logs,
        'registration': registration,
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
def registrations_list(request):
    """List all registrations for current user's invites"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('index')
    
    registrations = RegisteredPerson.objects.filter(
        invite__created_by_user=request.user
    ).order_by('-registered_at')
    
    # Filter by verification status
    verified_filter = request.GET.get('verified')
    if verified_filter == 'yes':
        registrations = registrations.filter(is_verified=True)
    elif verified_filter == 'no':
        registrations = registrations.filter(is_verified=False)
    
    # Search
    search_query = request.GET.get('search')
    if search_query:
        registrations = registrations.filter(
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(organisation__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(registrations, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'invites/registrations_list.html', {
        'page_obj': page_obj,
        'verified_filter': verified_filter,
        'search_query': search_query,
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
def export_registrations(request):
    """Export registrations to CSV"""
    try:
        staff_profile = request.user.staffprofile
    except StaffProfile.DoesNotExist:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin:index')
    
    registrations = RegisteredPerson.objects.filter(
        invite__created_by_user=request.user
    ).order_by('-registered_at')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="registrations_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'Full Name', 'Email', 'Phone', 'ID Number', 'Designation', 
        'Organisation', 'Activity', 'Bank', 'Account Number', 
        'Registered At', 'Verified', 'Invite Token'
    ])
    
    for reg in registrations:
        writer.writerow([
            reg.full_name, reg.email, reg.phone_number, reg.id_number,
            reg.designation, reg.organisation, reg.activity, reg.bank,
            reg.account_number, reg.registered_at.strftime('%Y-%m-%d %H:%M:%S'),
            'Yes' if reg.is_verified else 'No',
            str(reg.invite.token) if reg.invite else 'N/A'
        ])
    
    return response