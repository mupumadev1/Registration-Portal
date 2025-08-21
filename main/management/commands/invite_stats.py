from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Count, Q
from main.models import InviteLink, RegisteredPerson, StaffProfile

class Command(BaseCommand):
    help = 'Display invitation system statistics'

    def handle(self, *args, **options):
        # Basic stats
        total_invites = InviteLink.objects.count()
        total_registrations = RegisteredPerson.objects.count()
        total_staff = StaffProfile.objects.count()
        
        # Invite status breakdown
        active_invites = InviteLink.objects.filter(
            is_active=True, 
            expires_at__gt=timezone.now()
        ).count()
        
        expired_invites = InviteLink.objects.filter(
            expires_at__lte=timezone.now()
        ).count()
        
        used_up_invites = InviteLink.objects.filter(
            current_uses__gte=models.F('max_uses')
        ).count()
        
        # Recent activity (last 7 days)
        seven_days_ago = timezone.now() - timezone.timedelta(days=7)
        recent_invites = InviteLink.objects.filter(
            created_at__gte=seven_days_ago
        ).count()
        
        recent_registrations = RegisteredPerson.objects.filter(
            registered_at__gte=seven_days_ago
        ).count()
        
        # Top staff creators
        top_creators = InviteLink.objects.values(
            'created_by'
        ).annotate(
            invite_count=Count('id')
        ).order_by('-invite_count')[:5]
        
        # Conversion rate
        conversion_rate = (total_registrations / total_invites * 100) if total_invites > 0 else 0
        
        # Display results
        self.stdout.write(self.style.SUCCESS('=== INVITATION SYSTEM STATISTICS ===\n'))
        
        self.stdout.write(f'📊 OVERVIEW:')
        self.stdout.write(f'   Total Invites: {total_invites}')
        self.stdout.write(f'   Total Registrations: {total_registrations}')
        self.stdout.write(f'   Total Staff: {total_staff}')
        self.stdout.write(f'   Conversion Rate: {conversion_rate:.1f}%\n')
        
        self.stdout.write(f'📈 INVITE STATUS:')
        self.stdout.write(f'   Active: {active_invites}')
        self.stdout.write(f'   Expired: {expired_invites}')
        self.stdout.write(f'   Used Up: {used_up_invites}\n')
        
        self.stdout.write(f'⏰ RECENT ACTIVITY (Last 7 days):')
        self.stdout.write(f'   New Invites: {recent_invites}')
        self.stdout.write(f'   New Registrations: {recent_registrations}\n')
        
        if top_creators:
            self.stdout.write(f'🏆 TOP INVITE CREATORS:')
            for i, creator in enumerate(top_creators, 1):
                self.stdout.write(f'   {i}. {creator["created_by"]}: {creator["invite_count"]} invites')

