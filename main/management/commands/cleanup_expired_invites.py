from django.core.management.base import BaseCommand
from django.utils import timezone
from main.models import InviteLink

class Command(BaseCommand):
    help = 'Clean up expired invitation links'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Delete invites expired for more than this many days (default: 30)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        days = options['days']
        
        cutoff_date = timezone.now() - timezone.timedelta(days=days)
        expired_invites = InviteLink.objects.filter(
            expires_at__lt=cutoff_date,
            is_active=False
        )
        
        count = expired_invites.count()
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f'DRY RUN: Would delete {count} expired invites older than {days} days'
                )
            )
            for invite in expired_invites[:10]:  # Show first 10
                self.stdout.write(f'  - {invite.token} (expired: {invite.expires_at})')
            if count > 10:
                self.stdout.write(f'  ... and {count - 10} more')
        else:
            deleted_count, _ = expired_invites.delete()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully deleted {deleted_count} expired invites'
                )
            )
