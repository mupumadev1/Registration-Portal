# main/management/commands/create_staff.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from main.models import StaffProfile

class Command(BaseCommand):
    help = 'Create a staff user with invite creation permissions'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username for the staff user')
        parser.add_argument('email', type=str, help='Email for the staff user')
        parser.add_argument('--password', type=str, help='Password (will prompt if not provided)')
        parser.add_argument('--department', type=str, default='Admin', help='Department name')
        parser.add_argument('--max-invites', type=int, default=10, help='Max invites per day')
        parser.add_argument('--phone', type=str, default='', help='Phone number')
        parser.add_argument('--full-permissions', action='store_true', help='Grant all invitation permissions')

    def handle(self, *args, **options):
        username = options['username']
        email = options['email']
        password = options['password']
        department = options['department']
        max_invites = options['max_invites']
        phone = options['phone']
        full_permissions = options['full_permissions']

        if not password:
            import getpass
            password = getpass.getpass('Password: ')

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.ERROR(f'User {username} already exists')
            )
            return

        try:
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                is_staff=True
            )

            # Create staff profile
            staff_profile = StaffProfile.objects.create(
                user=user,
                department=department,
                phone_number=phone,
                can_create_invites=True,
                max_invites_per_day=max_invites
            )

            # Grant permissions if requested
            if full_permissions:
                content_type = ContentType.objects.get_for_model(staff_profile)
                permissions = Permission.objects.filter(content_type=content_type)
                user.user_permissions.set(permissions)
                
                # Also grant custom permissions
                try:
                    manage_all_perm = Permission.objects.get(codename='can_manage_all_invites')
                    stats_perm = Permission.objects.get(codename='can_view_invite_stats')
                    export_perm = Permission.objects.get(codename='can_export_registrations')
                    verify_perm = Permission.objects.get(codename='can_verify_registrations')
                    
                    user.user_permissions.add(manage_all_perm, stats_perm, export_perm, verify_perm)
                except Permission.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING('Some custom permissions not found. Run migrations first.')
                    )

            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created staff user {username} with invite permissions\n'
                    f'Department: {department}\n'
                    f'Max invites per day: {max_invites}\n'
                    f'Full permissions: {"Yes" if full_permissions else "No"}'
                )
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating staff user: {str(e)}')
            )
