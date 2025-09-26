import uuid
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from datetime import timedelta


class StaffProfile(models.Model):
    """Extended profile for staff members who can create invitations"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    department = models.CharField(max_length=100, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    can_create_invites = models.BooleanField(default=True, help_text="Can this staff member create invitation links?")
    max_invites_per_day = models.IntegerField(default=10, help_text="Maximum invites this staff can create per day")
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username} - {self.department}"
    
    @property
    def invites_created_today(self):
        """Count invites created by this staff today"""
        today = timezone.now().date()
        return InviteLink.objects.filter(
            created_by_user=self.user,
            created_at__date=today
        ).count()
    
    @property
    def can_create_more_invites(self):
        """Check if staff can create more invites today"""
        return self.can_create_invites and self.invites_created_today < self.max_invites_per_day


class InviteLink(models.Model):
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_by = models.CharField(max_length=100)
    created_by_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    archived = models.BooleanField(default=False)
    # How many uses allowed in total (and per user as a simple limit)
    max_uses = models.IntegerField(default=1, help_text="How many times the same user (identifier) can register with this link")
    current_uses = models.IntegerField(default=0)
    description = models.TextField(blank=True)
    title = models.CharField(max_length=200, default="Staff workshop")
    last_used_at = models.DateTimeField(null=True, blank=True)

    @property
    def total_registrations(self):
        """Total number of successful registrations through this link"""
        return RegisteredPerson.objects.filter(invite=self).count()

    @property
    def is_usable(self):
        """Check if link is still usable"""
        if not self.is_active or self.is_expired:
            return False
        return True

    def can_user_register(self, identifier):
        """
        Check if a user (identified by email/phone/IP) can still register
        identifier can be email, phone number, or IP address
        """
        if not self.is_usable:
            return False

        # Count how many times this identifier has been used with this link
        user_registrations = UserInviteUsage.objects.filter(
            invite=self,
            identifier=identifier
        ).count()

        # Use max_uses as per-user usage limit for this invite
        return user_registrations < self.max_uses
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def create_invite(cls, created_by, created_by_user=None, days_valid=7, max_uses=1,
                      description="", title=""):
        """Create a new invite link"""
        expires_at = timezone.now() + timedelta(days=days_valid)
        return cls.objects.create(
            created_by=created_by,
            created_by_user=created_by_user,
            expires_at=expires_at,
            max_uses=max_uses,
            description=description,
            title=title
        )
    def use_invite(self):
        """Mark invite as used. Update counters and timestamps. Do NOT auto-deactivate based on per-user cap."""
        if not self.is_usable:
            return False
        self.current_uses += 1
        self.last_used_at = timezone.now()
        self.save(update_fields=['current_uses', 'last_used_at'])
        return True


class UserInviteUsage(models.Model):
    """Track individual user usage of invite links"""
    invite = models.ForeignKey(InviteLink, on_delete=models.CASCADE, related_name='user_usages')
    identifier = models.CharField(max_length=255, help_text="Email, phone, or IP address")
    identifier_type = models.CharField(max_length=20, choices=[
        ('email', 'Email Address'),
        ('phone', 'Phone Number'),
        ('ip', 'IP Address'),
    ])
    registered_person = models.ForeignKey('RegisteredPerson', on_delete=models.CASCADE)
    used_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        # Enforce one usage per identifier per invite (user can register only once for a given link)
        unique_together = ['invite', 'identifier']
        indexes = [
            models.Index(fields=['invite', 'identifier']),
        ]

    def __str__(self):
        return f"{self.identifier} used invite {self.invite.token} on {self.used_at}"


class RegisteredPerson(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    designation = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    id_number = models.CharField(max_length=50)
    activity = models.TextField()
    organisation = models.CharField(max_length=150, blank=True)
    email = models.EmailField()
    bank = models.CharField(max_length=100, blank=True)
    account_number = models.CharField(max_length=50, blank=True)
    invite = models.ForeignKey(InviteLink, on_delete=models.SET_NULL, null=True, blank=True, related_name='registrations')

    registered_at = models.DateTimeField(auto_now_add=True)

    # Additional tracking
    registration_ip = models.GenericIPAddressField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    verification_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-registered_at']
        permissions = [
            ("can_verify_registrations", "Can verify registrations"),
            ("can_export_registrations", "Can export registration data"),
        ]
        # A person (by email) can register only once for a specific invite
        constraints = [
            models.UniqueConstraint(fields=['invite', 'email'], name='unique_registration_per_invite_email'),
        ]

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        super().save(*args, **kwargs)

        # Create usage tracking entry when person registers
        if is_new and self.invite:
            UserInviteUsage.objects.create(
                invite=self.invite,
                identifier=self.email,
                identifier_type='email',
                registered_person=self
            )




class InviteUsageLog(models.Model):
    """Log of invitation link usage for analytics"""
    invite = models.ForeignKey(InviteLink, on_delete=models.CASCADE, related_name='usage_logs')
    used_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    successful_registration = models.BooleanField(default=False)
    registered_person = models.ForeignKey('RegisteredPerson', on_delete=models.SET_NULL, 
                                        null=True, blank=True)
    
    class Meta:
        ordering = ['-used_at']
    
    def __str__(self):
        return f"Usage of {self.invite.token} at {self.used_at}"