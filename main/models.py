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
    """Model to store invitation links with expiry and usage tracking"""
    
    # Unique identifier for the invite link
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    # Link metadata
    created_by = models.CharField(max_length=100, help_text="Display name of person who created this invite")
    created_by_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                                       help_text="User who created this invite")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    # Usage tracking
    is_active = models.BooleanField(default=True)
    max_uses = models.IntegerField(default=1, help_text="Maximum number of times this link can be used")
    current_uses = models.IntegerField(default=0)
    
    # Optional description and purpose
    description = models.TextField(blank=True, help_text="Purpose of this invite link")
    target_audience = models.CharField(max_length=200, blank=True, help_text="Who is this invite for?")
    
    # Tracking
    last_used_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        permissions = [
            ("can_manage_all_invites", "Can manage all invitation links"),
            ("can_view_invite_stats", "Can view invitation statistics"),
        ]
    
    def __str__(self):
        return f"Invite {str(self.token)[:8]}... - Created by {self.created_by}"
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    @property
    def is_usable(self):
        return (
            self.is_active and 
            not self.is_expired and 
            self.current_uses < self.max_uses
        )
    
    @property
    def usage_percentage(self):
        """Get usage as percentage"""
        if self.max_uses == 0:
            return 0
        return (self.current_uses / self.max_uses) * 100
    
    def use_invite(self):
        """Mark invite as used and increment usage count"""
        if self.is_usable:
            self.current_uses += 1
            self.last_used_at = timezone.now()
            if self.current_uses >= self.max_uses:
                self.is_active = False
            self.save()
            return True
        return False
    
    @classmethod
    def create_invite(cls, created_by, created_by_user=None, days_valid=7, max_uses=1, 
                     description="", target_audience=""):
        """Create a new invite link"""
        expires_at = timezone.now() + timedelta(days=days_valid)
        return cls.objects.create(
            created_by=created_by,
            created_by_user=created_by_user,
            expires_at=expires_at,
            max_uses=max_uses,
            description=description,
            target_audience=target_audience
        )


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
    invite = models.OneToOneField(InviteLink, on_delete=models.SET_NULL, null=True, blank=True)

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

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"


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