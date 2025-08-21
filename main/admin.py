from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import StaffProfile, InviteLink, RegisteredPerson, InviteUsageLog


class StaffProfileInline(admin.StackedInline):
    model = StaffProfile
    can_delete = False
    verbose_name_plural = 'Staff Profile'
    extra = 0


class CustomUserAdmin(UserAdmin):
    inlines = (StaffProfileInline,)


# Unregister the original User admin and register the new one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)


@admin.register(StaffProfile)
class StaffProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'department', 'can_create_invites', 'max_invites_per_day', 'invites_created_today']
    list_filter = ['department', 'can_create_invites', 'created_at']
    search_fields = ['user__username', 'user__first_name', 'user__last_name', 'department']
    readonly_fields = ['created_at']
    
    def invites_created_today(self, obj):
        return obj.invites_created_today
    invites_created_today.short_description = 'Today\'s Invites'


@admin.register(InviteLink)
class InviteLinkAdmin(admin.ModelAdmin):
    list_display = ['token_short', 'created_by', 'created_at', 'expires_at', 'current_uses', 'max_uses', 'is_active']
    list_filter = ['is_active', 'created_at', 'expires_at', 'created_by_user']
    search_fields = ['token', 'created_by', 'description', 'target_audience']
    readonly_fields = ['token', 'created_at', 'current_uses', 'last_used_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('token', 'created_by', 'created_by_user', 'description', 'target_audience')
        }),
        ('Configuration', {
            'fields': ('expires_at', 'max_uses', 'is_active')
        }),
        ('Usage Statistics', {
            'fields': ('current_uses', 'last_used_at'),
            'classes': ('collapse',),
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',),
        }),
    )
    
    def token_short(self, obj):
        return f"{str(obj.token)[:8]}..."
    token_short.short_description = 'Token'


@admin.register(RegisteredPerson)
class RegisteredPersonAdmin(admin.ModelAdmin):
    list_display = ['full_name', 'email', 'designation', 'organisation', 'registered_at', 'is_verified']
    list_filter = ['designation', 'organisation', 'registered_at', 'is_verified']
    search_fields = ['first_name', 'last_name', 'email', 'id_number', 'phone_number']
    readonly_fields = ['registered_at', 'registration_ip']
    
    fieldsets = (
        ('Personal Information', {
            'fields': ('first_name', 'last_name', 'id_number', 'phone_number', 'email')
        }),
        ('Professional Information', {
            'fields': ('designation', 'organisation', 'activity')
        }),
        ('Banking Information', {
            'fields': ('bank', 'account_number')
        }),
        ('Registration Details', {
            'fields': ('invite', 'registered_at', 'registration_ip', 'is_verified', 'verification_notes')
        }),
    )


@admin.register(InviteUsageLog)
class InviteUsageLogAdmin(admin.ModelAdmin):
    list_display = ['invite_token_short', 'used_at', 'ip_address', 'successful_registration', 'registered_person']
    list_filter = ['used_at', 'successful_registration']
    readonly_fields = ['invite', 'used_at', 'ip_address', 'user_agent', 'registered_person', 'successful_registration']
    search_fields = ['invite__token', 'ip_address']
    
    def invite_token_short(self, obj):
        return f"{str(obj.invite.token)[:8]}..."
    invite_token_short.short_description = 'Invite Token'
    
    def has_add_permission(self, request):
        # Disable manual creation of usage logs - they should be created programmatically
        return False