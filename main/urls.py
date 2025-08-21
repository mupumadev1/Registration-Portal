from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('invite-entry/', views.invite_entry, name='invite_entry'),
    path('register/', views.register_person, name='register_person'),
    path('success/', views.reg_page, name='reg_page'),
    path('i/<uuid:token>/', views.register_with_token, name='register_with_token'),
    
    # Authentication URLs
    path('login/', views.StaffLoginView.as_view(), name='login'),
    path('logout/', views.custom_logout, name='logout'),
    # Staff management URLs
    path('manage/', views.manage_invites, name='manage_invites'),
    path('create-invite/', views.create_invite, name='create_invite'),
    path('statistics/', views.invite_statistics, name='invite_statistics'),
    path('export/', views.export_registrations, name='export_registrations'),
        # Staff/Admin URLs (require login and permissions)
    path('dashboard/', views.invite_dashboard, name='dashboard'),
    path('create-invite/', views.create_invite_link, name='create_invite'),
    path('invite-list/', views.invite_list, name='invite_list'),
    path('invite/<uuid:token>/details/', views.invite_details, name='invite_details'),
    path('invite/<uuid:token>/toggle/', views.toggle_invite_status, name='toggle_invite'),
    path('registrations/', views.registrations_list, name='registrations_list'),
    path('registration/<int:pk>/verify/', views.verify_registration, name='verify_registration'),
    path('usage-logs/', views.usage_logs, name='usage_logs'),

]
