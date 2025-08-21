
# forms.py - Updated forms
from django import forms
from .models import RegisteredPerson, InviteLink
from django.utils import timezone
from datetime import timedelta


class RegisteredPersonForm(forms.ModelForm):
    class Meta:
        model = RegisteredPerson
        fields = [
            'first_name', 'last_name', 'designation', 'phone_number',
            'id_number', 'activity', 'organisation', 'email', 'bank', 'account_number'
        ]
        widgets = {
            'activity': forms.Textarea(attrs={'rows': 3}),
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'required': True}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'required': True}),
            'designation': forms.TextInput(attrs={'class': 'form-control', 'required': True}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'required': True}),
            'id_number': forms.TextInput(attrs={'class': 'form-control', 'required': True}),
            'organisation': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'required': True}),
            'bank': forms.TextInput(attrs={'class': 'form-control'}),
            'account_number': forms.TextInput(attrs={'class': 'form-control'}),
        }


class InviteLinkForm(forms.ModelForm):
    days_valid = forms.IntegerField(
        initial=7,
        min_value=1,
        max_value=365,
        help_text="Number of days this invite will be valid"
    )
    
    class Meta:
        model = InviteLink
        fields = ['max_uses', 'description', 'target_audience', 'days_valid']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'target_audience': forms.TextInput(attrs={'class': 'form-control'}),
            'max_uses': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['max_uses'].initial = 1
        
        # Add CSS classes to form fields
        for field_name, field in self.fields.items():
            if field_name != 'days_valid':
                field.widget.attrs.update({'class': 'form-control'})
            else:
                field.widget.attrs.update({'class': 'form-control'})
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        days_valid = self.cleaned_data['days_valid']
        instance.expires_at = timezone.now() + timedelta(days=days_valid)
        
        if commit:
            instance.save()
        return instance



class InviteEntryForm(forms.Form):
    invite_code = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your invitation code',
            'required': True
        }),
        label='Invitation Code'
    )

class CreateInviteForm(forms.Form):
    created_by = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Leave blank to use your name'
        }),
        label='Created By'
    )
    days_valid = forms.IntegerField(
        min_value=1,
        max_value=365,
        initial=7,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        label='Valid for (days)'
    )
    max_uses = forms.IntegerField(
        min_value=1,
        max_value=1000,
        initial=1,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        label='Maximum Uses'
    )
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        label='Description (optional)'
    )
    target_audience = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g., Workshop participants, New employees'
        }),
        label='Target Audience (optional)'
    )