from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import CustomUser

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        # Add all your custom fields here when creating a user from the admin panel
        fields = ('username', 'email', 'role',)

class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = CustomUser
        # Add all your custom fields here when editing a user from the admin panel
        fields = ('username', 'email', 'role',)

