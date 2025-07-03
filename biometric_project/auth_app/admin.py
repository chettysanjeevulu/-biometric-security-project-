from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, UserFile, LogEntry
from .forms import CustomUserCreationForm, CustomUserChangeForm # Import the new forms

# This is the final, correct custom admin view for our user model.
class CustomUserAdmin(UserAdmin):
    # We tell the admin to use our custom forms for creating and changing users.
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser

    # This shows the 'role' field in the list of users.
    list_display = ('username', 'email', 'role', 'is_staff')
    
    # This adds our custom fields to the "Edit user" page in the admin panel.
    # This ensures the fields are displayed and, crucially, saved correctly.
    fieldsets = UserAdmin.fieldsets + (
        ('Custom Fields', {'fields': ('role', 'biometric_path', 'private_key', 'is_authenticated_by_server')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Custom Fields', {'fields': ('role', 'biometric_path', 'private_key')}),
    )

# We now register our CustomUser model with this special CustomUserAdmin view.
admin.site.register(CustomUser, CustomUserAdmin)

# The other models can be registered normally.
admin.site.register(UserFile)
admin.site.register(LogEntry)
