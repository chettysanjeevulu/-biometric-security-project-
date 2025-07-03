from django.shortcuts import redirect
from django.contrib import messages

def login_required_custom(function):
    def wrapper(request, *args, **kwargs):
        if 'user_id' not in request.session:
            messages.error(request, "You must be logged in to view this page.")
            return redirect('login')
        return function(request, *args, **kwargs)
    return wrapper

def admin_login_required(function):
    def wrapper(request, *args, **kwargs):
        if 'admin_email' not in request.session:
            messages.error(request, "Admin access required.")
            return redirect('admin_login')
        return function(request, *args, **kwargs)
    return wrapper
