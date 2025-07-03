import os
import logging
import numpy as np
import base64
from io import BytesIO
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse, Http404
from django.core.files.storage import FileSystemStorage
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import face_recognition
from PIL import Image

from .models import CustomUser, UserFile, LogEntry
from .utils.key_utils import generate_private_key, generate_session_key

logger = logging.getLogger(__name__)

# --- Helper function to handle Base64 image data from the webcam ---
def get_encoding_from_base64(base64_data):
    try:
        header, encoded = base64_data.split(",", 1)
        decoded_image_data = base64.b64decode(encoded)
        image = face_recognition.load_image_file(BytesIO(decoded_image_data))
        encodings = face_recognition.face_encodings(image)
        if len(encodings) > 0:
            return encodings[0]
        else:
            return None
    except Exception as e:
        logger.error(f"Error handling Base64 image for face recognition: {e}")
        return None

def index(request):
    return render(request, 'index.html')

def register_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        face_photo_base64 = request.POST.get('biometric_data')

        if not all([username, email, password, face_photo_base64]):
            messages.error(request, 'All fields, including a face capture, are required.')
            return render(request, 'register_user.html')

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'register_user.html')

        encoding = get_encoding_from_base64(face_photo_base64)
        if encoding is None:
            messages.error(request, 'No face could be detected in the captured photo. Please try again with good lighting.')
            return render(request, 'register_user.html')
        
        face_encoding_str = ",".join(map(str, encoding))
        private_key = generate_private_key()
        
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            face_encoding=face_encoding_str,
            private_key=private_key
        )
        messages.success(request, 'Registration successful! Please log in.')
        LogEntry.objects.create(level='INFO', message=f'New user registered with face recognition: {username}')
        return redirect('login')
    return render(request, 'register_user.html')

def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        face_photo_base64 = request.POST.get('biometric_data')
        user = authenticate(request, username=username, password=password)

        if user is not None and user.role == 'user':
            if user.lockout_until and timezone.now() < user.lockout_until:
                messages.error(request, f"Account is locked. Try again after {user.lockout_until}.")
                return render(request, 'login.html')

            if not face_photo_base64:
                messages.error(request, "A face capture is required for verification.")
                return render(request, 'login.html')

            try:
                stored_encoding = np.fromstring(user.face_encoding, dtype=float, sep=',')
                login_encoding = get_encoding_from_base64(face_photo_base64)

                if login_encoding is None:
                    messages.error(request, "No face detected in the captured photo.")
                    return render(request, 'login.html')
                
                results = face_recognition.compare_faces([stored_encoding], login_encoding)
                biometric_match = results[0]

            except Exception as e:
                biometric_match = False
                logger.error(f"Error processing face for {username}: {e}")

            if biometric_match:
                login(request, user)
                user.failed_attempts = 0
                user.lockout_until = None
                user.save()
                LogEntry.objects.create(level='INFO', message=f'User login successful with face recognition: {username}')
                return redirect('dashboard')
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.lockout_until = timezone.now() + timezone.timedelta(minutes=10)
                    messages.error(request, "Account locked due to too many failed attempts.")
                else:
                    messages.error(request, "Face does not match or incorrect credentials.")
                user.save()
        else:
            messages.error(request, "Invalid credentials or not a client account.")
    return render(request, 'login.html')


@login_required
def dashboard(request):
    if request.user.role != 'user': return redirect('login')
    if request.method == 'POST':
        if 'upload_file' in request.POST:
            uploaded_file = request.FILES.get('file')
            if uploaded_file:
                fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'uploads'))
                saved_filename = fs.save(uploaded_file.name, uploaded_file)
                UserFile.objects.create(user=request.user, filename='uploads/' + saved_filename)
                messages.success(request, f"File '{saved_filename}' uploaded successfully.")
                return redirect('dashboard')
        
        if 'delete_file' in request.POST:
            file_id = request.POST.get('file_id')
            file_to_delete = UserFile.objects.filter(id=file_id, user=request.user).first()
            if file_to_delete:
                file_path = os.path.join(settings.MEDIA_ROOT, file_to_delete.filename)
                if os.path.exists(file_path): os.remove(file_path)
                file_to_delete.delete()
                messages.success(request, "File deleted successfully.")
            return redirect('dashboard')

    files = UserFile.objects.filter(user=request.user)
    return render(request, 'dashboard.html', {'files': files})

@login_required
def download_file(request, file_id):
    file_to_download = UserFile.objects.filter(id=file_id, user=request.user).first()
    if not file_to_download: raise Http404("File not found.")
    file_path = os.path.join(settings.MEDIA_ROOT, file_to_download.filename)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/octet-stream")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response
    raise Http404("File not found on the server.")

def logout_user(request):
    logout(request)
    return redirect('login')
    
def admin_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            user_auth = CustomUser.objects.get(email=email)
            user = authenticate(request, username=user_auth.username, password=password)
            if user is not None and user.role == 'admin':
                login(request, user)
                return redirect('admin_dashboard')
        except CustomUser.DoesNotExist:
            pass
    messages.error(request, 'Invalid credentials or not an admin account.')
    return render(request, 'admin_login.html')

@login_required
def admin_dashboard(request):
    if request.user.role != 'admin': return redirect('admin_login')
    return render(request, 'admin_dashboard.html')

@login_required
def view_user_activities(request):
    if request.user.role != 'admin': return redirect('admin_login')
    files = UserFile.objects.all().order_by('-upload_time')
    return render(request, 'admin_user_activities.html', {'files': files})

@login_required
def log_dashboard(request):
    if request.user.role != 'admin': return redirect('admin_login')
    logs = LogEntry.objects.all().order_by('-created_at')[:100]
    return render(request, 'log_dashboard.html', {'logs': logs})

def admin_logout(request):
    logout(request)
    return redirect('admin_login')

def auth_serv_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            user_auth = CustomUser.objects.get(email=email)
            user = authenticate(request, username=user_auth.username, password=password)
            if user is not None and user.role == 'Authentication Server':
                login(request, user)
                return redirect('auth_serv_dashboard')
        except CustomUser.DoesNotExist:
            pass
    messages.error(request, 'Invalid credentials or not an Authentication Server account.')
    return render(request, 'auth_serv_login.html')

@login_required
def auth_serv_dashboard(request):
    if request.user.role != 'Authentication Server': return redirect('auth_serv_login')
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user_to_change = CustomUser.objects.filter(id=user_id).first()
        if user_to_change:
            if 'authorize_user' in request.POST:
                user_to_change.is_authenticated_by_server = True
                messages.success(request, f"User '{user_to_change.username}' has been authorized.")
            elif 'unauthorize_user' in request.POST:
                user_to_change.is_authenticated_by_server = False
                messages.success(request, f"Authorization for user '{user_to_change.username}' has been revoked.")
            user_to_change.save()
        return redirect('auth_serv_dashboard')
    users = CustomUser.objects.filter(role='user', is_superuser=False)
    return render(request, 'auth_serv_dashboard.html', {'users': users})

def auth_serv_logout(request):
    logout(request)
    return redirect('auth_serv_login')

def resource_serv_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            user_auth = CustomUser.objects.get(email=email)
            user = authenticate(request, username=user_auth.username, password=password)
            if user is not None and user.role == 'Resource Server':
                login(request, user)
                return redirect('resource_serv_dashboard')
        except CustomUser.DoesNotExist:
            pass
    messages.error(request, 'Invalid credentials or not a Resource Server account.')
    return render(request, 'resource_server.html')

@login_required
def resource_serv_dashboard(request):
    if request.user.role != 'Resource Server': return redirect('resource_serv_login')
    files = UserFile.objects.filter(user__is_authenticated_by_server=True).order_by('-upload_time')
    return render(request, 'resource_serv_dashboard.html', {'files': files})

def logout_resource_serv(request):
    logout(request)
    return redirect('resource_serv_login')
