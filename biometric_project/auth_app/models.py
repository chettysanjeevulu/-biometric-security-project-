from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    biometric_path = models.CharField(max_length=255, blank=True, null=True)
    private_key = models.TextField(blank=True, null=True)

    # ++ ADD THIS LINE ++
    # This field will store the comma-separated string of the face encoding.
    face_encoding = models.TextField(blank=True, null=True)

    ROLE_CHOICES = (
        ('user', 'User'),
        ('admin', 'Admin'),
        ('Authentication Server', 'Authentication Server'),
        ('Resource Server', 'Resource Server'),
    )
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, default='user')

    lockout_until = models.DateTimeField(blank=True, null=True)
    failed_attempts = models.IntegerField(default=0)
    is_authenticated_by_server = models.BooleanField(default=False)

class UserFile(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    upload_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.filename}"

class LogEntry(models.Model):
    level = models.CharField(max_length=10)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.created_at}] {self.level}: {self.message}"