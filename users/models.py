from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_email_verified = models.BooleanField(default=False)
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, blank=True, null=True)
    
    # Additional fields for user roles and permissions
    role = models.CharField(
        max_length=20,
        choices=[
            ('ADMIN', 'Admin'),
            ('MANAGER', 'Manager'),
            ('USER', 'User'),
        ],
        default='USER'
    )
    roles = models.ManyToManyField('Role', blank=True)

    def __str__(self):
        return self.email

    def has_permission(self, permission_codename):
        return self.roles.filter(permissions__codename=permission_codename).exists()

    def is_admin(self):
        return self.roles.filter(name='ADMIN').exists()

class Permission(models.Model):
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    permissions = models.ManyToManyField(Permission)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name
