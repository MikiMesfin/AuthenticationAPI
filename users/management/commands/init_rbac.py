from django.core.management.base import BaseCommand
from users.models import Permission, Role

class Command(BaseCommand):
    help = 'Initialize default roles and permissions'

    def handle(self, *args, **kwargs):
        # Create default permissions
        permissions = {
            'user_create': 'Can create users',
            'user_read': 'Can read user information',
            'user_update': 'Can update users',
            'user_delete': 'Can delete users',
            'role_manage': 'Can manage roles',
            'permission_manage': 'Can manage permissions',
        }

        created_permissions = {}
        for codename, description in permissions.items():
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                defaults={
                    'name': codename.replace('_', ' ').title(),
                    'description': description
                }
            )
            created_permissions[codename] = permission
            if created:
                self.stdout.write(f'Created permission: {permission.name}')

        # Create default roles
        roles = {
            'ADMIN': list(permissions.keys()),
            'MANAGER': ['user_read', 'user_update'],
            'USER': ['user_read'],
        }

        for role_name, permission_codes in roles.items():
            role, created = Role.objects.get_or_create(name=role_name)
            if created:
                self.stdout.write(f'Created role: {role_name}')
            
            role_permissions = [
                created_permissions[code] for code in permission_codes
            ]
            role.permissions.set(role_permissions) 