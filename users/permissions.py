from rest_framework import permissions

class HasPermission:
    def __init__(self, required_permission):
        self.required_permission = required_permission

    def __call__(self, *args, **kwargs):
        class CustomPermission(permissions.BasePermission):
            def has_permission(self, request, view):
                if not request.user or not request.user.is_authenticated:
                    return False
                return request.user.has_permission(self.required_permission)
        
        return CustomPermission()

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and 'ADMIN' in [role.name for role in request.user.roles.all()]
