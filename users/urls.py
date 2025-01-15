from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import UserRegistrationView, UserLoginView, VerifyEmailView, PasswordResetRequestView, PasswordResetConfirmView, TwoFactorAuthView, Verify2FAView, RoleViewSet, PermissionViewSet, UserRoleView
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify-email/<str:uidb64>/<str:token>/', 
         VerifyEmailView.as_view(), name='verify-email'),
    path('password-reset/', 
         PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset-confirm/', 
         PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('2fa/setup/', TwoFactorAuthView.as_view(), name='2fa-setup'),
    path('2fa/verify/', Verify2FAView.as_view(), name='2fa-verify'),
    path('user/roles/', UserRoleView.as_view(), name='user-roles'),
    *router.urls,
]
