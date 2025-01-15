from django.shortcuts import render
from rest_framework import status, generics, viewsets
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import UserRegistrationSerializer, UserLoginSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, Enable2FASerializer, Verify2FASerializer, RoleSerializer, PermissionSerializer, UserRoleSerializer
from django.utils.http import urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from .utils import send_verification_email, send_password_reset_email, generate_2fa_secret, generate_2fa_qr_code, verify_2fa_code
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from .models import Role, Permission, CustomUser
from .permissions import IsAdmin  # Use our custom IsAdmin permission

User = get_user_model()

# Create your views here.

class UserRegistrationView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            current_site = get_current_site(request)
            send_verification_email(user, current_site)
            refresh = RefreshToken.for_user(user)
            return Response({
                'message': 'User registered successfully. Please check your email to verify your account.',
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(email=email, password=password)
            
            if user is not None:
                if user.two_factor_enabled:
                    # If 2FA is enabled, require code
                    if 'code' not in request.data:
                        return Response({
                            'message': '2FA code required',
                            'requires_2fa': True
                        }, status=status.HTTP_200_OK)
                    
                    # Verify 2FA code
                    if not verify_2fa_code(user.two_factor_secret, request.data['code']):
                        return Response(
                            {'error': 'Invalid 2FA code'}, 
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                refresh = RefreshToken.for_user(user)
                return Response({
                    'tokens': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    }
                })
            return Response(
                {'error': 'Invalid credentials'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(generics.GenericAPIView):
    permission_classes = (AllowAny,)

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_email_verified = True
            user.save()
            return Response({'message': 'Email verified successfully'})
        return Response({'error': 'Invalid verification link'}, 
                       status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                current_site = get_current_site(request)
                send_password_reset_email(user, current_site)
                return Response({
                    'message': 'Password reset email has been sent.'
                })
            except User.DoesNotExist:
                return Response({
                    'message': 'If a user with this email exists, a password reset email will be sent.'
                })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                uid = force_str(urlsafe_base64_decode(serializer.validated_data['uidb64']))
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                user = None

            if user is not None and default_token_generator.check_token(
                user, serializer.validated_data['token']
            ):
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                return Response({'message': 'Password reset successful'})
            return Response({'error': 'Invalid reset link'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TwoFactorAuthView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = Enable2FASerializer

    def post(self, request):
        """Enable 2FA"""
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = request.user
            
            # Verify password before enabling 2FA
            if not user.check_password(serializer.validated_data['password']):
                return Response(
                    {'error': 'Invalid password'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Generate 2FA secret
            secret = generate_2fa_secret()
            user.two_factor_secret = secret
            user.two_factor_enabled = True
            user.save()
            
            # Generate QR code
            qr_code = generate_2fa_qr_code(user.username, secret)
            
            return Response({
                'message': '2FA enabled successfully',
                'qr_code': qr_code,
                'secret': secret  # Only show this once
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """Disable 2FA"""
        user = request.user
        user.two_factor_enabled = False
        user.two_factor_secret = None
        user.save()
        return Response({'message': '2FA disabled successfully'})

class Verify2FAView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = Verify2FASerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.two_factor_enabled:
                return Response(
                    {'error': '2FA is not enabled'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if verify_2fa_code(user.two_factor_secret, serializer.validated_data['code']):
                return Response({'message': '2FA code verified successfully'})
            return Response(
                {'error': 'Invalid 2FA code'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAdmin]

    def perform_update(self, serializer):
        role = serializer.save()
        if 'permission_ids' in self.request.data:
            role.permissions.set(
                Permission.objects.filter(id__in=self.request.data['permission_ids'])
            )

class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAdmin]

class UserRoleView(generics.RetrieveUpdateAPIView):
    serializer_class = UserRoleSerializer
    permission_classes = [IsAdmin]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        
        if 'role_ids' in request.data:
            user.roles.set(Role.objects.filter(id__in=request.data['role_ids']))
        
        return Response(serializer.data)
