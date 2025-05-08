from django.contrib import admin
from django.urls import path
from authentication.views import RegisterView, LoginView
from authentication.views import PasswordResetRequestView, PasswordResetConfirmView,ResetPasswordView,SendOTPView, VerifyOTPView,ProfileView
from django.conf.urls.static import static
from django.conf import settings
from rest_framework_simplejwt.views import  TokenRefreshView



urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/register', RegisterView.as_view(), name="auth_register"),  # Register endpoint
    path('api/auth/login', LoginView.as_view(), name="auth_login"),  # Login endpoint
    path('api/password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('api/password_reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_password/', ResetPasswordView.as_view(), name='reset_password'),
    path('api/send_otp/', SendOTPView.as_view(), name='send-otp'),
    path('api/verify_otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # 🔥 THIS IS THE MISSING PART


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

