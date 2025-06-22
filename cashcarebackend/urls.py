from django.contrib import admin
from django.urls import path
from authentication.views import RegisterView, LoginView,IncomeViews,ExpenseView
from authentication.views import PasswordResetRequestView, PasswordResetConfirmView,ResetPasswordView,SendOTPView, VerifyOTPView,ProfileView
from django.conf.urls.static import static
from django.conf import settings
from rest_framework_simplejwt.views import  TokenRefreshView
from django.urls import path
from django.urls import path
from authentication.views import HistoryListView, HistoryDetailView
from authentication.views import home_view
from authentication.views import ScanReceiptAPIView
from authentication.views import ParsedSMSListCreateView
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from authentication.views import GoalViewSet, GoalNotificationViewSet

router = DefaultRouter()
router.register('goals', GoalViewSet)
router.register('goal-notifications', GoalNotificationViewSet)


urlpatterns = [
    path('', home_view),
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
    path('income/', IncomeViews.as_view(), name='income-api'),
    path('expense/', ExpenseView.as_view(), name='expense'),
    path('history/', HistoryListView.as_view(), name='history-list'),
    path('history/<int:pk>/', HistoryDetailView.as_view(), name='history-detail'),
    path('api/scan_receipt/', ScanReceiptAPIView.as_view(), name='scan_receipt'),
    path('parsed-sms/', ParsedSMSListCreateView.as_view(), name='parsed_sms'),
    path('', include(router.urls)),

    

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

