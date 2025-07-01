from django.contrib import admin
from django.urls import path, include
from authentication.views import (
    RegisterView, LoginView, IncomeViews, ExpenseView,
    PasswordResetRequestView, PasswordResetConfirmView, ResetPasswordView,
    SendOTPView, VerifyOTPView, ProfileView, GoogleLoginView,
    HistoryListView, HistoryDetailView, home_view, ScanReceiptAPIView,
    ParsedSMSListCreateView, GoalViewSet, GoalNotificationViewSet
)
from rest_framework_simplejwt.views import TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from authentication import views

router = DefaultRouter()
router.register('goals', GoalViewSet)
router.register('goal-notifications', GoalNotificationViewSet)

urlpatterns = [
    path('', home_view),
    path('admin/', admin.site.urls),
    path('api/auth/register', RegisterView.as_view(), name="auth_register"),
    path('api/auth/login', LoginView.as_view(), name="auth_login"),
    path('api/password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('api/password_reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_password/', ResetPasswordView.as_view(), name='reset_password'),
    path('api/send_otp/', SendOTPView.as_view(), name='send-otp'),
    path('api/verify_otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('income/', IncomeViews.as_view(), name='income-api'),
    path('expense/', ExpenseView.as_view(), name='expense'),
    path('history/', HistoryListView.as_view(), name='history-list'),
    path('history/<int:pk>/', HistoryDetailView.as_view(), name='history-detail'),
    path('api/scan_receipt/', ScanReceiptAPIView.as_view(), name='scan_receipt'),
    path('parsed-sms/', ParsedSMSListCreateView.as_view(), name='parsed_sms'),
    path('api/auth/google/', GoogleLoginView.as_view(), name='google_login'),
    path('stats/monthly/', views.monthly_income_expense, name='monthly-income-expense'),
    path('stats/category/', views.category_summary, name='category-summary'),
    path('', include(router.urls)),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
