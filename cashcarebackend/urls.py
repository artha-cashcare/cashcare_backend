from django.contrib import admin
from django.urls import path, include
from authentication.views import (
    RegisterView, LoginView, IncomeViews, ExpenseView,
    PasswordResetRequestView, PasswordResetConfirmView, ResetPasswordView,
    SendOTPView, VerifyOTPView, ProfileView, GoogleLoginView,
    HistoryListView, HistoryDetailView, home_view, ScanReceiptAPIView,
    ParsedSMSListCreateView, GoalViewSet, NotificationViewSet,
    UserChartData, monthly_income_chart, MonthlyExpenseComparison,
    SourceExpenseComparison, PredictView, monthly_income_expense, category_summary,MonthlySummaryView,dashboard,custom_admin_dashboard,VerifyAndStorePaymentView
)
from suggestionAI.views import generate_ai_suggestion
from rest_framework_simplejwt.views import TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.i18n import i18n_patterns
from authentication.admin import my_admin_site  # change yourapp    to your app name

router = DefaultRouter()
router.register('goals', GoalViewSet)
router.register('goal-notifications', NotificationViewSet)
# admin.site.index = custom_admin_dashboard  # 👈 override default admin view

urlpatterns = [
    path('', home_view),
    path('admin/', my_admin_site.urls),
         # path("admin/dashboard/", custom_admin_dashboard, name="custom_admin_dashboard"),
    path('i18n/', include('django.conf.urls.i18n')),  # <-- REQUIRED for Jazzmin language sw
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
    path('stats/monthly/', monthly_income_expense, name='monthly-income-expense'),
    path('stats/category/', category_summary, name='category-summary'),
    path('user-chart-data/', UserChartData.as_view(), name='user_chart_data'),
    path("monthly-income-chart/", monthly_income_chart.as_view(), name="monthly_income_chart"),
    path('api/expense_comparison/', MonthlyExpenseComparison.as_view(), name='expense_comparison'),
    path('source-expense-comparison/', SourceExpenseComparison.as_view(), name='source_expense_comparison'),
    path('api/predict/', PredictView.as_view(), name='predict'),
    path('monthly-summary/', MonthlySummaryView.as_view(), name='monthly-summary'),
    path('dashboard/', dashboard),
    path('verify-payment/', VerifyAndStorePaymentView.as_view(), name='verify-payment'),

    path('suggestionAI/', include('suggestionAI.urls')),  


    # path('', include('webapp.urls')),


    path('', include(router.urls)),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
