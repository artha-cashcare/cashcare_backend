from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth import get_user_model
from django.db.models import Sum
from .models import CustomUser, Income, Expense, ParsedSMS, Goal
from suggestionAI.models import AISuggestion

class MyAdminSite(AdminSite):
    site_header = "Artha Cashcare Admin"
    site_title = "Artha Cashcare"
    index_title = "Dashboard"

    def index(self, request, extra_context=None):
        User = get_user_model()
        total_users = User.objects.filter(is_superuser=False).count()
        scanned_expenses = Expense.objects.filter(origin='scanned').count()
        manual_expenses = Expense.objects.filter(origin='manual').count()
        total_income = ParsedSMS.objects.filter(parsed_type='income').aggregate(total=Sum('amount'))['total'] or 0
        total_expense = ParsedSMS.objects.filter(parsed_type='expense').aggregate(total=Sum('amount'))['total'] or 0

        # Get top income users (top 10)
        top_income_users = (
            Income.objects.values('user__id', 'user__email')
            .annotate(total=Sum('amount'))
            .order_by('-total')[:10]
        )

        # Get top expense users (top 10)
        top_expense_users = (
            Expense.objects.values('user__id', 'user__email')
            .annotate(total=Sum('amount'))
            .order_by('-total')[:10]
        )

        # Combine income and expense per user into a dict
        user_dict = {}

        for u in top_income_users:
            uid = u['user__id']
            user_dict[uid] = {
                'email': u['user__email'],
                'income': float(u['total'] or 0),
                'expense': 0,
            }

        for u in top_expense_users:
            uid = u['user__id']
            if uid in user_dict:
                user_dict[uid]['expense'] = float(u['total'] or 0)
            else:
                user_dict[uid] = {
                    'email': u['user__email'],
                    'income': 0,
                    'expense': float(u['total'] or 0),
                }

        combined_users = list(user_dict.values())
        combined_users.sort(key=lambda x: x['income'] + x['expense'], reverse=True)

        # Prepare category data for income and expense
        income_by_category_user = (
            Income.objects
            .values('user__email', 'category__category_name')
            .annotate(total=Sum('amount'))
        )
        expense_by_category_user = (
            Expense.objects
            .values('user__email', 'category__category_name')
            .annotate(total=Sum('amount'))
        )

        def structure_category_data(data):
            structured = {}
            for row in data:
                user = row['user__email']
                category = row['category__category_name']
                total = row['total']
                if user not in structured:
                    structured[user] = {}
                structured[user][category] = float(total) if total else 0
            return structured

        income_category_data = structure_category_data(income_by_category_user)
        expense_category_data = structure_category_data(expense_by_category_user)

        # Get all income/expense categories & users as flat lists for JS
        income_categories = list({row['category__category_name'] for row in income_by_category_user})
        income_users = list({row['user__email'] for row in income_by_category_user})

        expense_categories = list({row['category__category_name'] for row in expense_by_category_user})
        expense_users = list({row['user__email'] for row in expense_by_category_user})

        context = {
            'total_users': total_users,
            'scanned_expenses': scanned_expenses,
            'manual_expenses': manual_expenses,
            'total_income': float(total_income),
            'total_expense': float(total_expense),
            'combined_users': combined_users[:10],
            'income_category_data': income_category_data,
            'expense_category_data': expense_category_data,
            'income_categories': income_categories,
            'income_users': income_users,
            'expense_categories': expense_categories,
            'expense_users': expense_users,
        }
        if extra_context:
            context.update(extra_context)
        return super().index(request, extra_context=context)


my_admin_site = MyAdminSite(name='myadmin')

my_admin_site.register(CustomUser)
my_admin_site.register(Income)
my_admin_site.register(Expense)
my_admin_site.register(ParsedSMS)
my_admin_site.register(Goal)
my_admin_site.register(AISuggestion)


from django.contrib import admin
from suggestionAI.models import AISuggestion

@admin.register(AISuggestion)
class AISuggestionAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'short_suggestion', 'has_feedback')

    def short_suggestion(self, obj):
        return obj.suggestion[:50] + "..." if len(obj.suggestion) > 50 else obj.suggestion
    short_suggestion.short_description = 'Suggestion'

    def has_feedback(self, obj):
        return bool(obj.feedback)
    has_feedback.boolean = True