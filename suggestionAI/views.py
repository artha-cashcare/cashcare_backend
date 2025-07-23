
import google.generativeai as genai
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Sum
from suggestionAI.models import AISuggestion
from decimal import Decimal
from django.utils import timezone
from authentication.models import Income,Expense,Goal


# ✅ Fix: Add the missing Decimal-to-float converter
def decimal_to_float(data):
    if isinstance(data, list):
        return [decimal_to_float(item) for item in data]
    elif isinstance(data, dict):
        return {k: decimal_to_float(v) for k, v in data.items()}
    elif isinstance(data, Decimal):
        return float(data)
    return data


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def generate_ai_suggestion(request):
    user = request.user

    # 🔢 Total income and expense
    income = Income.objects.filter(user=user).aggregate(total=Sum('amount'))['total'] or 0
    expense = Expense.objects.filter(user=user).aggregate(total=Sum('amount'))['total'] or 0

    # 📊 Income and expense by category
    income_by_category = (
        Income.objects.filter(user=user)
        .values('category__category_name')
        .annotate(total=Sum('amount'))
        .order_by('-total')
    )

    expense_by_category = (
        Expense.objects.filter(user=user)
        .values('category__category_name')
        .annotate(total=Sum('amount'))
        .order_by('-total')
    )

    # 🎯 Active goals
    active_goals = Goal.objects.filter(user=user, is_completed=False, is_failed=False)
    goal_data = []
    for goal in active_goals:
        goal_data.append({
            "title": goal.title,
            "target": float(goal.target_amount),
            "current": float(goal.current_amount),
            "progress": goal.progress_percentage,
            "days_remaining": goal.days_remaining
        })

    # 💬 Gemini prompt
    prompt = f"""
You're a smart AI for personal finance. Give **very practical, useful advice** to help this user manage money wisely and reach important goals.

User Snapshot:
- Monthly Income: Rs. {income}
- Monthly Expenses: Rs. {expense}
- Balance: Rs. {income - expense}

Income Sources:
{"".join([f"{cat['category__category_name']}: Rs. {cat['total']}, " for cat in income_by_category])}

Expenses:
{"".join([f"{cat['category__category_name']}: Rs. {cat['total']}, " for cat in expense_by_category])}

Goals:
{"No active goals" if not goal_data else "".join([
    f"{g['title']} (Target: {g['target']}, Saved: {g['current']}, Days Left: {g['days_remaining']}), "
    for g in goal_data
])}

⚠️ Instructions:
- Don’t repeat user's data — interpret it and give smart insight.
- Mention only 1 or 2 **important or urgent** goals.
- Estimate how much user **can or should save** this month and suggest how.
- Show 1 line for each selected goal: how much to save monthly & from where.
- Be realistic and practical.

🧾 Final output format:
1.(brief summary of income/expense)
2. Tip 1: (based on expenses – what can be reduced)
3. Tip 2: (based on income/saving – how to improve savings)
4. Monthly Savings Target: Rs. ___ (calculate from income – expense and suggest practical amount to save)
5. Goal Strategy:
   - {Goal.title}: (short, 1-liner how to reach it using this month’s savings or by reducing specific expenses)

Keep it useful. Don’t suggest all goals. Avoid long explanations.
"""



    # 🤖 Gemini AI generate
    model = genai.GenerativeModel("models/gemini-1.5-flash")
    response = model.generate_content(prompt)

    # 🧹 Prepare input data for saving to DB
    input_data = {
        "income": income,
        "expense": expense,
        "income_by_category": list(income_by_category),
        "expense_by_category": list(expense_by_category),
        "goals": goal_data
    }

    # ✅ Convert Decimal to float before saving JSON
    input_data = decimal_to_float(input_data)

    # 💾 Save suggestion to DB
    suggestion = AISuggestion.objects.create(
        user=user,
        input_data=input_data,
        suggestion=response.text
    )

    return Response({
        "suggestion_id": suggestion.id,
        "suggestion": response.text
    })
