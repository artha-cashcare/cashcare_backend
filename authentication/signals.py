# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from .models import Receipt, Income, Expense, History, ParsedSMS,ExpenseCategory,IncomeCategory

# @receiver(post_save, sender=Receipt)
# def create_expense_from_receipt(sender, instance, created, **kwargs):
#     if created and not instance.is_processed:
#         # Get or create a default expense category
#         default_category, _ = ExpenseCategory.objects.get_or_create(
#             category_name="Shopping",
#             is_default=True
#         )
        
#         Expense.objects.create(
#             user=instance.user,
#             amount=instance.amount,
#             description=f"Expense at {instance.merchant or 'unknown merchant'} from receipt",
#             origin='receipt',
#             receipt=instance,
#             category=default_category,
#             date=instance.date
#         )
        
#         # Create history entry
#         History.objects.create(
#             user=instance.user,
#             amount=instance.amount,
#             type='expense',
#             description=f"Expense at {instance.merchant or 'unknown merchant'}",
#             category=default_category.category_name,
#             reference_id=instance.id,
#             date=instance.date
#         )
        
#         instance.is_processed = True
#         instance.save()

# @receiver(post_save, sender=Income)
# def create_history_from_income(sender, instance, created, **kwargs):
#     if created:
#         History.objects.create(
#             user=instance.user,
#             amount=instance.amount,
#             type='income',
#             description=instance.description or f"Income from {instance.category}",
#             category=instance.category.category_name if instance.category else None,
#             reference_id=instance.id,
#             date=instance.date
#         )

# @receiver(post_save, sender=Expense)
# def create_history_from_expense(sender, instance, created, **kwargs):
#     if created:
#         History.objects.create(
#             user=instance.user,
#             amount=instance.amount,
#             type='expense',
#             description=instance.description or f"Expense on {instance.category}",
#             category=instance.category.category_name if instance.category else None,
#             reference_id=instance.id,
#             date=instance.date
#         )

# @receiver(post_save, sender=ParsedSMS)
# def create_transaction_from_sms(sender, instance, created, **kwargs):
#     if created:
#         if instance.parsed_type == 'income':
#             # Get or create the IncomeCategory object (not just name)
#             category, _ = IncomeCategory.objects.get_or_create(
#                 category_name=instance.category or "SMS Income"  # Ensure this is a string
#             )
            
#             Income.objects.create(
#                 user=instance.user,
#                 amount=instance.amount,
#                 origin='sms',
#                 category=category,  # Pass the OBJECT, not the name
#                 timestamp=instance.timestamp
#             )
            
#         elif instance.parsed_type == 'expense':
#             # Get or create the ExpenseCategory object (not just name)
#             category, _ = ExpenseCategory.objects.get_or_create(
#                 category_name=instance.category or "SMS Expense"  # Ensure this is a string
#             )
            
#             Expense.objects.create(
#                 user=instance.user,
#                 amount=instance.amount,
#                 origin='sms',
#                 category=category,  # Pass the OBJECT, not the name
#                 timestamp=instance.timestamp
#             )

# signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Receipt, Expense

@receiver(post_save, sender=Receipt)
def create_expense_from_receipt(sender, instance, created, **kwargs):
    """
    Automatically creates an Expense when a Receipt is created
    """
    if created:
        # Check if expense already exists to prevent duplicates
        if not hasattr(instance, 'linked_expense'):
            Expense.objects.create(
                user=instance.user,
                amount=instance.amount,
                category=instance.category,
                origin='scanned',
                receipt_reference=instance,
                timestamp=instance.timestamp
            )


from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Income, GoalIncomeCategoryRule, Notification, Goal

@receiver(post_save, sender=Goal)
def notify_goal_creation(sender, instance, created, **kwargs):
    if created:
        Notification.objects.create(
            user=instance.user,
            goal=instance,
            type='created',
            message=f"New goal created: '{instance.title}' (Target: Rs.{instance.target_amount})"
        )

@receiver(post_save, sender=Income)
def auto_add_goal_progress(sender, instance, created, **kwargs):
    if not created:
        return

    # Remove the wrong Notification creation for Income creation here

    rules = GoalIncomeCategoryRule.objects.filter(
        income_category=instance.category,
        goal__user=instance.user
    ).select_related('goal')

    for rule in rules:
        goal = rule.goal
        if goal.is_completed or goal.is_failed:
            continue

        added = (instance.amount * rule.percentage) / 100
        goal.current_amount += added
        goal.save()

        Notification.objects.create(
            user=instance.user,
            goal=goal,
            type='progress',
            message=f"Rs.{added:.2f} added to '{goal.title}'. Progress: {goal.progress_percentage:.1f}%"
        )

        if goal.days_remaining <= 7 and goal.progress_percentage < 50:
            Notification.objects.create(
                user=instance.user,
                goal=goal,
                type='low_progress',
                message=f"⚠️ Low progress on '{goal.title}' — {goal.days_remaining} days left."
            )

        if goal.current_amount >= goal.target_amount:
            Notification.objects.create(
                user=instance.user,
                goal=goal,
                type='completed',
                message=f"🎉 Goal completed: '{goal.title}'!"
            )



from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import ParsedSMS, Income, Expense, IncomeCategory, ExpenseCategory
@receiver(post_save, sender=ParsedSMS)
def create_income_or_expense_from_sms(sender, instance, created, **kwargs):
    if created:
        category_name = instance.category

        if instance.parsed_type == 'income':
            category_obj, _ = IncomeCategory.objects.get_or_create(category_name=category_name)
            Income.objects.create(
                user=instance.user,
                amount=instance.amount,
                category=category_obj,
                timestamp=instance.timestamp,
                origin='scanned'  # 👈 TRACK ORIGIN
            )

        elif instance.parsed_type == 'expense':
            category_obj, _ = ExpenseCategory.objects.get_or_create(category_name=category_name)
            Expense.objects.create(
                user=instance.user,
                amount=instance.amount,
                category=category_obj,
                timestamp=instance.timestamp,
                origin='scanned'  # 👈 TRACK ORIGIN
            )
