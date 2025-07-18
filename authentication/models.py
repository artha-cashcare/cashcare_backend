from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from datetime import timedelta
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    profile_image = models.ImageField(
        upload_to='profile_images/',
        null=True,
        blank=True,
        default=None
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

class EmailOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=5)

    def __str__(self):
        return f"{self.email} - {self.otp}"

class IncomeCategory(models.Model):
    category_name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.category_name

class ExpenseCategory(models.Model):
    user = models.ForeignKey(
       settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='expense_categories',
        null=True,
        blank=True
    )
    category_name = models.CharField(max_length=100)
    
    class Meta:
        unique_together = ('user', 'category_name')  # Prevent duplicates per user
        verbose_name_plural = 'Expense Categories'
    
    def __str__(self):
        return self.category_name


class Income(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='incomes'
    )
    category = models.ForeignKey(
        IncomeCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    origin = models.CharField(max_length=50, default='manual')
    timestamp = models.DateTimeField(auto_now_add=True)
    reference_id = models.IntegerField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['category']),
        ]
        ordering = ['-timestamp']
 
    def __str__(self):
        return f"{self.category} - {self.amount}"



class Receipt(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='receipts'
    )
    file_path = models.FileField(upload_to='receipts/')
    scanned_text = models.TextField(blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(
        ExpenseCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    date = models.DateField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Receipt {self.id} - {self.amount}"

class Expense(models.Model):
    ORIGIN_CHOICES = [
        ('manual', 'Manual Entry'),
        ('scanned', 'From Receipt Scan'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        related_name='expenses'
    )
    category = models.ForeignKey(
        ExpenseCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    origin = models.CharField(
        max_length=50, 
        choices=ORIGIN_CHOICES,
        default='manual'
    )
    receipt_reference = models.OneToOneField(
        Receipt,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='linked_expense'
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['category']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.category} - {self.amount}"


class ParsedSMS(models.Model):
    PARSED_TYPE_CHOICES = ( 
        ('income', 'Income'),
        ('expense', 'Expense'),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,   
        related_name='parsed_sms'
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    parsed_type = models.CharField(max_length=10, choices=PARSED_TYPE_CHOICES)
    category = models.CharField(max_length=100, blank=True, null=True)


    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
        ]
        ordering = ['-timestamp']


from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator

class Goal(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=100, default="Untitled Goal")  # default added
    target_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)  # default added
    current_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)  # default added
    deadline = models.DateField(null=True, blank=True)  # nullable and optional
    is_completed = models.BooleanField(default=False)
    is_failed = models.BooleanField(default=False)


    def save(self, *args, **kwargs):
        if self.current_amount >= self.target_amount:
            self.is_completed = True
        elif timezone.now().date() > self.deadline:
            self.is_failed = True
        super().save(*args, **kwargs)

    @property
    def progress_percentage(self):
        return min(100, (self.current_amount / self.target_amount) * 100) if self.target_amount else 0

    @property
    def days_remaining(self):
        if self.deadline:
            return (self.deadline - timezone.now().date()).days
        return None  # Or return 0 or -1 if you want a default


class GoalIncomeCategoryRule(models.Model):
    goal = models.ForeignKey(Goal, on_delete=models.CASCADE, related_name='rules')
    income_category = models.ForeignKey('IncomeCategory', on_delete=models.CASCADE)
    percentage = models.DecimalField(max_digits=5, decimal_places=2, validators=[
        MinValueValidator(0), MaxValueValidator(100)
    ])

class GoalNotification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    goal = models.ForeignKey(Goal, on_delete=models.CASCADE)
    type = models.CharField(max_length=20)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class History(models.Model):
    TRANSACTION_TYPE_CHOICES = (
        ('income', 'Income'),
        ('expense', 'Expense'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='history'
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPE_CHOICES)
    timestamp = models.DateTimeField()
    source = models.CharField(max_length=100)
    category = models.CharField(max_length=100, blank=True, null=True)
    reference_id = models.IntegerField(blank=True,null=True)  # ID from original Income/Expense
    
    # Additional useful fields
    description = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['type']),
            models.Index(fields=['category']),
        ]
        ordering = ['-timestamp']
        verbose_name_plural = 'Histories'

    def __str__(self):
        return f"{self.type.capitalize()} - {self.amount} ({self.category})"
    



    from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=Income)
def create_income_history(sender, instance, created, **kwargs):
    if created:
        History.objects.create(
            user=instance.user,
            amount=instance.amount,
            type='income',
            source=instance.origin,
            timestamp=instance.timestamp,
            category=instance.category.category_name if instance.category else None,
            reference_id=instance.id  # Store original Income ID
        )

@receiver(post_save, sender=Expense)
def create_expense_history(sender, instance, created, **kwargs):
    if created:
        History.objects.create(
            user=instance.user,
            amount=instance.amount,
            type='expense',
            source=instance.origin,
            timestamp=instance.timestamp,
            category=instance.category.category_name if instance.category else None,
            reference_id=instance.id  # Store original Expense ID
        )

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_payment(request):
    user = request.user
    user.is_verified = True
    user.save()
    return Response({'message': 'User verified as premium.'})