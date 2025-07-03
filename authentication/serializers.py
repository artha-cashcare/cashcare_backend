from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import EmailOTP
from rest_framework.exceptions import ValidationError

from rest_framework import serializers
from .models import ExpenseCategory,Expense,IncomeCategory,Income,Receipt

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    phone = serializers.CharField(source='phone_number', required=False, allow_null=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'first_name', 'last_name', 'phone', 'profile_image')
        extra_kwargs = {
            'profile_image': {'required': False}
        }

    def validate_email(self, value):
        """ Ensure the email is not already used by another user """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        """ Create a new user without OTP """
        phone_number = validated_data.pop('phone_number', None)
        
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone_number=phone_number,
            profile_image=validated_data.get('profile_image'),
            is_verified=False
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        return data

class UserSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(source='phone_number')
    profile_image_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'phone', 
                 'profile_image', 'profile_image_url', 'is_verified', 'address')

    def get_profile_image_url(self, obj):
        if obj.profile_image:
            return self.context['request'].build_absolute_uri(obj.profile_image.url)
        return None

class ProfileSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(source='phone_number', required=False)
    profile_image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'phone', 'address', 'profile_image')
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False},
            'address': {'required': False},
        }

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    




class IncomeSerializer(serializers.ModelSerializer):
    category = serializers.CharField(write_only=True)

    class Meta:
        model = Income
        fields = ['amount', 'category', 'origin']
    
    def create(self, validated_data):
        category_name = validated_data.pop('category').lower()
        category, _ = IncomeCategory.objects.get_or_create(
            category_name=category_name
        )
        return Income.objects.create(
            **validated_data,
            category=category  # Store category ID, not name
        )
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['category'] = instance.category.category_name
        return representation



class ExpenseSerializer(serializers.ModelSerializer):
    category = serializers.CharField(write_only=True)

    class Meta:
        model = Expense
        fields = ['amount', 'category', 'origin']
    
    def create(self, validated_data):
        category_name = validated_data.pop('category').lower()
        category, _ = ExpenseCategory.objects.get_or_create(
            category_name=category_name
        )
        return Expense.objects.create(
            **validated_data,
            category=category  # Store category ID, not name
        )
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['category'] = instance.category.category_name
        return representation

    

from rest_framework import serializers
from .models import History

class HistorySerializer(serializers.ModelSerializer):
    type_display = serializers.CharField(source='get_type_display', read_only=True)
    
    class Meta:
        model = History
        fields = [
            'id',
            'amount',
            'type',
            'type_display',
            'timestamp',
            'source',
            'category',
            'description',
            'reference_id'
        ]
        read_only_fields = fields  # All fields are read-only
from rest_framework import serializers
from .models import Receipt, ExpenseCategory
from django.contrib.auth import get_user_model

User = get_user_model()

class ExpenseCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseCategory
        fields = ['id', 'category_name']

class ReceiptSerializer(serializers.ModelSerializer):
    category = serializers.CharField(write_only=True)
    linked_expense = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Receipt
        fields = [
            'id', 'file_path', 'scanned_text', 
            'amount', 'category', 'date', 
            'timestamp', 'linked_expense'
        ]
        read_only_fields = [
            'id', 'timestamp', 'scanned_text',
            'linked_expense'
        ]
    
    def get_linked_expense(self, obj):
        """Returns basic info about the linked expense if it exists"""
        if hasattr(obj, 'linked_expense'):
            expense = obj.linked_expense
            return {
                'id': expense.id,
                'amount': str(expense.amount),
                'origin': expense.origin
            }
        return None
    
    def create(self, validated_data):
        user = self.context['request'].user
        category_name = validated_data.pop('category')
        
        # Get or create category for this user
        category, _ = ExpenseCategory.objects.get_or_create(
            user=user,
            category_name=category_name.lower().strip(),
        )
        
        # Create receipt (signal will handle expense creation)
        receipt = Receipt.objects.create(
            user=user,
            category=category,
            **validated_data
        )
        
        return receipt
    


from authentication.models import ParsedSMS

class ParsedSMSController(serializers.ModelSerializer):
    class Meta:
        model=ParsedSMS
        fields=['id','user','amount','timestamp','parsed_type','category']
        read_only_fields=['id','timestamp','user']


from rest_framework import serializers
from .models import Goal, GoalIncomeCategoryRule, GoalNotification, IncomeCategory

from rest_framework import serializers
from .models import GoalIncomeCategoryRule, IncomeCategory

from rest_framework import serializers
from .models import Goal, GoalIncomeCategoryRule, GoalNotification, IncomeCategory

class GoalRuleSerializer(serializers.ModelSerializer):
    income_category = serializers.CharField(source='income_category.category_name')

    class Meta:
        model = GoalIncomeCategoryRule
        fields = ['income_category', 'percentage']

    def create(self, validated_data):
        # Get or create income category
        category_name = validated_data.pop('income_category')['category_name']
        category, _ = IncomeCategory.objects.get_or_create(category_name=category_name)
        
        return GoalIncomeCategoryRule.objects.create(
            income_category=category,
            **validated_data
        )

class GoalSerializer(serializers.ModelSerializer):
    rules = GoalRuleSerializer(many=True, required=False)
    progress_percentage = serializers.ReadOnlyField()
    days_remaining = serializers.ReadOnlyField()

    class Meta:
        model = Goal
        fields = ['id', 'user', 'title', 'target_amount', 'current_amount', 
                 'deadline', 'is_completed', 'is_failed', 'rules',
                 'progress_percentage', 'days_remaining']
        read_only_fields = ['user']  # User is set automatically

    def create(self, validated_data):
        rules_data = validated_data.pop('rules', [])  # adjust key if different
        goal = Goal.objects.create(**validated_data)  # create your Goal instance

        for rule_data in rules_data:
            category_data = rule_data.pop('income_category')  # this is a dict
        # get IncomeCategory instance from DB
            income_category_obj = IncomeCategory.objects.get(category_name=category_data['category_name'])
        # now create GoalIncomeCategoryRule with proper instance
            GoalIncomeCategoryRule.objects.create(
                    goal=goal,
            income_category=income_category_obj,
            **rule_data
        )
        return goal


class GoalNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalNotification
        fields = ['id', 'goal', 'type', 'message', 'is_read', 'created_at']
        read_only_fields = ['created_at']