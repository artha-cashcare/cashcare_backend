import matplotlib
matplotlib.use('Agg')  # Set non-GUI backend
import matplotlib.pyplot as plt
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from .models import CustomUser
from django.contrib.auth import authenticate
from .serializers import (RegisterSerializer, LoginSerializer, UserSerializer, 
                         SendOTPSerializer, VerifyOTPSerializer, ProfileSerializer)
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView    
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.views import View
from django.shortcuts import render
from django.http import Http404
import random
import logging
from django.core.mail import send_mail
from django.utils import timezone
from .models import EmailOTP
import re
from django.http import HttpResponse
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import logging
from django.views.decorators.csrf import csrf_exempt
import json
# from .models import SMSData  # Make sure this exists
# RegisterView: for user registration
class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

# LoginView: for user login
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        print(f"📧 Login attempt - Email: {email}, Password: {password}")
        
        # Authenticate with the backend
        user = authenticate(request, username=email, password=password)
        print(f"👤 User object after auth: {user}")

        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": UserSerializer(user).data
            })
        return Response({"detail": "Invalid credentials"}, status=401)
    


def home_view(request):
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Welcome to CashCare</title>
        <style>
            body {
                margin: 0;
                padding: 0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(to right, #667eea, #764ba2);
                color: white;
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                text-align: center;
            }
            .container {
                padding: 40px;
                background: rgba(0, 0, 0, 0.3);
                border-radius: 15px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            }
            h1 {
                font-size: 3em;
                margin-bottom: 0.5em;
            }
            p {
                font-size: 1.2em;
                margin-top: 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Welcome to CashCare Backend</h1>
            <p>This is your API server. Use valid endpoints to get started.</p>
        </div>
    </body>
    </html>
    """
    return HttpResponse(html_content)

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Build dynamic domain from request
            origin = request.META.get('HTTP_ORIGIN')
            if origin and "http" in origin:
                domain = origin
            else:
                # fallback (e.g., if running via Postman or no origin header)
                domain = request.build_absolute_uri('/')[:-1]

            reset_link = f"{domain}/reset_password?uid={uid}&token={token}"

            send_mail(
                subject='Password Reset',
                message=f'Click the link to reset your password: {reset_link}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )
            return Response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

class PasswordResetConfirmView(APIView):
    def post(self, request):
        uidb64 = request.data.get('uid')
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password has been reset."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception:
            return Response({"error": "Something went wrong."}, status=status.HTTP_400_BAD_REQUEST)
        
class ResetPasswordView(View):
    def get(self, request):
        try:
            # Get the uid and token from the query parameters in the URL
            uidb64 = request.GET.get('uid')
            token = request.GET.get('token')

            # Decode the UID to get the user ID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)

            # Check if the token is valid for the user
            if not default_token_generator.check_token(user, token):
                return render(request, 'reset_password_error.html', {"error": "Invalid or expired token."})

            # If the token is valid, render the reset password form
            return render(request, 'authentication/reset_password.html', {"uidb64": uidb64, "token": token})

        except (TypeError, ValueError, CustomUser.DoesNotExist):
            # Raise an Http404 error if the UID or token is invalid
            raise Http404("The reset link is invalid or expired.")
        

class SendOTPView(APIView):
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = f"{random.randint(100000, 999999)}"

            EmailOTP.objects.update_or_create(email=email, defaults={
                'otp': otp,
                'created_at': timezone.now()
            })

            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}. It expires in 5 minutes.',
                'no-reply@example.com',
                [email],
                fail_silently=False
            )

            return Response({"message": "OTP sent successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            try:
                record = EmailOTP.objects.get(email=email)
                if record.is_expired():
                    return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)
                if record.otp != otp:
                    return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

                return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

            except EmailOTP.DoesNotExist:
                return Response({"error": "No OTP found for this email."}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user, context={'request': request})
        return Response(serializer.data)

    def patch(self, request):
        # Handle file upload separately if needed
        serializer = ProfileSerializer(
            request.user, 
            data=request.data,
            partial=True,
            context={'request': request}
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import Income
from .serializers import IncomeSerializer

class IncomeViews(APIView):
    permission_classes = [IsAuthenticated]  # Only logged-in users allowed

    def post(self, request):
        serializer = IncomeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)  # Assign logged-in user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        incomes = Income.objects.filter(user=request.user)
        return Response(list(incomes.values('amount', 'category', 'timestamp')), status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            income = Income.objects.get(pk=pk, user=request.user)  # Only update your own record
            serializer = IncomeSerializer(income, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Income.DoesNotExist:
            return Response({"error": "Income not found."}, status=status.HTTP_404_NOT_FOUND)
    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Expense
from .serializers import ExpenseSerializer

class ExpenseView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ExpenseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)  # ✅ Get user from JWT
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        expenses = Expense.objects.filter(user=request.user).order_by('-timestamp')
        serializer = ExpenseSerializer(expenses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


from rest_framework import generics, permissions, filters
from rest_framework import generics, filters
from .models import History
from .serializers import HistorySerializer
from django.utils import timezone
from datetime import timedelta
from django_filters.rest_framework import DjangoFilterBackend


class HistoryListView(generics.ListAPIView):
    serializer_class = HistorySerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ['type', 'category', 'source']
    ordering_fields = ['timestamp', 'amount']
    search_fields = ['category', 'description']
    ordering = ['-timestamp']  # Default ordering

    def get_queryset(self):
        queryset = History.objects.filter(user=self.request.user)
        
        # Date filtering
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        
        if date_from:
            queryset = queryset.filter(timestamp__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__lte=date_to)
            
        # Last N days filter
        last_days = self.request.query_params.get('last_days')
        if last_days and last_days.isdigit():
            date_threshold = timezone.now() - timedelta(days=int(last_days))
            queryset = queryset.filter(timestamp__gte=date_threshold)
            
        return queryset

class HistoryDetailView(generics.RetrieveAPIView):
    serializer_class = HistorySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return History.objects.filter(user=self.request.user)
    

from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Receipt, ExpenseCategory
from .serializers import ReceiptSerializer

class ScanReceiptAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Validate required fields
        required_fields = ['category', 'amount']
        errors = {}
        
        for field in required_fields:
            if field not in request.data or not request.data[field]:
                errors[field] = ['This field is required.']
        
        if errors:
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Prepare data for serializer
        data = {
            'category': request.data['category'],
            'amount': request.data['amount'],
            'date': request.data.get('date'),
            'file_path': request.FILES.get('file_path'),
            'scanned_text': request.data.get('scanned_text', '')
        }
        
        serializer = ReceiptSerializer(
            data=data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            receipt = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


from rest_framework import generics, permissions
from .models import ParsedSMS
from .serializers import ParsedSMSController

class ParsedSMSListCreateView(generics.ListCreateAPIView):
    serializer_class = ParsedSMSController
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ParsedSMS.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    
    

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Goal, Notification
from .serializers import GoalSerializer,NotificationSerializer

class GoalViewSet(viewsets.ModelViewSet):
    queryset = Goal.objects.all()
    serializer_class = GoalSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Goal.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False)
    def active(self, request):
        goals = self.get_queryset().filter(is_completed=False, is_failed=False)
        return Response(self.serializer_class(goals, many=True).data)

    @action(detail=True)
    def progress_data(self, request, pk=None):
        goal = self.get_object()
        return Response({
            'current': goal.current_amount,
            'target': goal.target_amount,
            'progress_percentage': goal.progress_percentage,
            'days_remaining': goal.days_remaining
        })

class NotificationViewSet(viewsets.ModelViewSet):
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)

    @action(detail=False, methods=['patch'])
    def mark_all_read(self, request):
        self.get_queryset().filter(read=False).update(read=True)
        return Response({'status': '✅ All marked as read'})

from django.contrib.auth import get_user_model
from google.oauth2 import id_token
from google.auth.transport import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from google.auth.transport import requests as google_requests


User = get_user_model()

class GoogleLoginView(APIView):
    def post(self, request):
        token = request.data.get('id_token')
        try:
            # Verify token
            idinfo = id_token.verify_oauth2_token(token, google_requests.Request())

            email = idinfo['email']
            name = idinfo.get('name', '')
            first_name = name.split(' ')[0]
            last_name = ' '.join(name.split(' ')[1:])

            user, created = User.objects.get_or_create(email=email, defaults={
                'username': email,
                'first_name': first_name,
                'last_name': last_name
            })

            # Return JWT
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'created': created
            })

        except ValueError as e:
            return Response({'error': 'Invalid token'}, status=400)



from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Sum
from django.db.models.functions import TruncMonth
from .models import Income, Expense

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def monthly_income_expense(request):
    user = request.user

    income = (
        Income.objects.filter(user=user)
        .annotate(month=TruncMonth('timestamp'))
        .values('month')
        .annotate(total=Sum('amount'))
        .order_by('month')
    )
    expense = (
        Expense.objects.filter(user=user)
        .annotate(month=TruncMonth('timestamp'))
        .values('month')
        .annotate(total=Sum('amount'))
        .order_by('month')
    )

    return Response({
        'income': list(income),
        'expense': list(expense)
    })
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def category_summary(request):
    user = request.user

    income = (
        Income.objects.filter(user=user)
        .values('category__category_name')
        .annotate(total=Sum('amount'))
        .order_by('-total')
    )
    expense = (
        Expense.objects.filter(user=user)
        .values('category__category_name')
        .annotate(total=Sum('amount'))
        .order_by('-total')
    )

    return Response({
        'income_by_category': list(income),
        'expense_by_category': list(expense)
    })

import logging

@permission_classes([IsAuthenticated])
class UserChartData(APIView):
    def get(self, request):
        user = request.user  # Authenticated user from token

        try:
            # Fetch income and expense data for the user
            income_data = Income.objects.filter(user=user).values('category__category_name').annotate(total=Sum('amount'))
            expense_data = Expense.objects.filter(user=user).values('category__category_name').annotate(total=Sum('amount'))

# Rename the key from 'category__name' → 'category'
            income_data = list(income_data)
            for item in income_data:
                item['category'] = item.pop('category__category_name')

            expense_data = list(expense_data)
            for item in expense_data:
                item['category'] = item.pop('category__category_name')



            if not income_data and not expense_data:
                return Response({"error": "No income or expense data found for this user."}, status=status.HTTP_404_NOT_FOUND)

            income_df = pd.DataFrame(list(income_data))
            expense_df = pd.DataFrame(list(expense_data))

            charts = {}

            # Generate income chart
            if not income_df.empty:
                fig, ax = plt.subplots(figsize=(10, 6))
                ax.bar(income_df['category'], income_df['total'], color='green', alpha=0.6)
                ax.set_xlabel('Income Source')
                ax.set_ylabel('Total Amount')
                ax.set_title('Income')
                buf = BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                charts['income_chart'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)

            # Generate expense chart
            if not expense_df.empty:
                fig, ax = plt.subplots(figsize=(10, 6))
                ax.bar(expense_df['category'], expense_df['total'], color='red', alpha=0.6)
                ax.set_xlabel('Expense Source')
                ax.set_ylabel('Total Amount')
                ax.set_title('Expenses')
                buf = BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                charts['expense_chart'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)

            return Response({
                'charts': charts,
                'income': list(income_data),
                'expense': list(expense_data),
            })

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Error generating chart data: {str(e)}")
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@permission_classes([IsAuthenticated])
class monthly_income_chart(APIView):
    def get(self, request):
        user = request.user  # Authenticated user

        try:
            income_data = (
                Income.objects.filter(user=user)
                .annotate(month=TruncMonth('timestamp'))
                .values('month')
                .annotate(total_income=Sum('amount'))
                .order_by('month')
            )

            expense_data = (
                Expense.objects.filter(user=user)
                .annotate(month=TruncMonth('timestamp'))
                .values('month')
                .annotate(total_expense=Sum('amount'))
                .order_by('month')
            )

            if not income_data and not expense_data:
                return Response({"error": "No income or expense data found for this user."}, status=status.HTTP_404_NOT_FOUND)

            income_df = pd.DataFrame(list(income_data))
            expense_df = pd.DataFrame(list(expense_data))

            income_df['month'] = income_df['month'].dt.to_period('M')
            expense_df['month'] = expense_df['month'].dt.to_period('M')

            charts = {}

            if not income_df.empty:
                fig, ax = plt.subplots(figsize=(10, 6))
                ax.bar(income_df['month'].astype(str), income_df['total_income'], color='green', label='Income')
                ax.set_xlabel('Month')
                ax.set_ylabel('Total Income')
                ax.set_title('Monthly Income')
                ax.legend()
                buf = BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                charts['income_chart'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)

            if not expense_df.empty:
                fig, ax = plt.subplots(figsize=(10, 6))
                ax.bar(expense_df['month'].astype(str), expense_df['total_expense'], color='red', label='Expense')
                ax.set_xlabel('Month')
                ax.set_ylabel('Total Expense')
                ax.set_title('Monthly Expenses')
                ax.legend()
                buf = BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                charts['expense_chart'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)

            return Response({
                'charts': charts,
                'income': list(income_data),
                'expense': list(expense_data),
            })

        except Exception as e:
            logger = logging.getLogger(__name__)

            logger.error(f"Error generating monthly summary: {str(e)}")
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@permission_classes([IsAuthenticated])
class MonthlyExpenseComparison(APIView):
    def get(self, request):
        user = request.user

        try:
            expense_data = (
                Expense.objects.filter(user=user)
                .annotate(month=TruncMonth('timestamp'))
                .values('month')
                .annotate(total_expense=Sum('amount'))
                .order_by('month')
            )

            expense_dict = {item["month"]: item["total_expense"] for item in expense_data}
            sorted_months = sorted(expense_dict.keys(), reverse=True)

            if len(sorted_months) < 2:
                return Response({"message": "Not enough data to compare expenses."})

            current_month = sorted_months[0]
            last_month = sorted_months[1]

            current_expense = expense_dict.get(current_month, 0)
            last_expense = expense_dict.get(last_month, 0)

            if last_expense > 0:
                expense_change = ((current_expense - last_expense) / last_expense) * 100
            else:
                expense_change = 0

            if expense_change > 50:
                message = f"Warning! Your expenses increased by {expense_change:.2f}% this month. Try reducing unnecessary spending."
            elif expense_change > 20:
                message = f"Your expenses increased by {expense_change:.2f}%. Consider reviewing your budget!"
            elif expense_change < 0:
                message = f"Great job! You spent {abs(expense_change):.2f}% less than last month. Keep saving!"
            else:
                message = "Your expenses are stable. Maintain good financial habits!"

            return Response({
                'current_month': str(current_month),
                'last_month': str(last_month),
                'current_expense': current_expense,
                'last_expense': last_expense,
                'expense_change': round(expense_change, 2),
                'message': message
            })

        except Exception as e:
            logger = logging.getLogger(__name__)

            logger.error(f"Error generating expense comparison: {str(e)}")
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@permission_classes([IsAuthenticated])
class SourceExpenseComparison(APIView):
    def get(self, request):
        user = request.user

        try:
            # Query to get category_name instead of category ID
            expense_data = (
                Expense.objects.filter(user=user)
                .values('category__category_name')  # <-- get category_name via related field
                .annotate(total_expense=Sum('amount'))
                .order_by('-total_expense')
            )

            if not expense_data:
                return Response({"message": "No expense data available."})

            # Convert to list so we can modify keys
            expense_data = list(expense_data)

            # Rename 'category__category_name' key to 'category' for clarity
            for item in expense_data:
                item['category'] = item.pop('category__category_name')

            highest_source = expense_data[0]['category']
            highest_expense = expense_data[0]['total_expense']

            message = f"Alert! You have spent the most on {highest_source} with an expense of {highest_expense:.2f}. Consider reviewing your spending."

            return Response({
                'source_expenses': expense_data,
                'highest_source': highest_source,
                'highest_expense': highest_expense,
                'message': message
            })

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Error generating source expense comparison: {str(e)}")
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from datetime import datetime
from django.http import HttpResponse
from django.db.models import Sum
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import matplotlib.pyplot as plt
import pandas as pd
from io import BytesIO
import numpy as np
import json
import base64
import logging
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
from PIL import Image
import re
import os
from django.utils.decorators import method_decorator
from django.http import JsonResponse
from .models import Receipt
import matplotlib
from django.db.models.functions import TruncMonth
import pickle
from .models import Goal
from .serializers import GoalSerializer
from .utils import predict
from joblib import load
matplotlib.use('Agg')

class PredictView(APIView):
 def post(self, request):
        features = request.data.get('features', [])
        
        # Check if the number of features is correct (5)
        if len(features) != 5:
            return Response({"error": "Missing or incorrect number of features. Expected 5."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Get the prediction, category, and recommendation
            prediction, category, recommendation = predict(features)
            
            return Response({
                "prediction": prediction,
                "category": category,
                "recommendation": recommendation
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.utils.timezone import make_aware


class MonthlySummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        report_type = request.GET.get("type", "month")
        year = request.GET.get("year")
        month = request.GET.get("month")
        quarter = request.GET.get("quarter")

        def summarize(start, end):
            transactions = History.objects.filter(user=user, timestamp__gte=start, timestamp__lt=end)
            income = transactions.filter(type="income").aggregate(total=Sum("amount"))["total"] or 0
            expenses = transactions.filter(type="expense").aggregate(total=Sum("amount"))["total"] or 0
            remaining = income - expenses
            breakdown_qs = transactions.filter(type="expense").values("category").annotate(amount=Sum("amount")).order_by("-amount")
            breakdown = [{"category": b["category"], "amount": b["amount"]} for b in breakdown_qs]
            top_txn_qs = transactions.order_by("-amount")[:5].values("category", "amount", "timestamp")
            top_txns = [{"title": t["category"], "amount": t["amount"], "date": t["timestamp"].date()} for t in top_txn_qs]
            return {
                "total_income": income,
                "total_expenses": expenses,
                "remaining": remaining,
                "breakdown": breakdown,
                "top_transactions": top_txns,
            }

        try:
            if report_type == "month":
                if not month:
                    return Response({"error": "month is required"}, status=400)
                start = make_aware(datetime.strptime(month + "-01", "%Y-%m-%d"))
                end = make_aware(datetime.strptime(f"{start.year}-{start.month + 1 if start.month < 12 else 1}-01", "%Y-%m-%d")) if start.month < 12 else make_aware(datetime.strptime(f"{start.year + 1}-01-01", "%Y-%m-%d"))
                return Response({"month": start.strftime("%B %Y"), **summarize(start, end)})

            elif report_type == "quarter":
                if not (year and quarter):
                    return Response({"error": "year and quarter are required"}, status=400)
                quarter = int(quarter)
                start_month = 3 * (quarter - 1) + 1
                start = make_aware(datetime.strptime(f"{year}-{start_month:02d}-01", "%Y-%m-%d"))
                end_month = start_month + 3
                if end_month > 12:
                    end = make_aware(datetime.strptime(f"{int(year) + 1}-01-01", "%Y-%m-%d"))
                else:
                    end = make_aware(datetime.strptime(f"{year}-{end_month:02d}-01", "%Y-%m-%d"))
                return Response({"quarter": f"Q{quarter} {year}", **summarize(start, end)})

            elif report_type == "year":
                if not year:
                    return Response({"error": "year is required"}, status=400)
                start = make_aware(datetime.strptime(f"{year}-01-01", "%Y-%m-%d"))
                end = make_aware(datetime.strptime(f"{int(year)+1}-01-01", "%Y-%m-%d"))
                return Response({"year": year, **summarize(start, end)})

            elif report_type == "all_months":
                if not year:
                    return Response({"error": "year is required"}, status=400)
                reports = []
                for m in range(1, 13):
                    start = make_aware(datetime.strptime(f"{year}-{m:02d}-01", "%Y-%m-%d"))
                    end_month = m + 1 if m < 12 else 1
                    end_year = int(year) if m < 12 else int(year) + 1
                    end = make_aware(datetime.strptime(f"{end_year}-{end_month:02d}-01", "%Y-%m-%d"))
                    summary = summarize(start, end)
                    summary["month"] = start.strftime("%B")
                    reports.append(summary)
                return Response({"year": year, "monthly_reports": reports})

            else:
                return Response({"error": "Invalid report type"}, status=400)

        except Exception as e:
            return Response({"error": str(e)}, status=500)







def dashboard(requesst):
    return HttpResponse("This is the testing of dashboard")


from django.contrib.auth import get_user_model
from django.shortcuts import render
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Sum

@staff_member_required
def custom_admin_dashboard(request):
    User = get_user_model()
    
    total_users = User.objects.count()
    scanned_expenses = Expense.objects.filter(origin='scanned').count()
    manual_expenses = Expense.objects.filter(origin='manual').count()
    total_parsed_amount = ParsedSMS.objects.aggregate(total=Sum('amount'))['total'] or 0

    context = {
        "total_users": total_users,
        "scanned_expenses": scanned_expenses,
        "manual_expenses": manual_expenses,
        "total_parsed_amount": total_parsed_amount,
    }

    return render(request, "custom_dashboard.html", context)

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from authentication.models import Payment, Notification
from django.utils import timezone
from datetime import datetime, timezone as dt_timezone


class VerifyAndStorePaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        user = request.user

        transaction_date_str = request.data['transactionDetails']['date']
        naive_dt = datetime.fromisoformat(transaction_date_str)
        aware_dt = timezone.make_aware(naive_dt, timezone=dt_timezone.utc)
        try:
            # 1. Store payment
            Payment.objects.create(
                user=user,
                product_id=data['productId'],
                product_name=data['productName'],
                amount=data['totalAmount'],
                reference_id=data['transactionDetails']['referenceId'],
                status=data['transactionDetails']['status'],
                transaction_date=aware_dt
            )

            # 2. Create goal notification
            Notification.objects.create(
                user=user,
                type='payment',
                message=f"Payment successful for {data['productName']} (₹{data['totalAmount']})"
            )

            # 3. Mark user as verified (premium)
            user.is_verified = True
            user.save()

            return Response({
                'status': 'success',
                'message': 'Payment recorded and user verified as premium.'
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
