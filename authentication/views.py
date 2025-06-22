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
from rest_framework.response import Response
from rest_framework import status
from django.views import View
from django.shortcuts import render
from django.http import Http404
import random
from django.core.mail import send_mail
from django.utils import timezone
from .models import EmailOTP
import re
from django.http import HttpResponse

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

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"detail": "Invalid email or password"}, status=401)

        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response({"detail": "Invalid email or password"}, status=401)

        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": UserSerializer(user, context={"request": request}).data

        })

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
from .models import Goal, GoalNotification
from .serializers import GoalSerializer, GoalNotificationSerializer

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

class GoalNotificationViewSet(viewsets.ModelViewSet):
    queryset = GoalNotification.objects.all()
    serializer_class = GoalNotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return GoalNotification.objects.filter(user=self.request.user)

    @action(detail=False, methods=['patch'])
    def mark_all_read(self, request):
        self.get_queryset().filter(is_read=False).update(is_read=True)
        return Response({'status': '✅ All marked as read'})
