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
