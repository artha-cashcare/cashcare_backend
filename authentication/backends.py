from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models import Q

class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            # Force lowercase email to avoid case sensitivity issues
            email = username.lower() if username else None
            user = UserModel.objects.get(email__iexact=email)
            
            # Debug logs
            print(f"🔐 User found: {user.email}")
            print(f"🔑 Password check: {user.check_password(password)}")
            print(f"✅ Active status: {user.is_active}")

            if user.check_password(password) and self.user_can_authenticate(user):
                print("🎉 Authentication successful!")
                return user
            else:
                print("❌ Authentication failed (password/active status)")
                return None
        except UserModel.DoesNotExist:
            print(f"❌ User with email '{username}' not found!")
            return None