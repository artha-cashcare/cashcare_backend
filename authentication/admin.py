# authentication/admin.py
from django.contrib import admin
from .models import CustomUser  # Change this to CustomUser

admin.site.register(CustomUser)  # Register the CustomUser model
