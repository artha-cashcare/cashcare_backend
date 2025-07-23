from django.urls import path
from suggestionAI.views import generate_ai_suggestion  # Import your view here

urlpatterns = [
    path('generate/', generate_ai_suggestion, name='generate_ai'),
]
