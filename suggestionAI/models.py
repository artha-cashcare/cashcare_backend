from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class AISuggestion(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    input_data = models.JSONField()
    suggestion = models.TextField()
    feedback = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Suggestion for {self.user.first_name} at {self.created_at.strftime('%Y-%m-%d %H:%M')}"
