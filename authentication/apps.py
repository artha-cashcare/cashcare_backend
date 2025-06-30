from django.apps import AppConfig

class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'authentication'

    def ready(self):
        import authentication.signals  

def ready(self):
        # Import signals to register them
        import authentication.signals  # Change to your actual app name