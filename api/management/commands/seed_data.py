from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand

from api.models import User


class Command(BaseCommand):
    help = "Seed default admin user."

    def handle(self, *args, **options):
        email = "vajbharath665@gmail.com"
        password = "vajbharathvaj"

        user, created = User.objects.update_or_create(
            email=email,
            defaults={
                "auth_provider": User.AuthProvider.EMAIL,
                "role": User.Role.ADMIN,
                "status": User.Status.ACTIVE,
                "is_email_verified": True,
                "password_hash": make_password(password),
            },
        )

        if created:
            self.stdout.write(self.style.SUCCESS(f"Created admin user: {user.email}"))
            return

        self.stdout.write(self.style.SUCCESS(f"Updated admin user: {user.email}"))
