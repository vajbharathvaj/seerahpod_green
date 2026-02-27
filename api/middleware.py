from django.http import JsonResponse
from django.utils import timezone

from .models import AdminSession, User


class AdminAccessMiddleware:
    EXEMPT_PATHS = {
        '/api/v1/admin/auth/login/',
        '/api/v1/admin/auth/google/',
        '/api/v1/admin/auth/refresh/',
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if not path.startswith('/api/v1/admin/'):
            return self.get_response(request)

        if request.method == 'OPTIONS' or path in self.EXEMPT_PATHS:
            return self.get_response(request)

        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=401)

        access_token = auth_header.split(' ', 1)[1].strip()
        if not access_token:
            return JsonResponse({'detail': 'Invalid authorization token.'}, status=401)

        session = (
            AdminSession.objects.select_related('user')
            .filter(access_token=access_token, revoked_at__isnull=True)
            .first()
        )
        if session is None or session.access_expires_at <= timezone.now():
            return JsonResponse({'detail': 'Token is invalid or expired.'}, status=401)

        user = session.user
        if user.status != User.Status.ACTIVE:
            return JsonResponse({'detail': 'Account is not active.'}, status=403)
        if user.role not in (User.Role.ADMIN, User.Role.MANAGER):
            return JsonResponse({'detail': 'Admin access required.'}, status=403)

        request.admin_user = user
        request.admin_session = session
        return self.get_response(request)
