import uuid
import json
import hashlib
import hmac
import secrets
import string
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core import signing
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from rest_framework.response import Response
from django.utils import timezone
from django.db.models import Avg, Case, Count, F, IntegerField, Max, Q, Sum, When
from django.utils.dateparse import parse_datetime
from rest_framework import serializers, status
from rest_framework.views import APIView

from .models import Category, PlayEvent, Playlist, PlaylistClickEvent, PlaylistTrack, RecommendationRule, SearchLog, SupportMessage, SupportTicket, Track, User, UserMfaBackupCode, UserMfaTotp, UserNotification, UserSession, UserSettings, UserTrackLike


class HealthView(APIView):
    def get(self, request):
        return Response({'status': 'ok'})


USER_ACCESS_TOKEN_TTL_MINUTES = getattr(settings, 'USER_ACCESS_TOKEN_TTL_MINUTES', 60)
USER_REFRESH_TOKEN_TTL_DAYS = getattr(settings, 'USER_REFRESH_TOKEN_TTL_DAYS', 30)
USER_LOGIN_2FA_TOKEN_MAX_AGE_SECONDS = getattr(settings, 'USER_LOGIN_2FA_TOKEN_MAX_AGE_SECONDS', 300)
LIKED_SONGS_PLAYLIST_ID = uuid.UUID('00000000-0000-0000-0000-00000000f00d')


def _get_google_server_client_id():
    # serverClientId used by Flutter GoogleSignIn should be the Web OAuth client id.
    server_client_id = (getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '') or '').strip()
    if server_client_id:
        return server_client_id
    return (getattr(settings, 'GOOGLE_OAUTH_MOBILE_CLIENT_ID', '') or '').strip()


def _get_allowed_google_client_ids():
    allowed = []
    for value in [
        getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', ''),
        getattr(settings, 'GOOGLE_OAUTH_MOBILE_CLIENT_ID', ''),
    ]:
        client_id = (value or '').strip()
        if client_id and client_id not in allowed:
            allowed.append(client_id)
    return allowed


def _serialize_user(user):
    has_2fa_enabled = UserMfaTotp.objects.filter(user=user, is_enabled=True).exists()
    return {
        'id': str(user.id),
        'email': user.email,
        'username': user.username,
        'has_password': bool(user.password_hash),
        'has_2fa_enabled': has_2fa_enabled,
        'role': user.role,
        'status': user.status,
        'auth_provider': user.auth_provider,
        'is_email_verified': user.is_email_verified,
    }


def _create_user_session(user):
    now = timezone.now()
    access_token = uuid.uuid4().hex + uuid.uuid4().hex
    refresh_token = uuid.uuid4().hex + uuid.uuid4().hex
    return UserSession.objects.create(
        user=user,
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=now + timezone.timedelta(minutes=USER_ACCESS_TOKEN_TTL_MINUTES),
        refresh_expires_at=now + timezone.timedelta(days=USER_REFRESH_TOKEN_TTL_DAYS),
    )


def _hash_email_otp_code(code: str):
    payload = f'{settings.SECRET_KEY}:{(code or "").strip()}'.encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _email_otp_matches_hash(expected_hash: str, code: str):
    candidate = _hash_email_otp_code(code)
    return hmac.compare_digest((expected_hash or '').strip(), candidate)


def _generate_email_otp_code(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def _mask_email(email: str):
    email = (email or '').strip()
    if '@' not in email:
        return email
    local, domain = email.split('@', 1)
    if len(local) <= 2:
        local_masked = local[0] + '*' * max(len(local) - 1, 0)
    else:
        local_masked = local[:2] + ('*' * (len(local) - 2))
    return f'{local_masked}@{domain}'


def _send_email_2fa_code(user, *, code: str, reason: str):
    subject = 'SeerahPod verification code'
    body = (
        'Use the following verification code for your SeerahPod account:\n\n'
        f'{code}\n\n'
        f'Reason: {reason}\n'
        'This code expires shortly. If you did not request this, ignore this email.'
    )
    send_mail(
        subject=subject,
        message=body,
        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@seerahpod.local'),
        recipient_list=[user.email],
        fail_silently=False,
    )


def _create_login_2fa_token(user, *, code):
    payload = {
        'user_id': str(user.id),
        'code_hash': _hash_email_otp_code(code),
        'nonce': secrets.token_urlsafe(12),
    }
    return signing.dumps(payload, salt='user.login.2fa')


def _resolve_login_2fa_token(token: str):
    try:
        payload = signing.loads(
            token,
            salt='user.login.2fa',
            max_age=USER_LOGIN_2FA_TOKEN_MAX_AGE_SECONDS,
        )
    except signing.BadSignature:
        return None, None

    user_id = payload.get('user_id') if isinstance(payload, dict) else None
    if not user_id:
        return None, None
    user = User.objects.filter(id=user_id).first()
    if user is None or user.status != User.Status.ACTIVE:
        return None, None
    return user, payload


def _normalize_2fa_code(raw: str) -> str:
    code = ''.join(ch for ch in (raw or '').strip() if ch.isalnum())
    return code.upper()


def _generate_backup_codes(count=10):
    codes = []
    for _ in range(count):
        raw = ''.join(secrets.choice(string.digits) for _ in range(8))
        codes.append(f'{raw[:4]}-{raw[4:]}')
    return codes


def _replace_backup_codes(user):
    plain_codes = _generate_backup_codes()
    UserMfaBackupCode.objects.filter(user=user).delete()
    UserMfaBackupCode.objects.bulk_create(
        [
            UserMfaBackupCode(
                user=user,
                code_hash=make_password(_normalize_2fa_code(code)),
            )
            for code in plain_codes
        ]
    )
    return plain_codes


def _consume_backup_code(user, code: str) -> bool:
    normalized_code = _normalize_2fa_code(code)
    if not normalized_code:
        return False
    candidates = UserMfaBackupCode.objects.filter(user=user, used_at__isnull=True).order_by('created_at')
    for row in candidates:
        if check_password(normalized_code, row.code_hash):
            updated = UserMfaBackupCode.objects.filter(id=row.id, used_at__isnull=True).update(used_at=timezone.now())
            return updated == 1
    return False


def _verify_user_2fa_code(user, code: str) -> bool:
    mfa = UserMfaTotp.objects.filter(user=user, is_enabled=True).first()
    if mfa is None:
        return False
    return _consume_backup_code(user, code)


def _verify_google_id_token(id_token: str):
    id_token = (id_token or '').strip()
    if not id_token:
        raise ValueError('Missing id_token.')

    allowed_client_ids = _get_allowed_google_client_ids()
    if not allowed_client_ids:
        raise RuntimeError('Google OAuth client IDs are not configured on the server.')

    url = 'https://oauth2.googleapis.com/tokeninfo?' + urllib_parse.urlencode({'id_token': id_token})
    try:
        with urllib_request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except urllib_error.HTTPError as exc:
        try:
            details = json.loads(exc.read().decode('utf-8'))
        except Exception:
            details = {}
        raise ValueError(details.get('error_description') or details.get('error') or 'Invalid Google token.') from exc
    except Exception as exc:
        raise RuntimeError('Unable to verify Google token.') from exc

    aud = payload.get('aud')
    if aud not in allowed_client_ids:
        raise ValueError('Google token audience mismatch.')

    email = (payload.get('email') or '').strip().lower()
    sub = (payload.get('sub') or '').strip()
    email_verified = payload.get('email_verified')
    if isinstance(email_verified, str):
        email_verified = email_verified.lower() == 'true'

    if not email:
        raise ValueError('Google token did not include an email.')
    if not sub:
        raise ValueError('Google token did not include a subject (sub).')
    if email_verified is not True:
        raise ValueError('Google email is not verified.')

    return {'email': email, 'sub': sub}


def _get_bearer_token(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return None
    access_token = auth_header.split(' ', 1)[1].strip()
    return access_token or None


def _get_active_user_session_from_request(request):
    access_token = _get_bearer_token(request)
    if not access_token:
        return None
    session = (
        UserSession.objects.select_related('user')
        .filter(access_token=access_token, revoked_at__isnull=True)
        .first()
    )
    if session is None or session.access_expires_at <= timezone.now():
        return None
    if session.user.status != User.Status.ACTIVE:
        return None
    return session


def _sanitize_username_base(value: str) -> str:
    allowed = ''.join(ch for ch in (value or '').lower() if ch.isalnum() or ch in '._-')
    allowed = allowed.strip('._-')
    if not allowed:
        return 'user'
    return allowed[:140]


def _normalize_requested_username(value: str) -> str:
    raw = (value or '').strip()
    if not raw:
        raise ValueError('Username is required.')
    normalized = _sanitize_username_base(raw)
    if not normalized:
        raise ValueError('Username must include letters or numbers.')
    if len(normalized) < 3:
        raise ValueError('Username must be at least 3 characters.')
    return normalized


def _build_unique_username_from_email(email: str, *, exclude_user_id=None) -> str:
    local_part = (email or '').strip().lower().split('@', 1)[0]
    base = _sanitize_username_base(local_part)
    candidate = base
    suffix = 2
    lookup = User.objects.all()
    if exclude_user_id:
        lookup = lookup.exclude(id=exclude_user_id)
    while lookup.filter(username__iexact=candidate).exists():
        suffix_text = f'_{suffix}'
        candidate = f'{base[:150 - len(suffix_text)]}{suffix_text}'
        suffix += 1
    return candidate


def _get_or_create_user_settings(user):
    settings_obj, _ = UserSettings.objects.get_or_create(user=user)
    return settings_obj


def _serialize_user_settings(settings_obj):
    return {
        'playback_speed': float(settings_obj.playback_speed),
        'auto_play_next': bool(settings_obj.auto_play_next),
        'download_over_wifi_only': bool(settings_obj.download_over_wifi_only),
        'background_play_enabled': bool(settings_obj.background_play_enabled),
        'notifications_enabled': bool(settings_obj.notifications_enabled),
        'silent_mode': bool(settings_obj.silent_mode),
        'analytics_enabled': bool(settings_obj.analytics_enabled),
        'personalization_enabled': bool(settings_obj.personalization_enabled),
    }


def _serialize_user_notification(row: UserNotification):
    return {
        'id': str(row.id),
        'type': row.notification_type,
        'title': row.title,
        'message': row.message,
        'action_label': row.action_label,
        'action_route': row.action_route,
        'metadata': row.metadata or {},
        'is_read': bool(row.read_at),
        'read_at': row.read_at,
        'created_at': row.created_at,
    }


def _serialize_support_user(user: User | None):
    if user is None:
        return None
    return {
        'id': str(user.id),
        'email': user.email,
        'username': user.username,
        'role': user.role,
    }


def _serialize_support_ticket(ticket: SupportTicket):
    return {
        'id': str(ticket.id),
        'user_id': str(ticket.user_id),
        'subject': ticket.subject,
        'status': ticket.status,
        'priority': ticket.priority,
        'last_message_at': ticket.last_message_at,
        'closed_at': ticket.closed_at,
        'user_unread_count': int(ticket.user_unread_count or 0),
        'admin_unread_count': int(ticket.admin_unread_count or 0),
        'created_at': ticket.created_at,
        'updated_at': ticket.updated_at,
        'user': _serialize_support_user(getattr(ticket, 'user', None)),
        'assigned_admin': _serialize_support_user(getattr(ticket, 'assigned_admin', None)),
    }


def _serialize_support_message(row: SupportMessage):
    return {
        'id': str(row.id),
        'ticket_id': str(row.ticket_id),
        'sender_type': row.sender_type,
        'sender_user_id': str(row.sender_user_id) if row.sender_user_id else None,
        'message': row.message,
        'attachment_url': row.attachment_url,
        'client_message_id': row.client_message_id,
        'created_at': row.created_at,
        'sender_user': _serialize_support_user(getattr(row, 'sender_user', None)),
    }


def _non_empty_q(field_name: str):
    return Q(**{f'{field_name}__isnull': False}) & ~Q(**{f'{field_name}__exact': ''})


def _playable_track_q(prefix: str = ''):
    return _non_empty_q(f'{prefix}audio_url')


def _track_cover_image_urls(track):
    urls = []
    for image in track.cover_images.all().order_by('position', 'created_at'):
        value = (image.image_url or '').strip()
        if value and value not in urls:
            urls.append(value)

    cover = (track.cover_image_url or '').strip()
    if cover and cover not in urls:
        urls.insert(0, cover)
    return urls


def _normalize_search_query(value: str) -> str:
    return ' '.join((value or '').strip().lower().split())


def _resolve_search_source_screen(request):
    raw = (
        request.query_params.get('source_screen')
        or request.META.get('HTTP_X_SOURCE_SCREEN')
        or ''
    ).strip().lower()
    if raw == SearchLog.SourceScreen.HOME:
        return SearchLog.SourceScreen.HOME
    return SearchLog.SourceScreen.SEARCH_PAGE


def _resolve_search_device_platform(request):
    raw = (
        request.query_params.get('device_platform')
        or request.META.get('HTTP_X_DEVICE_PLATFORM')
        or ''
    ).strip().lower()
    if raw == SearchLog.DevicePlatform.IOS:
        return SearchLog.DevicePlatform.IOS
    if raw == SearchLog.DevicePlatform.ANDROID:
        return SearchLog.DevicePlatform.ANDROID

    user_agent = (request.META.get('HTTP_USER_AGENT') or '').lower()
    if 'iphone' in user_agent or 'ipad' in user_agent or 'ios' in user_agent:
        return SearchLog.DevicePlatform.IOS
    return SearchLog.DevicePlatform.ANDROID


def _resolve_playlist_click_source(request):
    raw = (
        request.query_params.get('source')
        or request.META.get('HTTP_X_SOURCE')
        or ''
    ).strip().lower()
    if raw == PlaylistClickEvent.Source.HOME:
        return PlaylistClickEvent.Source.HOME
    if raw == PlaylistClickEvent.Source.SEARCH:
        return PlaylistClickEvent.Source.SEARCH
    return PlaylistClickEvent.Source.LIBRARY


def _resolve_playlist_click_device_platform(request):
    resolved = _resolve_search_device_platform(request)
    if resolved == SearchLog.DevicePlatform.IOS:
        return PlaylistClickEvent.DevicePlatform.IOS
    return PlaylistClickEvent.DevicePlatform.ANDROID


def _log_search_query(request, *, query: str, result_count: int):
    if not query:
        return

    try:
        session = _get_active_user_session_from_request(request)
        SearchLog.objects.create(
            user=session.user if session else None,
            query=query,
            normalized_query=_normalize_search_query(query),
            result_count=max(int(result_count), 0),
            source_screen=_resolve_search_source_screen(request),
            device_platform=_resolve_search_device_platform(request),
        )
    except Exception:
        # Search logging must never break user-facing search.
        pass


def _parse_limit_offset(request, *, default_limit=20, max_limit=500):
    limit_raw = request.query_params.get('limit', default_limit)
    offset_raw = request.query_params.get('offset', 0)
    try:
        limit = max(min(int(limit_raw), max_limit), 1)
    except (TypeError, ValueError):
        limit = default_limit
    try:
        offset = max(int(offset_raw), 0)
    except (TypeError, ValueError):
        offset = 0
    return limit, offset


class UserSignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)


class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()


class UserGoogleLoginSerializer(serializers.Serializer):
    id_token = serializers.CharField()


class UserRefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class UserProfileUpdateSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)

    def validate_username(self, value):
        return _normalize_requested_username(value)


class UserPasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField()

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})
        if attrs['current_password'] == attrs['new_password']:
            raise serializers.ValidationError({'new_password': 'New password must be different from current password.'})
        return attrs


class UserPasswordSetSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField()

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})
        return attrs


class UserLogin2FAVerifySerializer(serializers.Serializer):
    mfa_token = serializers.CharField()
    code = serializers.CharField()


class User2FATotpVerifySerializer(serializers.Serializer):
    code = serializers.CharField()


class User2FATotpDisableSerializer(serializers.Serializer):
    current_password = serializers.CharField()
    code = serializers.CharField()


class User2FABackupCodesRegenerateSerializer(serializers.Serializer):
    current_password = serializers.CharField()
    code = serializers.CharField()


class UserSettingsUpdateSerializer(serializers.Serializer):
    playback_speed = serializers.FloatField(required=False, min_value=0.25, max_value=2.0)
    auto_play_next = serializers.BooleanField(required=False)
    download_over_wifi_only = serializers.BooleanField(required=False)
    background_play_enabled = serializers.BooleanField(required=False)
    notifications_enabled = serializers.BooleanField(required=False)
    silent_mode = serializers.BooleanField(required=False)
    analytics_enabled = serializers.BooleanField(required=False)
    personalization_enabled = serializers.BooleanField(required=False)


class UserNotificationUpdateSerializer(serializers.Serializer):
    is_read = serializers.BooleanField(required=False)


class UserSessionsRevokeAllSerializer(serializers.Serializer):
    keep_current = serializers.BooleanField(required=False, default=False)


class UserTrackLikeUpdateSerializer(serializers.Serializer):
    is_liked = serializers.BooleanField(required=True)


class SupportMessageSendSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=2000)
    client_message_id = serializers.CharField(max_length=128, required=False, allow_blank=True, allow_null=True)

    def validate_message(self, value):
        normalized = (value or '').strip()
        if not normalized:
            raise serializers.ValidationError('Message cannot be empty.')
        return normalized

    def validate_client_message_id(self, value):
        normalized = (value or '').strip()
        return normalized or None


class SupportTicketStatusUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=SupportTicket.Status.choices)


class SupportTicketAssignSerializer(serializers.Serializer):
    admin_id = serializers.UUIDField(required=False, allow_null=True)


class PlayEventCreateSerializer(serializers.Serializer):
    track_id = serializers.UUIDField()
    played_seconds = serializers.IntegerField(required=False, min_value=0)
    total_duration = serializers.IntegerField(required=False, min_value=1)
    completion_percentage = serializers.FloatField(required=False, min_value=0, max_value=100)
    source = serializers.ChoiceField(required=False, choices=PlayEvent.Source.choices)
    device_platform = serializers.ChoiceField(required=False, choices=PlayEvent.DevicePlatform.choices)


class PlaylistClickCreateSerializer(serializers.Serializer):
    source = serializers.ChoiceField(required=False, choices=PlaylistClickEvent.Source.choices)
    device_platform = serializers.ChoiceField(
        required=False,
        choices=PlaylistClickEvent.DevicePlatform.choices,
    )


class UserAuthGoogleConfigView(APIView):
    permission_classes = []

    def get(self, request, **kwargs):
        client_id = _get_google_server_client_id()
        return Response(
            {
                'ok': True,
                'google_server_client_id': client_id,
            }
        )


class UserAuthSignupView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = UserSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email'].strip().lower()
        password = serializer.validated_data['password']
        requested_username = (serializer.validated_data.get('username') or '').strip()

        existing = User.objects.filter(email__iexact=email).first()
        if existing is not None:
            return Response({'detail': 'An account with this email already exists.'}, status=status.HTTP_409_CONFLICT)

        if requested_username:
            try:
                username = _normalize_requested_username(requested_username)
            except ValueError as exc:
                return Response({'username': [str(exc)]}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects.filter(username__iexact=username).exists():
                return Response({'detail': 'Username is already taken.'}, status=status.HTTP_409_CONFLICT)
        else:
            username = _build_unique_username_from_email(email)

        user = User.objects.create(
            email=email,
            username=username,
            password_hash=make_password(password),
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            is_email_verified=False,
            last_login_at=timezone.now(),
        )
        session = _create_user_session(user)
        return Response(
            {
                'ok': True,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_user(user),
            },
            status=status.HTTP_201_CREATED,
        )


class UserAuthLoginView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        identifier = serializer.validated_data['email'].strip()
        password = serializer.validated_data['password']
        if not identifier:
            return Response({'detail': 'Email or username is required.'}, status=status.HTTP_400_BAD_REQUEST)
        normalized = identifier.lower()
        if '@' in normalized:
            user = User.objects.filter(email__iexact=normalized).first()
        else:
            user = User.objects.filter(username__iexact=normalized).first()

        if user is None or not user.password_hash or not check_password(password, user.password_hash):
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
        if user.status != User.Status.ACTIVE:
            return Response({'detail': 'Account is not active.'}, status=status.HTTP_403_FORBIDDEN)

        if UserMfaTotp.objects.filter(user=user, is_enabled=True).exists():
            login_code = _generate_email_otp_code()
            try:
                _send_email_2fa_code(user, code=login_code, reason='login')
            except Exception:
                return Response(
                    {'detail': 'Unable to send verification email.'},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )
            return Response(
                {
                    'ok': True,
                    'mfa_required': True,
                    'mfa_token': _create_login_2fa_token(user, code=login_code),
                    'mfa_delivery': 'email',
                    'mfa_email': _mask_email(user.email),
                    'user': _serialize_user(user),
                }
            )

        user.last_login_at = timezone.now()
        user.save(update_fields=['last_login_at', 'updated_at'])
        session = _create_user_session(user)
        return Response(
            {
                'ok': True,
                'mfa_required': False,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_user(user),
            }
        )


class UserAuthGoogleView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = UserGoogleLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            verified = _verify_google_id_token(serializer.validated_data['id_token'])
        except ValueError as exc:
            return Response({'detail': str(exc) or 'Invalid Google token.'}, status=status.HTTP_401_UNAUTHORIZED)
        except RuntimeError as exc:
            return Response({'detail': str(exc) or 'Google token verification failed.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        email = verified['email']
        user = User.objects.filter(email__iexact=email).first()
        if user is None:
            user = User.objects.create(
                email=email,
                username=_build_unique_username_from_email(email),
                auth_provider=User.AuthProvider.GOOGLE,
                provider_id=verified['sub'],
                is_email_verified=True,
                role=User.Role.USER,
                status=User.Status.ACTIVE,
                last_login_at=timezone.now(),
            )
        else:
            if user.status != User.Status.ACTIVE:
                return Response({'detail': 'Account is not active.'}, status=status.HTTP_403_FORBIDDEN)
            update_fields = ['last_login_at', 'updated_at']
            user.last_login_at = timezone.now()
            if user.auth_provider == User.AuthProvider.GOOGLE and not user.provider_id:
                user.provider_id = verified['sub']
                update_fields.insert(1, 'provider_id')
            user.save(update_fields=update_fields)

        session = _create_user_session(user)
        return Response(
            {
                'ok': True,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_user(user),
            }
        )


class UserAuthRefreshView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = UserRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data['refresh_token']

        session = (
            UserSession.objects.select_related('user')
            .filter(refresh_token=refresh_token, revoked_at__isnull=True)
            .first()
        )
        if session is None or session.refresh_expires_at <= timezone.now():
            return Response({'detail': 'Refresh token is invalid or expired.'}, status=status.HTTP_401_UNAUTHORIZED)
        if session.user.status != User.Status.ACTIVE:
            return Response({'detail': 'Account is not active.'}, status=status.HTTP_403_FORBIDDEN)

        session.access_token = uuid.uuid4().hex + uuid.uuid4().hex
        session.refresh_token = uuid.uuid4().hex + uuid.uuid4().hex
        session.access_expires_at = timezone.now() + timezone.timedelta(minutes=USER_ACCESS_TOKEN_TTL_MINUTES)
        session.refresh_expires_at = timezone.now() + timezone.timedelta(days=USER_REFRESH_TOKEN_TTL_DAYS)
        session.save(update_fields=['access_token', 'refresh_token', 'access_expires_at', 'refresh_expires_at', 'updated_at'])
        return Response(
            {
                'ok': True,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_user(session.user),
            }
        )


class UserAuthLogoutView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)
        session.revoked_at = timezone.now()
        session.save(update_fields=['revoked_at', 'updated_at'])
        return Response({'ok': True})


class UserAuthSessionsRevokeAllView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserSessionsRevokeAllSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        keep_current = serializer.validated_data.get('keep_current', False)

        now = timezone.now()
        sessions_qs = UserSession.objects.filter(user=session.user, revoked_at__isnull=True)
        if keep_current:
            sessions_qs = sessions_qs.exclude(id=session.id)
        revoked_count = sessions_qs.update(revoked_at=now, updated_at=now)

        return Response(
            {
                'ok': True,
                'keep_current': bool(keep_current),
                'revoked_count': int(revoked_count),
            }
        )


class UserAuthMeView(APIView):
    permission_classes = []

    def get(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({'ok': True, 'user': _serialize_user(session.user)})

    def patch(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserProfileUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        requested = serializer.validated_data['username']
        if User.objects.exclude(id=session.user.id).filter(username__iexact=requested).exists():
            return Response({'detail': 'Username is already taken.'}, status=status.HTTP_409_CONFLICT)

        if session.user.username != requested:
            session.user.username = requested
            session.user.save(update_fields=['username', 'updated_at'])

        return Response({'ok': True, 'user': _serialize_user(session.user)})


class UserAuthPasswordChangeView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserPasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = session.user
        if not user.password_hash:
            return Response(
                {'detail': 'Password change is available only for accounts with a password login.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not check_password(serializer.validated_data['current_password'], user.password_hash):
            return Response({'detail': 'Current password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

        now = timezone.now()
        with transaction.atomic():
            user.password_hash = make_password(serializer.validated_data['new_password'])
            user.save(update_fields=['password_hash', 'updated_at'])
            UserSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=now, updated_at=now)
            new_session = _create_user_session(user)

        return Response(
            {
                'ok': True,
                'access_token': new_session.access_token,
                'refresh_token': new_session.refresh_token,
                'access_expires_at': new_session.access_expires_at,
                'refresh_expires_at': new_session.refresh_expires_at,
                'user': _serialize_user(user),
            }
        )


class UserAuthPasswordSetView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserPasswordSetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = session.user
        if user.password_hash:
            return Response(
                {'detail': 'Password is already set for this account.'},
                status=status.HTTP_409_CONFLICT,
            )

        now = timezone.now()
        with transaction.atomic():
            user.password_hash = make_password(serializer.validated_data['new_password'])
            user.save(update_fields=['password_hash', 'updated_at'])
            UserSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=now, updated_at=now)
            new_session = _create_user_session(user)

        return Response(
            {
                'ok': True,
                'access_token': new_session.access_token,
                'refresh_token': new_session.refresh_token,
                'access_expires_at': new_session.access_expires_at,
                'refresh_expires_at': new_session.refresh_expires_at,
                'user': _serialize_user(user),
            }
        )


class UserAuthLogin2FAVerifyView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = UserLogin2FAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user, token_payload = _resolve_login_2fa_token(serializer.validated_data['mfa_token'])
        if user is None or token_payload is None:
            return Response({'detail': 'MFA token is invalid or expired.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not UserMfaTotp.objects.filter(user=user, is_enabled=True).exists():
            return Response({'detail': 'Two-factor authentication is not enabled.'}, status=status.HTTP_400_BAD_REQUEST)

        code = serializer.validated_data['code']
        token_code_hash = (token_payload.get('code_hash') or '').strip()
        email_code_ok = bool(token_code_hash) and _email_otp_matches_hash(token_code_hash, code)
        backup_code_ok = _consume_backup_code(user, code)
        if not email_code_ok and not backup_code_ok:
            return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        user.last_login_at = timezone.now()
        user.save(update_fields=['last_login_at', 'updated_at'])
        session = _create_user_session(user)
        return Response(
            {
                'ok': True,
                'mfa_required': False,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_user(user),
            }
        )


class UserAuth2FATotpSetupView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        user = session.user
        if not user.password_hash:
            return Response(
                {'detail': 'Create a password login before enabling two-factor authentication.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        existing = UserMfaTotp.objects.filter(user=user).first()
        if existing is not None and existing.is_enabled:
            return Response({'detail': 'Two-factor authentication is already enabled.'}, status=status.HTTP_409_CONFLICT)

        setup_code = _generate_email_otp_code()
        setup_code_hash = _hash_email_otp_code(setup_code)
        if existing is None:
            UserMfaTotp.objects.create(
                user=user,
                secret=setup_code_hash,
                is_enabled=False,
                verified_at=None,
            )
        else:
            existing.secret = setup_code_hash
            existing.is_enabled = False
            existing.verified_at = None
            existing.save(update_fields=['secret', 'is_enabled', 'verified_at', 'updated_at'])

        try:
            _send_email_2fa_code(user, code=setup_code, reason='2FA setup')
        except Exception:
            return Response({'detail': 'Unable to send verification email.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        return Response(
            {
                'ok': True,
                'setup': {
                    'delivery': 'email',
                    'email': _mask_email(user.email),
                    'message': 'Verification code sent to your email.',
                },
            }
        )


class UserAuth2FATotpVerifyView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = User2FATotpVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = session.user
        mfa = UserMfaTotp.objects.filter(user=user).first()
        if mfa is None:
            return Response({'detail': 'Two-factor setup has not been started.'}, status=status.HTTP_400_BAD_REQUEST)
        if mfa.is_enabled:
            return Response({'detail': 'Two-factor authentication is already enabled.'}, status=status.HTTP_409_CONFLICT)
        if not _email_otp_matches_hash(mfa.secret, serializer.validated_data['code']):
            return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        now = timezone.now()
        with transaction.atomic():
            mfa.is_enabled = True
            mfa.verified_at = now
            mfa.secret = ''
            mfa.save(update_fields=['is_enabled', 'verified_at', 'secret', 'updated_at'])
            backup_codes = _replace_backup_codes(user)
            UserSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=now, updated_at=now)
            new_session = _create_user_session(user)

        return Response(
            {
                'ok': True,
                'access_token': new_session.access_token,
                'refresh_token': new_session.refresh_token,
                'access_expires_at': new_session.access_expires_at,
                'refresh_expires_at': new_session.refresh_expires_at,
                'user': _serialize_user(user),
                'backup_codes': backup_codes,
            }
        )


class UserAuth2FATotpDisableView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = User2FATotpDisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = session.user
        mfa = UserMfaTotp.objects.filter(user=user, is_enabled=True).first()
        if mfa is None:
            return Response({'detail': 'Two-factor authentication is not enabled.'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.password_hash or not check_password(serializer.validated_data['current_password'], user.password_hash):
            return Response({'detail': 'Current password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
        if not _verify_user_2fa_code(user, serializer.validated_data['code']):
            return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        now = timezone.now()
        with transaction.atomic():
            mfa.is_enabled = False
            mfa.verified_at = None
            mfa.secret = ''
            mfa.save(update_fields=['is_enabled', 'verified_at', 'secret', 'updated_at'])
            UserMfaBackupCode.objects.filter(user=user).delete()
            UserSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=now, updated_at=now)
            new_session = _create_user_session(user)

        return Response(
            {
                'ok': True,
                'access_token': new_session.access_token,
                'refresh_token': new_session.refresh_token,
                'access_expires_at': new_session.access_expires_at,
                'refresh_expires_at': new_session.refresh_expires_at,
                'user': _serialize_user(user),
            }
        )


class UserAuth2FABackupCodesRegenerateView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = User2FABackupCodesRegenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = session.user
        mfa = UserMfaTotp.objects.filter(user=user, is_enabled=True).first()
        if mfa is None:
            return Response({'detail': 'Two-factor authentication is not enabled.'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.password_hash or not check_password(serializer.validated_data['current_password'], user.password_hash):
            return Response({'detail': 'Current password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
        if not _verify_user_2fa_code(user, serializer.validated_data['code']):
            return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        backup_codes = _replace_backup_codes(user)
        return Response(
            {
                'ok': True,
                'backup_codes': backup_codes,
            }
        )


class UserAuthSettingsView(APIView):
    permission_classes = []

    def get(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)
        settings_obj = _get_or_create_user_settings(session.user)
        return Response({'ok': True, 'settings': _serialize_user_settings(settings_obj)})

    def patch(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserSettingsUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        if not serializer.validated_data:
            return Response({'detail': 'No settings provided.'}, status=status.HTTP_400_BAD_REQUEST)

        settings_obj = _get_or_create_user_settings(session.user)
        for field_name, value in serializer.validated_data.items():
            setattr(settings_obj, field_name, value)
        settings_obj.save(update_fields=[*serializer.validated_data.keys(), 'updated_at'])

        return Response({'ok': True, 'settings': _serialize_user_settings(settings_obj)})


class UserAuthNotificationsView(APIView):
    permission_classes = []

    @staticmethod
    def _wants_unread_only(request):
        raw = (request.query_params.get('unread_only') or '').strip().lower()
        return raw in {'1', 'true', 'yes', 'on'}

    def get(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        limit, offset = _parse_limit_offset(request, default_limit=30, max_limit=100)
        unread_only = self._wants_unread_only(request)

        base_queryset = UserNotification.objects.filter(user=session.user).order_by('-created_at')
        if not base_queryset.exists() and offset == 0 and not unread_only:
            UserNotification.objects.create(
                user=session.user,
                notification_type=UserNotification.Type.SYSTEM,
                title='Welcome to SeerahPod',
                message='Your notifications will appear here as new activity happens.',
            )
            base_queryset = UserNotification.objects.filter(user=session.user).order_by('-created_at')

        unread_count = base_queryset.filter(read_at__isnull=True).count()
        scoped_queryset = base_queryset.filter(read_at__isnull=True) if unread_only else base_queryset
        total_count = scoped_queryset.count()
        notifications = scoped_queryset[offset:offset + limit]

        results = [_serialize_user_notification(row) for row in notifications]
        count = len(results)
        next_offset = offset + count
        has_more = next_offset < total_count

        return Response(
            {
                'ok': True,
                'count': count,
                'total_count': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': has_more,
                'next_offset': next_offset if has_more else None,
                'unread_count': unread_count,
                'results': results,
            }
        )


class UserAuthNotificationDetailView(APIView):
    permission_classes = []

    def _get_notification_for_user(self, user, notification_id):
        return UserNotification.objects.filter(id=notification_id, user=user).first()

    def get(self, request, id):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        row = self._get_notification_for_user(session.user, id)
        if row is None:
            return Response({'detail': 'Notification not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'ok': True, 'notification': _serialize_user_notification(row)})

    def patch(self, request, id):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        row = self._get_notification_for_user(session.user, id)
        if row is None:
            return Response({'detail': 'Notification not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserNotificationUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        if not serializer.validated_data:
            return Response({'detail': 'No notification updates provided.'}, status=status.HTTP_400_BAD_REQUEST)

        if 'is_read' in serializer.validated_data:
            row.read_at = timezone.now() if serializer.validated_data['is_read'] else None
            row.save(update_fields=['read_at'])

        return Response({'ok': True, 'notification': _serialize_user_notification(row)})


class UserAuthNotificationsMarkAllReadView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        now = timezone.now()
        updated_count = (
            UserNotification.objects.filter(user=session.user, read_at__isnull=True)
            .update(read_at=now)
        )
        return Response({'ok': True, 'updated_count': int(updated_count)})


class UserTrackLikeView(APIView):
    permission_classes = []

    def _get_playable_track(self, track_id):
        return (
            Track.objects.filter(
                id=track_id,
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q())
            .first()
        )

    def get(self, request, id, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        track = self._get_playable_track(id)
        if track is None:
            return Response({'detail': 'Track not found.'}, status=status.HTTP_404_NOT_FOUND)

        is_liked = UserTrackLike.objects.filter(user=session.user, track=track).exists()
        return Response(
            {
                'ok': True,
                'track_id': str(track.id),
                'is_liked': bool(is_liked),
            }
        )

    def post(self, request, id, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        track = self._get_playable_track(id)
        if track is None:
            return Response({'detail': 'Track not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserTrackLikeUpdateSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        is_liked = serializer.validated_data['is_liked']

        if is_liked:
            _, created = UserTrackLike.objects.get_or_create(
                user=session.user,
                track=track,
            )
        else:
            UserTrackLike.objects.filter(
                user=session.user,
                track=track,
            ).delete()
            created = False

        return Response(
            {
                'ok': True,
                'track_id': str(track.id),
                'is_liked': bool(is_liked),
                'created': bool(created),
            }
        )


def _parse_support_datetime(raw_value: str | None):
    value = (raw_value or '').strip()
    if not value:
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _active_support_ticket_for_user(user: User):
    return (
        SupportTicket.objects.select_related('user', 'assigned_admin')
        .filter(user=user, status__in=[SupportTicket.Status.OPEN, SupportTicket.Status.IN_PROGRESS])
        .order_by('-updated_at', '-created_at')
        .first()
    )


class UserSupportTicketOpenView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        ticket = _active_support_ticket_for_user(session.user)
        created = False
        if ticket is None:
            ticket = SupportTicket.objects.create(
                user=session.user,
                subject='Support chat',
                status=SupportTicket.Status.OPEN,
                priority=SupportTicket.Priority.MEDIUM,
            )
            created = True
        return Response(
            {'ok': True, 'created': created, 'ticket': _serialize_support_ticket(ticket)},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class UserSupportTicketActiveView(APIView):
    permission_classes = []

    def get(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        ticket = _active_support_ticket_for_user(session.user)
        if ticket is None:
            ticket = (
                SupportTicket.objects.select_related('user', 'assigned_admin')
                .filter(user=session.user)
                .order_by('-updated_at', '-created_at')
                .first()
            )
        return Response({'ok': True, 'ticket': _serialize_support_ticket(ticket) if ticket else None})


class UserSupportTicketMessagesView(APIView):
    permission_classes = []

    def _get_user_ticket(self, *, user, ticket_id):
        return (
            SupportTicket.objects.select_related('user', 'assigned_admin')
            .filter(id=ticket_id, user=user)
            .first()
        )

    def get(self, request, id, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        ticket = self._get_user_ticket(user=session.user, ticket_id=id)
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)

        limit, offset = _parse_limit_offset(request, default_limit=30, max_limit=200)
        before = _parse_support_datetime(request.query_params.get('before'))
        since = _parse_support_datetime(request.query_params.get('since'))

        queryset = (
            SupportMessage.objects.select_related('sender_user')
            .filter(ticket=ticket)
            .order_by('created_at', 'id')
        )
        if before is not None:
            queryset = queryset.filter(created_at__lt=before)
        if since is not None:
            queryset = queryset.filter(created_at__gt=since)

        total_count = queryset.count()
        rows = queryset[offset:offset + limit]
        results = [_serialize_support_message(row) for row in rows]
        count = len(results)
        next_offset = offset + count

        return Response(
            {
                'ok': True,
                'ticket': _serialize_support_ticket(ticket),
                'count': count,
                'total_count': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': next_offset < total_count,
                'next_offset': next_offset if next_offset < total_count else None,
                'results': results,
            }
        )

    def post(self, request, id, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        ticket = self._get_user_ticket(user=session.user, ticket_id=id)
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)
        if ticket.status == SupportTicket.Status.CLOSED:
            return Response(
                {
                    'detail': 'Ticket is closed.',
                    'code': 'ticket_closed',
                    'next_action': 'open_new_ticket',
                },
                status=status.HTTP_409_CONFLICT,
            )

        serializer = SupportMessageSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message_text = serializer.validated_data['message']
        client_message_id = serializer.validated_data.get('client_message_id')

        created = True
        with transaction.atomic():
            existing = None
            if client_message_id:
                existing = (
                    SupportMessage.objects.select_related('sender_user')
                    .filter(ticket=ticket, client_message_id=client_message_id)
                    .first()
                )
            if existing is not None:
                created = False
                message_row = existing
            else:
                try:
                    message_row = SupportMessage.objects.create(
                        ticket=ticket,
                        sender_type=SupportMessage.SenderType.USER,
                        sender_user=session.user,
                        message=message_text,
                        client_message_id=client_message_id,
                    )
                except IntegrityError:
                    if not client_message_id:
                        raise
                    message_row = (
                        SupportMessage.objects.select_related('sender_user')
                        .filter(ticket=ticket, client_message_id=client_message_id)
                        .first()
                    )
                    if message_row is None:
                        raise
                    created = False

            if created:
                SupportTicket.objects.filter(id=ticket.id).update(
                    last_message_at=message_row.created_at,
                    admin_unread_count=F('admin_unread_count') + 1,
                    updated_at=timezone.now(),
                )

        ticket.refresh_from_db()
        return Response(
            {
                'ok': True,
                'created': created,
                'ticket': _serialize_support_ticket(ticket),
                'message': _serialize_support_message(message_row),
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class UserSupportTicketReadView(APIView):
    permission_classes = []

    def post(self, request, id, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        ticket = SupportTicket.objects.filter(id=id, user=session.user).first()
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)

        ticket.user_unread_count = 0
        ticket.save(update_fields=['user_unread_count', 'updated_at'])
        return Response({'ok': True, 'ticket': _serialize_support_ticket(ticket)})


class UserSupportSummaryView(APIView):
    permission_classes = []

    def get(self, request, **kwargs):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        active_ticket = _active_support_ticket_for_user(session.user)
        unread_totals = SupportTicket.objects.filter(user=session.user).aggregate(
            unread=Sum('user_unread_count')
        )
        unread_message_count = int(unread_totals.get('unread') or 0)
        return Response(
            {
                'ok': True,
                'active_ticket_id': str(active_ticket.id) if active_ticket else None,
                'unread_message_count': unread_message_count,
                'has_unread': unread_message_count > 0,
            }
        )


class RecommendationTrackSerializer(serializers.ModelSerializer):
    category = serializers.SerializerMethodField()
    cover_image_urls = serializers.SerializerMethodField()

    def get_category(self, obj):
        if obj.category is None:
            return None
        return {'id': str(obj.category.id), 'name': obj.category.name}

    def get_cover_image_urls(self, obj):
        return _track_cover_image_urls(obj)

    class Meta:
        model = Track
        fields = [
            'id',
            'title',
            'speaker_name',
            'audio_url',
            'video_url',
            'duration_seconds',
            'cover_image_url',
            'cover_image_urls',
            'category',
            'created_at',
        ]


class PlaylistSummarySerializer(serializers.ModelSerializer):
    track_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Playlist
        fields = [
            'id',
            'title',
            'description',
            'cover_image_url',
            'visibility',
            'is_active',
            'track_count',
            'created_at',
        ]


class RecommendationsFeedView(APIView):
    def _parse_days_and_limit(self, rule, default_days):
        config = rule.config or {}
        days = config.get('days', default_days)
        limit = config.get('limit', 10)

        try:
            days = max(int(days), 1)
        except (TypeError, ValueError):
            days = default_days

        try:
            limit = max(int(limit), 1)
        except (TypeError, ValueError):
            limit = 10

        return days, limit

    def _recently_added_tracks(self, rule):
        days, limit = self._parse_days_and_limit(rule, default_days=2)

        cutoff = timezone.now() - timezone.timedelta(days=days)
        queryset = (
            Track.objects.filter(
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
                created_at__gte=cutoff,
            )
            .filter(_playable_track_q())
            .select_related('category').prefetch_related('cover_images')
            .order_by('-created_at')[:limit]
        )
        return list(queryset)

    def _top_played_tracks(self, rule):
        days, limit = self._parse_days_and_limit(rule, default_days=7)
        cutoff = timezone.now() - timezone.timedelta(days=days)

        ranked = list(
            PlayEvent.objects.filter(
                created_at__gte=cutoff,
                track__deleted_at__isnull=True,
                track__status=Track.Status.PUBLISHED,
                track__visibility=Track.Visibility.PUBLIC,
            )
            .values('track_id')
            .annotate(
                play_count=Count('id'),
                total_played_seconds=Sum('played_seconds'),
            )
            .order_by('-play_count', '-total_played_seconds')[:limit]
        )
        ranked_track_ids = [row['track_id'] for row in ranked]
        if not ranked_track_ids:
            return []

        preserved_order = Case(
            *[When(id=track_id, then=position) for position, track_id in enumerate(ranked_track_ids)],
            output_field=IntegerField(),
        )
        tracks = (
            Track.objects.filter(id__in=ranked_track_ids)
            .select_related('category').prefetch_related('cover_images')
            .order_by(preserved_order)
        )
        return list(tracks)

    def _based_on_history_tracks(self, rule, user_id):
        if not user_id:
            return []
        try:
            user_uuid = uuid.UUID(user_id)
        except (ValueError, TypeError, AttributeError):
            return []

        config = rule.config or {}
        days = config.get('days', 30)
        min_listens = config.get('min_listens', 3)
        limit = config.get('limit', 10)
        top_categories = config.get('top_categories', 3)

        try:
            days = max(int(days), 1)
        except (TypeError, ValueError):
            days = 30

        try:
            min_listens = max(int(min_listens), 1)
        except (TypeError, ValueError):
            min_listens = 3

        try:
            limit = max(int(limit), 1)
        except (TypeError, ValueError):
            limit = 10

        try:
            top_categories = max(int(top_categories), 1)
        except (TypeError, ValueError):
            top_categories = 3

        cutoff = timezone.now() - timezone.timedelta(days=days)
        user_events = PlayEvent.objects.filter(
            user_id=user_uuid,
            created_at__gte=cutoff,
            track__deleted_at__isnull=True,
            track__status=Track.Status.PUBLISHED,
            track__visibility=Track.Visibility.PUBLIC,
        )

        if user_events.count() < min_listens:
            return []

        category_rows = list(
            user_events.filter(track__category__isnull=False)
            .values('track__category_id')
            .annotate(
                affinity_seconds=Sum('played_seconds'),
                listens=Count('id'),
            )
            .order_by('-affinity_seconds', '-listens')[:top_categories]
        )
        category_ids = [row['track__category_id'] for row in category_rows]
        if not category_ids:
            return []

        category_rank = Case(
            *[When(category_id=category_id, then=position) for position, category_id in enumerate(category_ids)],
            output_field=IntegerField(),
        )

        tracks = (
            Track.objects.filter(
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
                category_id__in=category_ids,
            )
            .filter(_playable_track_q())
            .annotate(
                category_rank=category_rank,
                global_play_count=Count('playevent', filter=Q(playevent__created_at__gte=cutoff)),
                global_play_seconds=Sum('playevent__played_seconds', filter=Q(playevent__created_at__gte=cutoff)),
            )
            .select_related('category').prefetch_related('cover_images')
            .order_by('category_rank', '-global_play_count', '-global_play_seconds', '-created_at')[:limit]
        )
        return list(tracks)

    def get(self, request):
        user_id = request.query_params.get('user_id')
        active_rules = RecommendationRule.objects.filter(is_active=True).order_by('priority', 'created_at')
        sections = []

        for rule in active_rules:
            if rule.rule_key == 'top_played':
                tracks = self._top_played_tracks(rule)
            elif rule.rule_key == 'recently_added':
                tracks = self._recently_added_tracks(rule)
            elif rule.rule_key == 'based_on_history':
                tracks = self._based_on_history_tracks(rule, user_id)
            else:
                continue

            sections.append(
                {
                    'rule_id': str(rule.id),
                    'rule_key': rule.rule_key,
                    'name': rule.name,
                    'description': rule.description,
                    'priority': rule.priority,
                    'tracks': RecommendationTrackSerializer(tracks, many=True).data,
                    'track_count': len(tracks),
                }
            )

        return Response({'ok': True, 'count': len(sections), 'results': sections})


class TrendingPodcastsView(APIView):
    def get(self, request):
        days = request.query_params.get('days', 30)
        limit = request.query_params.get('limit', 10)
        try:
            days = max(int(days), 1)
        except (TypeError, ValueError):
            days = 30
        try:
            limit = max(int(limit), 1)
        except (TypeError, ValueError):
            limit = 10

        cutoff = timezone.now() - timezone.timedelta(days=days)
        podcast_name_filter = Q(track__category__name__iexact='podcast') | Q(track__category__name__icontains='podcast')

        ranked_rows = list(
            PlayEvent.objects.filter(
                created_at__gte=cutoff,
                track__deleted_at__isnull=True,
                track__status=Track.Status.PUBLISHED,
                track__visibility=Track.Visibility.PUBLIC,
            )
            .filter(podcast_name_filter)
            .values(
                'track_id',
                'track__title',
                'track__speaker_name',
                'track__cover_image_url',
                'track__duration_seconds',
            )
            .annotate(
                play_count=Count('id'),
                total_played_seconds=Sum('played_seconds'),
            )
            .order_by('-play_count', '-total_played_seconds', '-track__title')[:limit]
        )

        results = [
            {
                'id': str(row['track_id']),
                'title': row['track__title'],
                'speaker_name': row['track__speaker_name'],
                'cover_image_url': row['track__cover_image_url'],
                'duration_seconds': row['track__duration_seconds'],
                'plays': row['play_count'],
            }
            for row in ranked_rows
        ]

        if not results:
            fallback_tracks = (
                Track.objects.filter(
                    deleted_at__isnull=True,
                    status=Track.Status.PUBLISHED,
                    visibility=Track.Visibility.PUBLIC,
                )
                .filter(Q(category__name__iexact='podcast') | Q(category__name__icontains='podcast'))
                .select_related('category').prefetch_related('cover_images')
                .order_by('-created_at')[:limit]
            )
            results = [
                {
                    'id': str(track.id),
                    'title': track.title,
                    'speaker_name': track.speaker_name,
                    'cover_image_url': track.cover_image_url,
                    'cover_image_urls': _track_cover_image_urls(track),
                    'duration_seconds': track.duration_seconds,
                    'plays': 0,
                }
                for track in fallback_tracks
            ]

        return Response(
            {
                'ok': True,
                'days': days,
                'count': len(results),
                'results': results,
            }
        )


class PlayEventCreateView(APIView):
    permission_classes = []

    def post(self, request):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = PlayEventCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data

        track = (
            Track.objects.filter(
                id=payload['track_id'],
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q())
            .first()
        )
        if track is None:
            return Response({'detail': 'Track not found.'}, status=status.HTTP_404_NOT_FOUND)

        fallback_duration = track.duration_seconds if (track.duration_seconds or 0) > 0 else 1
        total_duration = payload.get('total_duration') or fallback_duration
        if total_duration <= 0:
            total_duration = fallback_duration

        played_seconds = payload.get('played_seconds', 0)
        if played_seconds < 0:
            played_seconds = 0
        if played_seconds > total_duration:
            played_seconds = total_duration

        completion_percentage = payload.get('completion_percentage')
        if completion_percentage is None:
            completion_percentage = (played_seconds / total_duration) * 100 if total_duration > 0 else 0.0
        completion_percentage = max(min(float(completion_percentage), 100.0), 0.0)

        source = payload.get('source') or PlayEvent.Source.HOME
        device_platform = payload.get('device_platform') or _resolve_search_device_platform(request)

        event = PlayEvent.objects.create(
            user=session.user,
            track=track,
            played_seconds=int(played_seconds),
            total_duration=int(total_duration),
            completion_percentage=completion_percentage,
            source=source,
            device_platform=device_platform,
        )

        return Response(
            {
                'ok': True,
                'event': {
                    'id': str(event.id),
                    'track_id': str(track.id),
                    'played_seconds': event.played_seconds,
                    'total_duration': event.total_duration,
                    'completion_percentage': round(float(event.completion_percentage), 1),
                    'source': event.source,
                    'device_platform': event.device_platform,
                    'created_at': event.created_at,
                },
            },
            status=status.HTTP_201_CREATED,
        )


class HomeContinueListeningView(APIView):
    permission_classes = []

    def get(self, request):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        limit = request.query_params.get('limit', 5)
        try:
            limit = max(min(int(limit), 20), 1)
        except (TypeError, ValueError):
            limit = 5

        min_progress = request.query_params.get('min_progress', 5)
        max_progress = request.query_params.get('max_progress', 95)
        try:
            min_progress = max(min(float(min_progress), 100.0), 0.0)
        except (TypeError, ValueError):
            min_progress = 5.0
        try:
            max_progress = max(min(float(max_progress), 100.0), 0.0)
        except (TypeError, ValueError):
            max_progress = 95.0
        if min_progress > max_progress:
            min_progress, max_progress = max_progress, min_progress

        events = (
            PlayEvent.objects.filter(
                user=session.user,
                track__deleted_at__isnull=True,
                track__status=Track.Status.PUBLISHED,
                track__visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q('track__'))
            .select_related('track').prefetch_related('track__cover_images')
            .order_by('-created_at')
        )

        seen_track_ids = set()
        results = []
        for event in events:
            if event.track_id in seen_track_ids:
                continue
            seen_track_ids.add(event.track_id)

            track = event.track
            total_duration = int(event.total_duration or 0)
            if total_duration <= 0:
                total_duration = int(track.duration_seconds or 0)
            if total_duration <= 0:
                total_duration = 1

            played_seconds = int(event.played_seconds or 0)
            if played_seconds < 0:
                played_seconds = 0
            if played_seconds > total_duration:
                played_seconds = total_duration

            progress_percent = float(event.completion_percentage or 0)
            if progress_percent <= 0 and total_duration > 0:
                progress_percent = (played_seconds / total_duration) * 100
            if progress_percent < 0:
                progress_percent = 0.0
            if progress_percent > 100:
                progress_percent = 100.0

            if progress_percent < min_progress:
                continue
            if progress_percent >= max_progress:
                continue

            results.append(
                {
                    'id': str(track.id),
                    'title': track.title,
                    'speaker_name': track.speaker_name,
                    'cover_image_url': track.cover_image_url,
                    'cover_image_urls': _track_cover_image_urls(track),
                    'audio_url': track.audio_url,
                    'video_url': track.video_url,
                    'duration_seconds': track.duration_seconds,
                    'played_seconds': played_seconds,
                    'progress_percent': round(progress_percent, 1),
                    'last_played_at': event.created_at,
                }
            )
            if len(results) >= limit:
                break

        return Response(
            {
                'ok': True,
                'count': len(results),
                'results': results,
            }
        )


class HomeRecentlyPlayedView(APIView):
    permission_classes = []

    def get(self, request):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        limit = request.query_params.get('limit', 20)
        try:
            limit = max(min(int(limit), 50), 1)
        except (TypeError, ValueError):
            limit = 20

        events = (
            PlayEvent.objects.filter(
                user=session.user,
                track__deleted_at__isnull=True,
                track__status=Track.Status.PUBLISHED,
                track__visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q('track__'))
            .select_related('track').prefetch_related('track__cover_images')
            .order_by('-created_at')
        )

        seen_track_ids = set()
        results = []
        for event in events:
            if event.track_id in seen_track_ids:
                continue
            seen_track_ids.add(event.track_id)
            track = event.track
            progress_percent = float(event.completion_percentage or 0)
            if progress_percent < 0:
                progress_percent = 0.0
            if progress_percent > 100:
                progress_percent = 100.0
            results.append(
                {
                    'id': str(track.id),
                    'title': track.title,
                    'speaker_name': track.speaker_name,
                    'cover_image_url': track.cover_image_url,
                    'cover_image_urls': _track_cover_image_urls(track),
                    'audio_url': track.audio_url,
                    'video_url': track.video_url,
                    'duration_seconds': track.duration_seconds,
                    'progress_percent': round(progress_percent, 1),
                    'last_played_at': event.created_at,
                }
            )
            if len(results) >= limit:
                break

        return Response(
            {
                'ok': True,
                'count': len(results),
                'results': results,
            }
        )


def _playlist_preview_cover_urls(playlist_id, *, limit=4):
    rows = (
        PlaylistTrack.objects.filter(
            playlist_id=playlist_id,
            track__deleted_at__isnull=True,
            track__status=Track.Status.PUBLISHED,
            track__visibility=Track.Visibility.PUBLIC,
        )
        .filter(_playable_track_q('track__'))
        .exclude(track__cover_image_url__isnull=True)
        .exclude(track__cover_image_url__exact='')
        .select_related('track').prefetch_related('track__cover_images')
        .order_by('position', 'created_at')[:limit]
    )
    return [row.track.cover_image_url for row in rows]


def _liked_tracks_queryset_for_user(user):
    return (
        UserTrackLike.objects.filter(
            user=user,
            track__deleted_at__isnull=True,
            track__status=Track.Status.PUBLISHED,
            track__visibility=Track.Visibility.PUBLIC,
        )
        .filter(_playable_track_q('track__'))
        .select_related('track')
        .prefetch_related('track__cover_images')
        .order_by('-created_at')
    )


def _serialize_liked_songs_playlist_summary(*, user):
    liked_rows = list(_liked_tracks_queryset_for_user(user)[:4])
    preview_cover_image_urls = []
    for row in liked_rows:
        for cover in _track_cover_image_urls(row.track):
            if cover and cover not in preview_cover_image_urls:
                preview_cover_image_urls.append(cover)
            if len(preview_cover_image_urls) >= 4:
                break
        if len(preview_cover_image_urls) >= 4:
            break

    track_count = _liked_tracks_queryset_for_user(user).count()
    primary_cover = preview_cover_image_urls[0] if preview_cover_image_urls else None
    return {
        'id': str(LIKED_SONGS_PLAYLIST_ID),
        'title': 'Liked Songs',
        'description': 'Songs you liked',
        'cover_image_url': primary_cover,
        'visibility': 'private',
        'track_count': int(track_count),
        'click_count': int(track_count),
        'created_at': user.created_at,
        'preview_cover_image_urls': preview_cover_image_urls,
    }


def _active_public_playlists_queryset():
    return (
        Playlist.objects.filter(
            deleted_at__isnull=True,
            is_active=True,
        )
        .exclude(visibility=Playlist.Visibility.HIDDEN)
        .annotate(
            track_count=Count(
                'playlisttrack',
                filter=Q(
                    playlisttrack__track__deleted_at__isnull=True,
                    playlisttrack__track__status=Track.Status.PUBLISHED,
                    playlisttrack__track__visibility=Track.Visibility.PUBLIC,
                ) & _playable_track_q('playlisttrack__track__'),
            )
        )
    )


class PlaylistsListView(APIView):
    permission_classes = []

    def get(self, request):
        limit, offset = _parse_limit_offset(request, default_limit=300, max_limit=500)
        query = (request.query_params.get('q') or '').strip()
        base_queryset = _active_public_playlists_queryset()
        if query:
            base_queryset = base_queryset.filter(
                Q(title__icontains=query) | Q(description__icontains=query)
            )
        base_queryset = base_queryset.order_by('-created_at')
        total_count = base_queryset.count()
        playlists = base_queryset[offset:offset + limit]
        serialized = PlaylistSummarySerializer(playlists, many=True).data
        for row, playlist in zip(serialized, playlists):
            row['preview_cover_image_urls'] = _playlist_preview_cover_urls(playlist.id)

        count = len(serialized)
        next_offset = offset + count
        has_more = next_offset < total_count
        return Response(
            {
                'ok': True,
                'count': count,
                'total_count': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': has_more,
                'next_offset': next_offset if has_more else None,
                'results': serialized,
            }
        )


class TopPlaylistsView(APIView):
    permission_classes = []

    def get(self, request):
        session = _get_active_user_session_from_request(request)
        limit = request.query_params.get('limit', 20)
        window_days = request.query_params.get('window_days', 30)
        try:
            limit = max(min(int(limit), 100), 1)
        except (TypeError, ValueError):
            limit = 20
        try:
            window_days = max(min(int(window_days), 365), 1)
        except (TypeError, ValueError):
            window_days = 30

        include_liked_songs = session is not None
        db_limit = max(limit - 1, 0) if include_liked_songs else limit

        cutoff = timezone.now() - timezone.timedelta(days=window_days)
        playlists = []
        if db_limit > 0:
            playlists = list(
                _active_public_playlists_queryset()
                .annotate(
                    click_count=Count(
                        'click_events',
                        filter=Q(click_events__created_at__gte=cutoff),
                    ),
                    last_clicked_at=Max(
                        'click_events__created_at',
                        filter=Q(click_events__created_at__gte=cutoff),
                    ),
                )
                .filter(click_count__gt=0)
                .order_by('-click_count', '-last_clicked_at', '-created_at')[:db_limit]
            )

        serialized = PlaylistSummarySerializer(playlists, many=True).data
        for row, playlist in zip(serialized, playlists):
            row['preview_cover_image_urls'] = _playlist_preview_cover_urls(playlist.id)
            row['click_count'] = int(getattr(playlist, 'click_count', 0) or 0)

        results = list(serialized)
        if include_liked_songs:
            liked_row = _serialize_liked_songs_playlist_summary(user=session.user)
            results = [liked_row, *results]
            if len(results) > limit:
                results = results[:limit]

        return Response(
            {
                'ok': True,
                'window_days': window_days,
                'count': len(results),
                'results': results,
            }
        )


class PlaylistClickCreateView(APIView):
    permission_classes = []

    def post(self, request, id):
        playlist = (
            Playlist.objects.filter(
                id=id,
                deleted_at__isnull=True,
                is_active=True,
            )
            .exclude(visibility=Playlist.Visibility.HIDDEN)
            .first()
        )
        if playlist is None:
            return Response({'detail': 'Playlist not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = PlaylistClickCreateSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        session = _get_active_user_session_from_request(request)

        event = PlaylistClickEvent.objects.create(
            playlist=playlist,
            user=session.user if session else None,
            source=payload.get('source') or _resolve_playlist_click_source(request),
            device_platform=payload.get('device_platform') or _resolve_playlist_click_device_platform(request),
        )
        return Response(
            {
                'ok': True,
                'event': {
                    'id': str(event.id),
                    'playlist_id': str(playlist.id),
                    'source': event.source,
                    'device_platform': event.device_platform,
                    'created_at': event.created_at,
                },
            },
            status=status.HTTP_201_CREATED,
        )


class PlaylistTracksView(APIView):
    permission_classes = []

    def _get_playlist(self, playlist_id):
        return _active_public_playlists_queryset().filter(id=playlist_id).first()

    def _serialize_track_row(self, *, track, position):
        return {
            'id': str(track.id),
            'title': track.title,
            'speaker_name': track.speaker_name,
            'audio_url': track.audio_url,
            'video_url': track.video_url,
            'duration_seconds': track.duration_seconds,
            'cover_image_url': track.cover_image_url,
            'cover_image_urls': _track_cover_image_urls(track),
            'position': position,
        }

    def _liked_songs_response(self, *, request):
        session = _get_active_user_session_from_request(request)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)

        liked_rows = list(_liked_tracks_queryset_for_user(session.user))
        serialized_tracks = [
            self._serialize_track_row(track=row.track, position=index)
            for index, row in enumerate(liked_rows, start=1)
        ]
        liked_summary = _serialize_liked_songs_playlist_summary(user=session.user)

        return Response(
            {
                'ok': True,
                'playlist': {
                    'id': liked_summary['id'],
                    'title': liked_summary['title'],
                    'description': liked_summary['description'],
                    'cover_image_url': liked_summary['cover_image_url'],
                    'visibility': liked_summary['visibility'],
                    'track_count': int(liked_summary.get('track_count') or 0),
                    'preview_cover_image_urls': liked_summary.get('preview_cover_image_urls') or [],
                    'created_at': liked_summary['created_at'],
                },
                'count': len(serialized_tracks),
                'results': serialized_tracks,
            }
        )

    def get(self, request, id):
        if id == LIKED_SONGS_PLAYLIST_ID:
            return self._liked_songs_response(request=request)

        playlist = self._get_playlist(id)
        if playlist is None:
            return Response({'detail': 'Playlist not found.'}, status=status.HTTP_404_NOT_FOUND)

        tracks = (
            PlaylistTrack.objects.filter(
                playlist_id=playlist.id,
                track__deleted_at__isnull=True,
                track__status=Track.Status.PUBLISHED,
                track__visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q('track__'))
            .select_related('track').prefetch_related('track__cover_images')
            .order_by('position', 'created_at')
        )

        serialized_tracks = [
            self._serialize_track_row(track=row.track, position=row.position)
            for row in tracks
        ]

        preview_cover_image_urls = []
        for row in serialized_tracks:
            cover = (row.get('cover_image_url') or '').strip()
            if cover:
                preview_cover_image_urls.append(cover)
            if len(preview_cover_image_urls) >= 4:
                break

        return Response(
            {
                'ok': True,
                'playlist': {
                    'id': str(playlist.id),
                    'title': playlist.title,
                    'description': playlist.description,
                    'cover_image_url': playlist.cover_image_url,
                    'visibility': playlist.visibility,
                    'track_count': int(playlist.track_count or 0),
                    'preview_cover_image_urls': preview_cover_image_urls,
                    'created_at': playlist.created_at,
                },
                'count': len(serialized_tracks),
                'results': serialized_tracks,
            }
        )


class LibraryPodcastsTracksView(APIView):
    permission_classes = []

    def get(self, request):
        limit, offset = _parse_limit_offset(request, default_limit=30, max_limit=200)
        base_queryset = (
            Track.objects.filter(
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
                category__name__iexact='podcast',
            )
            .filter(_playable_track_q())
        )
        total_count = base_queryset.count()
        tracks = (
            base_queryset.select_related('category').prefetch_related('cover_images')
            .order_by('-created_at')[offset:offset + limit]
        )
        serialized = RecommendationTrackSerializer(tracks, many=True).data
        count = len(serialized)
        next_offset = offset + count
        has_more = next_offset < total_count
        return Response(
            {
                'ok': True,
                'count': count,
                'total_count': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': has_more,
                'next_offset': next_offset if has_more else None,
                'results': serialized,
            }
        )


class LibrarySongsTracksView(APIView):
    permission_classes = []

    def get(self, request):
        limit, offset = _parse_limit_offset(request, default_limit=30, max_limit=200)
        base_queryset = (
            Track.objects.filter(
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q())
            .exclude(category__name__iexact='podcast')
        )
        total_count = base_queryset.count()
        tracks = (
            base_queryset.select_related('category').prefetch_related('cover_images')
            .order_by('-created_at')[offset:offset + limit]
        )
        serialized = RecommendationTrackSerializer(tracks, many=True).data
        count = len(serialized)
        next_offset = offset + count
        has_more = next_offset < total_count
        return Response(
            {
                'ok': True,
                'count': count,
                'total_count': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': has_more,
                'next_offset': next_offset if has_more else None,
                'results': serialized,
            }
        )


class SearchTracksView(APIView):
    permission_classes = []

    def get(self, request):
        query = (request.query_params.get('q') or '').strip()
        limit = request.query_params.get('limit', 20)
        try:
            limit = max(min(int(limit), 50), 1)
        except (TypeError, ValueError):
            limit = 20

        if not query:
            return Response(
                {
                    'ok': True,
                    'query': '',
                    'count': 0,
                    'results': [],
                }
            )

        tracks = (
            Track.objects.filter(
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q())
            .filter(
                Q(title__icontains=query)
                | Q(speaker_name__icontains=query)
                | Q(category__name__icontains=query)
            )
            .select_related('category').prefetch_related('cover_images')
            .order_by('-created_at')[:limit]
        )

        serialized = RecommendationTrackSerializer(tracks, many=True).data
        _log_search_query(request, query=query, result_count=len(serialized))
        return Response(
            {
                'ok': True,
                'query': query,
                'count': len(serialized),
                'results': serialized,
            }
        )


class SearchSuggestionsView(APIView):
    permission_classes = []

    def get(self, request):
        min_count = request.query_params.get('min_count', 100)
        limit = request.query_params.get('limit', 12)
        try:
            min_count = max(int(min_count), 1)
        except (TypeError, ValueError):
            min_count = 100
        try:
            limit = max(min(int(limit), 30), 1)
        except (TypeError, ValueError):
            limit = 12

        ranked = (
            SearchLog.objects.exclude(normalized_query__isnull=True)
            .exclude(normalized_query__exact='')
            .values('normalized_query')
            .annotate(search_count=Count('id'))
            .filter(search_count__gt=min_count)
            .order_by('-search_count', 'normalized_query')[:limit]
        )

        results = [
            {
                'query': row['normalized_query'],
                'search_count': row['search_count'],
            }
            for row in ranked
        ]

        return Response(
            {
                'ok': True,
                'min_count': min_count,
                'count': len(results),
                'results': results,
            }
        )


class CategoriesListView(APIView):
    permission_classes = []

    def get(self, request):
        categories = (
            Category.objects.annotate(
                track_count=Count(
                    'track',
                    filter=Q(
                        track__deleted_at__isnull=True,
                        track__status=Track.Status.PUBLISHED,
                        track__visibility=Track.Visibility.PUBLIC,
                    ),
                )
            )
            .filter(track_count__gt=0)
            .order_by('name')
        )

        results = [
            {
                'id': str(category.id),
                'name': category.name,
                'track_count': int(category.track_count),
            }
            for category in categories
        ]
        return Response(
            {
                'ok': True,
                'count': len(results),
                'results': results,
            }
        )


class CategoryTracksView(APIView):
    permission_classes = []

    def get(self, request, id):
        category = Category.objects.filter(id=id).first()
        if category is None:
            return Response({'detail': 'Category not found.'}, status=status.HTTP_404_NOT_FOUND)

        limit = request.query_params.get('limit', 50)
        offset = request.query_params.get('offset', 0)
        try:
            limit = max(min(int(limit), 500), 1)
        except (TypeError, ValueError):
            limit = 50
        try:
            offset = max(int(offset), 0)
        except (TypeError, ValueError):
            offset = 0

        base_queryset = (
            Track.objects.filter(
                category_id=category.id,
                deleted_at__isnull=True,
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
            )
            .filter(_playable_track_q())
        )
        total_count = base_queryset.count()
        tracks = base_queryset.select_related('category').prefetch_related('cover_images').order_by('-created_at')[offset:offset + limit]
        serialized = RecommendationTrackSerializer(tracks, many=True).data
        count = len(serialized)
        next_offset = offset + count
        has_more = next_offset < total_count

        return Response(
            {
                'ok': True,
                'category': {
                    'id': str(category.id),
                    'name': category.name,
                },
                'count': count,
                'total_count': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': has_more,
                'next_offset': next_offset if has_more else None,
                'results': serialized,
            }
        )


class RecommendationStatsView(APIView):
    def get(self, request):
        days = request.query_params.get('days', 30)
        try:
            days = max(int(days), 1)
        except (TypeError, ValueError):
            days = 30

        cutoff = timezone.now() - timezone.timedelta(days=days)
        active_rules = RecommendationRule.objects.filter(is_active=True).count()

        scoped_events = PlayEvent.objects.filter(created_at__gte=cutoff)
        total_events = scoped_events.count()
        recommended_events = scoped_events.filter(source=PlayEvent.Source.RECOMMENDED).count()
        avg_played_seconds = scoped_events.aggregate(avg_seconds=Avg('played_seconds')).get('avg_seconds') or 0

        click_through_rate = round((recommended_events / total_events) * 100, 1) if total_events > 0 else 0.0
        avg_listen_minutes = round(float(avg_played_seconds) / 60, 1) if avg_played_seconds else 0.0

        return Response(
            {
                'ok': True,
                'days': days,
                'active_rules': active_rules,
                'click_through_rate': click_through_rate,
                'avg_listen_minutes': avg_listen_minutes,
                'total_events': total_events,
                'recommended_events': recommended_events,
            }
        )

