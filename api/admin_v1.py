import os
import uuid
import json
import tempfile
import subprocess
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from decimal import Decimal

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db.models import Avg, Count, F, Q, Sum
from django.db import IntegrityError, transaction
from django.core.files.base import File
from django.core.files.storage import default_storage
from django.db.models.functions import TruncDay, TruncMonth
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .audit import log_admin_action
from .models import (
    AdminSession,
    Category,
    PlatformSettings,
    Playlist,
    PlaylistTrack,
    PlayEvent,
    PremiumSettings,
    RecommendationRule,
    SupportMessage,
    SupportTicket,
    Subscription,
    Track,
    TrackCoverImage,
    User,
)


class AdminStubView(APIView):
    endpoint = ''

    def _ok(self, request, **kwargs):
        return Response(
            {
                'ok': True,
                'endpoint': self.endpoint,
                'method': request.method,
                'path_params': kwargs,
                'query_params': request.query_params,
            }
        )

    def get(self, request, **kwargs):
        return self._ok(request, **kwargs)

    def post(self, request, **kwargs):
        return self._ok(request, **kwargs)

    def patch(self, request, **kwargs):
        return self._ok(request, **kwargs)

    def delete(self, request, **kwargs):
        return self._ok(request, **kwargs)


def _stub(endpoint):
    class _View(AdminStubView):
        pass

    _View.endpoint = endpoint
    return _View


ADMIN_ACCESS_TOKEN_TTL_MINUTES = getattr(settings, 'ADMIN_ACCESS_TOKEN_TTL_MINUTES', 30)
ADMIN_REFRESH_TOKEN_TTL_DAYS = getattr(settings, 'ADMIN_REFRESH_TOKEN_TTL_DAYS', 30)


def _serialize_admin_user(user):
    return {
        'id': str(user.id),
        'email': user.email,
        'role': user.role,
        'status': user.status,
    }


def _create_admin_session(user):
    now = timezone.now()
    access_token = uuid.uuid4().hex + uuid.uuid4().hex
    refresh_token = uuid.uuid4().hex + uuid.uuid4().hex
    session = AdminSession.objects.create(
        user=user,
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=now + timezone.timedelta(minutes=ADMIN_ACCESS_TOKEN_TTL_MINUTES),
        refresh_expires_at=now + timezone.timedelta(days=ADMIN_REFRESH_TOKEN_TTL_DAYS),
    )
    return session


def _is_valid_password(raw_password, stored_hash):
    if not stored_hash:
        return False
    if stored_hash.startswith(('pbkdf2_', 'argon2', 'bcrypt$', 'scrypt$')):
        return check_password(raw_password, stored_hash)
    return raw_password == stored_hash


def _audit(request, action, entity_type, entity_id=None, metadata=None):
    admin_user = getattr(request, 'admin_user', None)
    if admin_user is None:
        return
    log_admin_action(
        request,
        admin_user=admin_user,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        metadata=metadata or {},
    )


class AdminLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class AdminGoogleLoginSerializer(serializers.Serializer):
    id_token = serializers.CharField()


def _verify_google_id_token(id_token: str):
    """
    Verify a Google ID token using Google's tokeninfo endpoint.

    We avoid extra dependencies (google-auth) in this project; for production, prefer
    signature verification + issuer/audience validation with cached certs.
    """

    id_token = (id_token or '').strip()
    if not id_token:
        raise ValueError('Missing id_token.')

    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '') or ''
    client_id = client_id.strip()
    if not client_id:
        raise RuntimeError('GOOGLE_OAUTH_CLIENT_ID is not configured on the server.')

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
    if aud != client_id:
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

    return {
        'email': email,
        'sub': sub,
        'name': payload.get('name') or '',
        'picture': payload.get('picture') or '',
    }


class AdminRefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class AdminAuthLoginView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = AdminLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email'].strip().lower()
        password = serializer.validated_data['password']
        user = User.objects.filter(email__iexact=email).first()

        if user is None:
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
        if user.status != User.Status.ACTIVE:
            log_admin_action(
                request,
                admin_user=user,
                action='admin.login.denied_status',
                entity_type='user',
                entity_id=user.id,
                metadata={'status': user.status, 'email': email},
            )
            return Response({'detail': 'Account is not active.'}, status=status.HTTP_403_FORBIDDEN)
        if user.role not in (User.Role.ADMIN, User.Role.MANAGER):
            log_admin_action(
                request,
                admin_user=user,
                action='admin.login.denied_role',
                entity_type='user',
                entity_id=user.id,
                metadata={'role': user.role, 'email': email},
            )
            return Response({'detail': 'Admin access required.'}, status=status.HTTP_403_FORBIDDEN)
        if not _is_valid_password(password, user.password_hash):
            log_admin_action(
                request,
                admin_user=user,
                action='admin.login.failed_password',
                entity_type='user',
                entity_id=user.id,
                metadata={'email': email},
            )
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        if user.password_hash and not user.password_hash.startswith(('pbkdf2_', 'argon2', 'bcrypt$', 'scrypt$')):
            user.password_hash = make_password(password)
        user.last_login_at = timezone.now()
        user.save(update_fields=['password_hash', 'last_login_at', 'updated_at'])

        session = _create_admin_session(user)
        log_admin_action(
            request,
            admin_user=user,
            action='admin.login.success',
            entity_type='admin_session',
            entity_id=session.id,
            metadata={'email': email, 'role': user.role},
        )
        return Response(
            {
                'ok': True,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_admin_user(user),
            }
        )


class AdminAuthGoogleView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = AdminGoogleLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            verified = _verify_google_id_token(serializer.validated_data['id_token'])
        except ValueError as exc:
            return Response({'detail': str(exc) or 'Invalid Google token.'}, status=status.HTTP_401_UNAUTHORIZED)
        except RuntimeError as exc:
            return Response(
                {'detail': str(exc) or 'Google token verification failed.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        email = verified['email']
        user = User.objects.filter(email__iexact=email).first()
        if user is None:
            return Response({'detail': 'Admin account not found.'}, status=status.HTTP_403_FORBIDDEN)
        if user.status != User.Status.ACTIVE:
            log_admin_action(
                request,
                admin_user=user,
                action='admin.login.google.denied_status',
                entity_type='user',
                entity_id=user.id,
                metadata={'status': user.status, 'email': email},
            )
            return Response({'detail': 'Account is not active.'}, status=status.HTTP_403_FORBIDDEN)
        if user.role not in (User.Role.ADMIN, User.Role.MANAGER):
            log_admin_action(
                request,
                admin_user=user,
                action='admin.login.google.denied_role',
                entity_type='user',
                entity_id=user.id,
                metadata={'role': user.role, 'email': email},
            )
            return Response({'detail': 'Admin access required.'}, status=status.HTTP_403_FORBIDDEN)

        user.last_login_at = timezone.now()
        # Do not overwrite auth_provider for existing accounts; just record provider_id if this user is google-based.
        update_fields = ['last_login_at', 'updated_at']
        if user.auth_provider == User.AuthProvider.GOOGLE and not user.provider_id:
            user.provider_id = verified['sub']
            update_fields.insert(1, 'provider_id')
        user.save(update_fields=update_fields)

        session = _create_admin_session(user)
        log_admin_action(
            request,
            admin_user=user,
            action='admin.login.google.success',
            entity_type='admin_session',
            entity_id=session.id,
            metadata={'email': email, 'role': user.role},
        )
        return Response(
            {
                'ok': True,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_admin_user(user),
            }
        )


class AdminAuthRefreshView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = AdminRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data['refresh_token']

        session = (
            AdminSession.objects.select_related('user')
            .filter(refresh_token=refresh_token, revoked_at__isnull=True)
            .first()
        )
        if session is None:
            return Response({'detail': 'Refresh token is invalid or expired.'}, status=status.HTTP_401_UNAUTHORIZED)
        if session.refresh_expires_at <= timezone.now():
            log_admin_action(
                request,
                admin_user=session.user,
                action='admin.token.refresh.failed_expired',
                entity_type='admin_session',
                entity_id=session.id,
                metadata={},
            )
            return Response({'detail': 'Refresh token is invalid or expired.'}, status=status.HTTP_401_UNAUTHORIZED)

        user = session.user
        if user.status != User.Status.ACTIVE or user.role not in (User.Role.ADMIN, User.Role.MANAGER):
            log_admin_action(
                request,
                admin_user=user,
                action='admin.token.refresh.denied',
                entity_type='user',
                entity_id=user.id,
                metadata={'status': user.status, 'role': user.role},
            )
            return Response({'detail': 'Admin access required.'}, status=status.HTTP_403_FORBIDDEN)

        session.access_token = uuid.uuid4().hex + uuid.uuid4().hex
        session.refresh_token = uuid.uuid4().hex + uuid.uuid4().hex
        session.access_expires_at = timezone.now() + timezone.timedelta(minutes=ADMIN_ACCESS_TOKEN_TTL_MINUTES)
        session.refresh_expires_at = timezone.now() + timezone.timedelta(days=ADMIN_REFRESH_TOKEN_TTL_DAYS)
        session.save(update_fields=['access_token', 'refresh_token', 'access_expires_at', 'refresh_expires_at', 'updated_at'])
        log_admin_action(
            request,
            admin_user=user,
            action='admin.token.refresh.success',
            entity_type='admin_session',
            entity_id=session.id,
            metadata={},
        )

        return Response(
            {
                'ok': True,
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'access_expires_at': session.access_expires_at,
                'refresh_expires_at': session.refresh_expires_at,
                'user': _serialize_admin_user(user),
            }
        )


class AdminAuthLogoutView(APIView):
    def post(self, request, **kwargs):
        session = getattr(request, 'admin_session', None)
        user = getattr(request, 'admin_user', None)
        if session is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)
        session.revoked_at = timezone.now()
        session.save(update_fields=['revoked_at', 'updated_at'])
        if user is not None:
            log_admin_action(
                request,
                admin_user=user,
                action='admin.logout',
                entity_type='admin_session',
                entity_id=session.id,
                metadata={},
            )
        return Response({'ok': True})


class AdminAuthMeView(APIView):
    def get(self, request, **kwargs):
        user = getattr(request, 'admin_user', None)
        if user is None:
            return Response({'detail': 'Not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({'ok': True, 'user': _serialize_admin_user(user)})


class PremiumSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PremiumSettings
        fields = [
            'subscription_price',
            'free_trial_days',
            'auto_lock_new_content',
            'allow_gifting',
            'updated_at',
        ]


class PremiumSettingsUpdateSerializer(serializers.Serializer):
    subscription_price = serializers.DecimalField(max_digits=10, decimal_places=2, required=False)
    free_trial_days = serializers.IntegerField(required=False, min_value=0)
    auto_lock_new_content = serializers.BooleanField(required=False)
    allow_gifting = serializers.BooleanField(required=False)


class AdminPremiumSettingsView(APIView):
    def get(self, request, **kwargs):
        row = PremiumSettings.objects.first()
        if row is None:
            # Create a default singleton row for development/demo environments.
            row = PremiumSettings.objects.create(
                subscription_price=Decimal('9.99'),
                free_trial_days=7,
                auto_lock_new_content=False,
                allow_gifting=False,
                updated_by=getattr(request, 'admin_user', None),
            )
        return Response({'ok': True, 'settings': PremiumSettingsSerializer(row).data})

    def patch(self, request, **kwargs):
        row = PremiumSettings.objects.first()
        if row is None:
            row = PremiumSettings.objects.create(
                subscription_price=Decimal('9.99'),
                free_trial_days=7,
                auto_lock_new_content=False,
                allow_gifting=False,
                updated_by=getattr(request, 'admin_user', None),
            )

        serializer = PremiumSettingsUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        updates = serializer.validated_data
        changed = {}
        for field in ['subscription_price', 'free_trial_days', 'auto_lock_new_content', 'allow_gifting']:
            if field in updates:
                old = getattr(row, field)
                new = updates[field]
                if old != new:
                    setattr(row, field, new)
                    changed[field] = {'from': str(old), 'to': str(new)}

        row.updated_by = getattr(request, 'admin_user', None)
        row.save()
        if changed:
            _audit(
                request,
                action='premium_settings.update',
                entity_type='premium_settings',
                entity_id=row.id,
                metadata={'changed_fields': changed},
            )
        return Response({'ok': True, 'settings': PremiumSettingsSerializer(row).data})


class CategorySummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']


class CategoryCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)

    def validate_name(self, value):
        normalized = value.strip()
        if not normalized:
            raise serializers.ValidationError('Category name cannot be empty.')
        return normalized


class AdminCategoriesCollectionView(APIView):
    def get(self, request, **kwargs):
        categories = Category.objects.order_by('name')
        serializer = CategorySummarySerializer(categories, many=True)
        return Response({'ok': True, 'count': len(serializer.data), 'results': serializer.data})

    def post(self, request, **kwargs):
        serializer = CategoryCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        normalized_name = serializer.validated_data['name']
        category = Category.objects.filter(name__iexact=normalized_name).first()
        created = False
        if category is None:
            category = Category.objects.create(name=normalized_name)
            created = True
        return Response(
            {'ok': True, 'category': CategorySummarySerializer(category).data},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class AdminCategoryDetailView(APIView):
    def delete(self, request, id, **kwargs):
        category = Category.objects.filter(id=id).first()
        if category is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        category.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PlaylistSerializer(serializers.ModelSerializer):
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
            'updated_at',
        ]


class PlaylistUpsertSerializer(serializers.Serializer):
    MAX_COVER_IMAGE_BYTES = 5 * 1024 * 1024
    ALLOWED_COVER_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp'}
    ALLOWED_COVER_IMAGE_MIME_TYPES = {'image/jpeg', 'image/png', 'image/webp'}
    BLOCKED_COVER_IMAGE_MIME_TYPES = {
        'application/x-msdownload',
        'application/x-executable',
        'application/x-dosexec',
        'application/octet-stream',
        'text/x-shellscript',
    }

    title = serializers.CharField(max_length=255, required=False)
    description = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    cover_image_url = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    cover_image_file = serializers.FileField(required=False, write_only=True)
    visibility = serializers.ChoiceField(choices=Playlist.Visibility.choices, required=False)
    is_active = serializers.BooleanField(required=False)

    def validate_cover_image_file(self, uploaded_file):
        if uploaded_file.size > self.MAX_COVER_IMAGE_BYTES:
            raise serializers.ValidationError('Cover image must be 5MB or smaller.')

        extension = os.path.splitext(uploaded_file.name)[1].lower()
        if extension not in self.ALLOWED_COVER_IMAGE_EXTENSIONS:
            raise serializers.ValidationError('Only .jpg, .jpeg, .png, and .webp files are allowed.')

        content_type = (getattr(uploaded_file, 'content_type', '') or '').lower()
        if not content_type:
            raise serializers.ValidationError('Missing file content type.')
        if content_type in self.BLOCKED_COVER_IMAGE_MIME_TYPES:
            raise serializers.ValidationError('Executable or unsafe file types are not allowed.')
        if content_type not in self.ALLOWED_COVER_IMAGE_MIME_TYPES:
            raise serializers.ValidationError('Only image/jpeg, image/png, and image/webp are allowed.')

        return uploaded_file

    def _store_uploaded_file(self, uploaded_file, folder_name):
        extension = os.path.splitext(uploaded_file.name)[1] or ''
        filename = f'{uuid.uuid4()}{extension}'
        storage_path = f'{folder_name}/{filename}'
        saved_path = default_storage.save(storage_path, uploaded_file)
        return {
            'path': saved_path,
            'url': default_storage.url(saved_path),
        }

    def validate(self, attrs):
        if self.instance is None:
            errors = {}
            if 'title' not in attrs or not str(attrs.get('title', '')).strip():
                errors['title'] = 'This field is required.'
            if 'description' not in attrs or not str(attrs.get('description', '')).strip():
                errors['description'] = 'This field is required.'
            if 'visibility' not in attrs:
                errors['visibility'] = 'This field is required.'

            has_cover_file = 'cover_image_file' in attrs and attrs.get('cover_image_file') is not None
            has_cover_url = 'cover_image_url' in attrs and bool(str(attrs.get('cover_image_url', '')).strip())
            if not has_cover_file and not has_cover_url:
                errors['cover_image_file'] = 'Cover image is required.'

            if errors:
                raise serializers.ValidationError(errors)
        return attrs

    def create(self, validated_data):
        cover_image_file = validated_data.pop('cover_image_file', None)
        stored_cover = None
        try:
            if cover_image_file is not None:
                stored_cover = self._store_uploaded_file(
                    cover_image_file,
                    'playlist_covers',
                )
                validated_data['cover_image_url'] = stored_cover['url']
            with transaction.atomic():
                return Playlist.objects.create(**validated_data)
        except Exception:
            if stored_cover is not None:
                try:
                    default_storage.delete(stored_cover['path'])
                except Exception:
                    pass
            raise

    def update(self, instance, validated_data):
        cover_image_file = validated_data.pop('cover_image_file', None)
        stored_cover = None
        try:
            if cover_image_file is not None:
                stored_cover = self._store_uploaded_file(
                    cover_image_file,
                    'playlist_covers',
                )
            with transaction.atomic():
                if stored_cover is not None:
                    instance.cover_image_url = stored_cover['url']
                for key, value in validated_data.items():
                    setattr(instance, key, value)
                instance.save()
            return instance
        except Exception:
            if stored_cover is not None:
                try:
                    default_storage.delete(stored_cover['path'])
                except Exception:
                    pass
            raise


class AdminPlaylistsCollectionView(APIView):
    def get(self, request, **kwargs):
        queryset = (
            Playlist.objects.filter(deleted_at__isnull=True)
            .annotate(track_count=Count('playlisttrack'))
            .order_by('-created_at')
        )
        serializer = PlaylistSerializer(queryset, many=True)
        return Response({'ok': True, 'count': len(serializer.data), 'results': serializer.data})

    def post(self, request, **kwargs):
        serializer = PlaylistUpsertSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        playlist = serializer.save()
        _audit(
            request,
            action='playlist.create',
            entity_type='playlist',
            entity_id=playlist.id,
            metadata={'title': playlist.title},
        )
        playlist = Playlist.objects.filter(id=playlist.id).annotate(track_count=Count('playlisttrack')).first()
        return Response(
            {'ok': True, 'playlist': PlaylistSerializer(playlist).data},
            status=status.HTTP_201_CREATED,
        )


class AdminPlaylistDetailView(APIView):
    def _get_playlist(self, playlist_id):
        return Playlist.objects.filter(id=playlist_id, deleted_at__isnull=True).annotate(track_count=Count('playlisttrack')).first()

    def get(self, request, id, **kwargs):
        playlist = self._get_playlist(id)
        if playlist is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        payload = PlaylistSerializer(playlist).data
        payload['track_ids'] = list(
            PlaylistTrack.objects.filter(playlist_id=playlist.id)
            .order_by('position')
            .values_list('track_id', flat=True)
        )
        return Response({'ok': True, 'playlist': payload})

    def patch(self, request, id, **kwargs):
        playlist = self._get_playlist(id)
        if playlist is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        old_values = {
            'title': playlist.title,
            'description': playlist.description,
            'cover_image_url': playlist.cover_image_url,
            'visibility': playlist.visibility,
            'is_active': playlist.is_active,
        }
        serializer = PlaylistUpsertSerializer(instance=playlist, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        playlist = serializer.save()
        new_values = {
            'title': playlist.title,
            'description': playlist.description,
            'cover_image_url': playlist.cover_image_url,
            'visibility': playlist.visibility,
            'is_active': playlist.is_active,
        }
        changed = {
            key: {'from': old_values[key], 'to': new_values[key]}
            for key in old_values
            if old_values[key] != new_values[key]
        }
        _audit(
            request,
            action='playlist.update',
            entity_type='playlist',
            entity_id=playlist.id,
            metadata={'changed_fields': changed},
        )
        playlist = self._get_playlist(playlist.id)
        return Response({'ok': True, 'playlist': PlaylistSerializer(playlist).data})

    def delete(self, request, id, **kwargs):
        playlist = self._get_playlist(id)
        if playlist is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        playlist.deleted_at = timezone.now()
        playlist.save(update_fields=['deleted_at', 'updated_at'])
        _audit(
            request,
            action='playlist.delete',
            entity_type='playlist',
            entity_id=playlist.id,
            metadata={'title': playlist.title},
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class TrackSerializer(serializers.ModelSerializer):
    category = CategorySummarySerializer(read_only=True)
    cover_images = serializers.SerializerMethodField()

    def get_cover_images(self, obj):
        return [
            {'id': str(image.id), 'image_url': image.image_url, 'position': image.position}
            for image in obj.cover_images.all().order_by('position', 'created_at')
        ]

    class Meta:
        model = Track
        fields = [
            'id',
            'title',
            'speaker_name',
            'description',
            'audio_url',
            'video_url',
            'cover_image_url',
            'cover_images',
            'duration_seconds',
            'category',
            'is_premium',
            'status',
            'visibility',
            'created_at',
            'updated_at',
        ]


class TrackUpsertSerializer(serializers.Serializer):
    MAX_VIDEO_BYTES = 300 * 1024 * 1024
    ALLOWED_VIDEO_EXTENSIONS = {'.mp4', '.mov', '.m4v', '.webm'}
    ALLOWED_VIDEO_MIME_TYPES = {'video/mp4', 'video/quicktime', 'video/webm'}

    title = serializers.CharField(max_length=255, required=False)
    speaker_name = serializers.CharField(max_length=255, required=False)
    description = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    audio_url = serializers.CharField(required=False, allow_blank=True)
    video_url = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    cover_image_url = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    audio_file = serializers.FileField(required=False, write_only=True)
    video_file = serializers.FileField(required=False, write_only=True)
    cover_image_file = serializers.FileField(required=False, write_only=True)
    duration_seconds = serializers.IntegerField(required=False, min_value=0)
    category_id = serializers.UUIDField(required=False, allow_null=True)
    category_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    is_premium = serializers.BooleanField(required=False)
    status = serializers.ChoiceField(choices=Track.Status.choices, required=False)
    visibility = serializers.ChoiceField(choices=Track.Visibility.choices, required=False)

    def _request_cover_image_files(self):
        request = self.context.get('request')
        if request is None:
            return []
        return request.FILES.getlist('cover_image_files')

    def _extract_cover_image_files(self, validated_data):
        cover_image_file = validated_data.pop('cover_image_file', None)
        cover_image_files = list(self._request_cover_image_files())
        if cover_image_file is not None:
            cover_image_files = [cover_image_file, *cover_image_files]
        return cover_image_files

    def _store_uploaded_file(self, uploaded_file, folder_name):
        extension = os.path.splitext(uploaded_file.name)[1] or ''
        filename = f'{uuid.uuid4()}{extension}'
        storage_path = f'{folder_name}/{filename}'
        saved_path = default_storage.save(storage_path, uploaded_file)
        return default_storage.url(saved_path)

    def _store_cover_video(self, uploaded_file):
        input_suffix = os.path.splitext(uploaded_file.name)[1] or '.mp4'
        input_path = ''
        output_path = ''
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=input_suffix) as source_file:
                for chunk in uploaded_file.chunks():
                    source_file.write(chunk)
                input_path = source_file.name

            with tempfile.NamedTemporaryFile(delete=False, suffix='.mp4') as transcoded_file:
                output_path = transcoded_file.name

            command = [
                'ffmpeg',
                '-y',
                '-i',
                input_path,
                '-an',  # strip any audio from cover video
                '-vf',
                'scale=trunc(iw/2)*2:trunc(ih/2)*2',
                '-c:v',
                'libx264',
                '-preset',
                'veryfast',
                '-pix_fmt',
                'yuv420p',
                '-movflags',
                '+faststart',
                output_path,
            ]
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0 or not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
                raise serializers.ValidationError(
                    'Unable to process cover video. Upload MP4/MOV/M4V/WEBM and try again.'
                )

            filename = f'{uuid.uuid4()}.mp4'
            storage_path = f'track_videos/{filename}'
            with open(output_path, 'rb') as output_file:
                saved_path = default_storage.save(storage_path, File(output_file, name=filename))
            return default_storage.url(saved_path)
        except FileNotFoundError:
            if hasattr(uploaded_file, 'seek'):
                uploaded_file.seek(0)
            return self._store_uploaded_file(uploaded_file, 'track_videos')
        finally:
            if input_path and os.path.exists(input_path):
                try:
                    os.remove(input_path)
                except OSError:
                    pass
            if output_path and os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass

    def validate_video_file(self, uploaded_file):
        if uploaded_file.size > self.MAX_VIDEO_BYTES:
            raise serializers.ValidationError('Video must be 300MB or smaller.')

        extension = os.path.splitext(uploaded_file.name)[1].lower()
        if extension not in self.ALLOWED_VIDEO_EXTENSIONS:
            raise serializers.ValidationError('Only .mp4, .mov, .m4v, and .webm files are allowed.')

        content_type = (getattr(uploaded_file, 'content_type', '') or '').lower()
        if content_type and content_type not in self.ALLOWED_VIDEO_MIME_TYPES:
            raise serializers.ValidationError('Only MP4, MOV, M4V, and WEBM video files are allowed.')

        return uploaded_file

    def _resolve_category(self, validated_data):
        category_id = validated_data.pop('category_id', None)
        category_name = validated_data.pop('category_name', None)

        if category_id:
            try:
                return Category.objects.get(id=category_id)
            except Category.DoesNotExist as exc:
                raise serializers.ValidationError({'category_id': 'Category not found.'}) from exc

        if category_name:
            normalized_name = category_name.strip()
            if not normalized_name:
                return None
            existing = Category.objects.filter(name__iexact=normalized_name).first()
            if existing is not None:
                return existing
            return Category.objects.create(name=normalized_name)

        return None

    def create(self, validated_data):
        audio_file = validated_data.pop('audio_file', None)
        video_file = validated_data.pop('video_file', None)
        cover_image_files = self._extract_cover_image_files(validated_data)

        if audio_file is not None:
            validated_data['audio_url'] = self._store_uploaded_file(audio_file, 'audio_tracks')
        if video_file is not None:
            validated_data['video_url'] = self._store_cover_video(video_file)
            validated_data['cover_image_url'] = None
        stored_cover_urls = []
        for file_obj in cover_image_files:
            stored_cover_urls.append(self._store_uploaded_file(file_obj, 'track_covers'))
        if stored_cover_urls:
            validated_data['cover_image_url'] = stored_cover_urls[0]
            validated_data['video_url'] = None

        category = self._resolve_category(validated_data)
        if category is not None:
            validated_data['category'] = category
        track = Track.objects.create(**validated_data)
        if stored_cover_urls:
            TrackCoverImage.objects.bulk_create(
                [
                    TrackCoverImage(track=track, image_url=image_url, position=index)
                    for index, image_url in enumerate(stored_cover_urls)
                ]
            )
        return track

    def update(self, instance, validated_data):
        audio_file = validated_data.pop('audio_file', None)
        video_file = validated_data.pop('video_file', None)
        cover_image_files = self._extract_cover_image_files(validated_data)

        if audio_file is not None:
            instance.audio_url = self._store_uploaded_file(audio_file, 'audio_tracks')
        if video_file is not None:
            instance.video_url = self._store_cover_video(video_file)
            instance.cover_image_url = None
            instance.cover_images.all().delete()
        if cover_image_files:
            stored_cover_urls = [
                self._store_uploaded_file(file_obj, 'track_covers')
                for file_obj in cover_image_files
            ]
            instance.cover_image_url = stored_cover_urls[0]
            instance.video_url = None
            instance.cover_images.all().delete()
            TrackCoverImage.objects.bulk_create(
                [
                    TrackCoverImage(track=instance, image_url=image_url, position=index)
                    for index, image_url in enumerate(stored_cover_urls)
                ]
            )

        category_provided = 'category_id' in self.initial_data or 'category_name' in self.initial_data
        if category_provided:
            instance.category = self._resolve_category(validated_data)

        for key, value in validated_data.items():
            if key == 'video_url' and (value is None or str(value).strip() == ''):
                value = None
            if key == 'audio_url' and value is None:
                value = ''
            setattr(instance, key, value)

        audio_present = bool((instance.audio_url or '').strip())
        cover_image_present = bool((instance.cover_image_url or '').strip())
        cover_video_present = bool((instance.video_url or '').strip())
        if not audio_present:
            raise serializers.ValidationError(
                {'audio_url': 'Audio source is required for a track.'}
            )
        if not cover_image_present and not cover_video_present:
            raise serializers.ValidationError(
                {'cover_image_url': 'Provide either cover image(s) or a cover video.'}
            )
        if cover_image_present and cover_video_present:
            raise serializers.ValidationError(
                {'video_url': 'Cover can contain either image(s) or video, not both.'}
            )
        instance.save()
        return instance

    def validate(self, attrs):
        audio_url = (attrs.get('audio_url') or '').strip() if 'audio_url' in attrs else ''
        video_url = (attrs.get('video_url') or '').strip() if 'video_url' in attrs else ''
        cover_image_url = (attrs.get('cover_image_url') or '').strip() if 'cover_image_url' in attrs else ''
        has_audio_url = bool(audio_url)
        has_cover_video_url = bool(video_url)
        has_cover_image_url = bool(cover_image_url)
        has_audio_file = attrs.get('audio_file') is not None
        has_cover_video_file = attrs.get('video_file') is not None
        has_cover_image_file = attrs.get('cover_image_file') is not None
        has_cover_image_files = bool(self._request_cover_image_files())

        incoming_audio = has_audio_url or has_audio_file
        incoming_cover_video = has_cover_video_url or has_cover_video_file
        incoming_cover_images = (
            has_cover_image_url or has_cover_image_file or has_cover_image_files
        )

        if incoming_cover_video and incoming_cover_images:
            raise serializers.ValidationError(
                {'video_url': 'Cover can contain either image(s) or video, not both.'}
            )

        if self.instance is None:
            required_fields = ['title', 'speaker_name', 'duration_seconds']
            missing_fields = [field for field in required_fields if field not in attrs]
            if not incoming_audio:
                missing_fields.append('audio_url')
            if not incoming_cover_video and not incoming_cover_images:
                missing_fields.append('cover_image_url')
            if missing_fields:
                raise serializers.ValidationError(
                    {field: 'This field is required.' for field in missing_fields}
                )
        else:
            existing_audio = bool((self.instance.audio_url or '').strip())
            final_audio_present = incoming_audio or (
                existing_audio and ('audio_url' not in attrs)
            )
            if not final_audio_present:
                raise serializers.ValidationError(
                    {'audio_url': 'Audio source is required for a track.'}
                )
            existing_cover_image = bool((self.instance.cover_image_url or '').strip())
            existing_cover_video = bool((self.instance.video_url or '').strip())
            if incoming_cover_video:
                final_cover_image = False
                final_cover_video = True
            elif incoming_cover_images:
                final_cover_image = True
                final_cover_video = False
            else:
                final_cover_image = existing_cover_image
                final_cover_video = existing_cover_video
                if final_cover_image and final_cover_video:
                    # Legacy rows may contain both; allow non-cover updates.
                    return attrs
            if not final_cover_image and not final_cover_video:
                raise serializers.ValidationError(
                    {'cover_image_url': 'Provide either cover image(s) or a cover video.'}
                )
        return attrs


class AdminTracksCollectionView(APIView):
    def get(self, request, **kwargs):
        queryset = Track.objects.filter(deleted_at__isnull=True).select_related('category').prefetch_related('cover_images')

        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        visibility_filter = request.query_params.get('visibility')
        if visibility_filter:
            queryset = queryset.filter(visibility=visibility_filter)

        premium_filter = request.query_params.get('is_premium')
        if premium_filter is not None:
            if premium_filter.lower() in ('true', '1', 'yes'):
                queryset = queryset.filter(is_premium=True)
            elif premium_filter.lower() in ('false', '0', 'no'):
                queryset = queryset.filter(is_premium=False)

        search_query = request.query_params.get('q')
        if search_query:
            queryset = queryset.filter(
                Q(title__icontains=search_query)
                | Q(speaker_name__icontains=search_query)
                | Q(category__name__icontains=search_query)
            )

        page = request.query_params.get('page', '1')
        page_size = request.query_params.get('page_size', '50')
        try:
            page = max(int(page), 1)
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(page_size)
        except (TypeError, ValueError):
            page_size = 50
        page_size = min(max(page_size, 1), 100)

        total_count = queryset.count()
        total_pages = max((total_count + page_size - 1) // page_size, 1)
        if page > total_pages:
            page = total_pages

        start = (page - 1) * page_size
        end = start + page_size
        paginated_queryset = queryset.order_by('-created_at')[start:end]

        serializer = TrackSerializer(paginated_queryset, many=True)
        return Response(
            {
                'ok': True,
                'count': len(serializer.data),
                'total_count': total_count,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_previous': page > 1,
                'results': serializer.data,
            }
        )

    def post(self, request, **kwargs):
        serializer = TrackUpsertSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        track = serializer.save()
        _audit(
            request,
            action='track.create',
            entity_type='track',
            entity_id=track.id,
            metadata={
                'title': track.title,
                'status': track.status,
                'visibility': track.visibility,
            },
        )
        return Response(
            {'ok': True, 'track': TrackSerializer(track).data},
            status=status.HTTP_201_CREATED,
        )


class AdminTrackDetailView(APIView):
    def _get_track(self, track_id):
        return Track.objects.filter(id=track_id, deleted_at__isnull=True).select_related('category').prefetch_related('cover_images').first()

    def get(self, request, id, **kwargs):
        track = self._get_track(id)
        if track is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'ok': True, 'track': TrackSerializer(track).data})

    def patch(self, request, id, **kwargs):
        track = self._get_track(id)
        if track is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        old_values = {
            'title': track.title,
            'speaker_name': track.speaker_name,
            'description': track.description,
            'audio_url': track.audio_url,
            'video_url': track.video_url,
            'cover_image_url': track.cover_image_url,
            'duration_seconds': track.duration_seconds,
            'category_id': str(track.category_id) if track.category_id else None,
            'is_premium': track.is_premium,
            'status': track.status,
            'visibility': track.visibility,
        }

        serializer = TrackUpsertSerializer(instance=track, data=request.data, partial=True, context={'request': request})
        serializer.is_valid(raise_exception=True)
        track = serializer.save()
        new_values = {
            'title': track.title,
            'speaker_name': track.speaker_name,
            'description': track.description,
            'audio_url': track.audio_url,
            'video_url': track.video_url,
            'cover_image_url': track.cover_image_url,
            'duration_seconds': track.duration_seconds,
            'category_id': str(track.category_id) if track.category_id else None,
            'is_premium': track.is_premium,
            'status': track.status,
            'visibility': track.visibility,
        }
        changed = {
            key: {'from': old_values[key], 'to': new_values[key]}
            for key in old_values
            if old_values[key] != new_values[key]
        }
        _audit(
            request,
            action='track.update',
            entity_type='track',
            entity_id=track.id,
            metadata={'changed_fields': changed},
        )
        return Response({'ok': True, 'track': TrackSerializer(track).data})

    def delete(self, request, id, **kwargs):
        track = self._get_track(id)
        if track is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        track.deleted_at = timezone.now()
        track.save(update_fields=['deleted_at', 'updated_at'])
        _audit(
            request,
            action='track.delete',
            entity_type='track',
            entity_id=track.id,
            metadata={'title': track.title},
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminTrackPublishView(APIView):
    def post(self, request, id, **kwargs):
        track = Track.objects.filter(id=id, deleted_at__isnull=True).first()
        if track is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        track.status = Track.Status.PUBLISHED
        track.save(update_fields=['status', 'updated_at'])
        _audit(
            request,
            action='track.publish',
            entity_type='track',
            entity_id=track.id,
            metadata={'title': track.title},
        )
        return Response({'ok': True, 'track': TrackSerializer(track).data})


class AdminTrackUnpublishView(APIView):
    def post(self, request, id, **kwargs):
        track = Track.objects.filter(id=id, deleted_at__isnull=True).first()
        if track is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        track.status = Track.Status.DRAFT
        track.save(update_fields=['status', 'updated_at'])
        _audit(
            request,
            action='track.unpublish',
            entity_type='track',
            entity_id=track.id,
            metadata={'title': track.title},
        )
        return Response({'ok': True, 'track': TrackSerializer(track).data})


class PlaylistTrackListItemSerializer(serializers.ModelSerializer):
    track_id = serializers.UUIDField(source='track.id', read_only=True)
    title = serializers.CharField(source='track.title', read_only=True)
    speaker_name = serializers.CharField(source='track.speaker_name', read_only=True)
    duration_seconds = serializers.IntegerField(source='track.duration_seconds', read_only=True)
    is_premium = serializers.BooleanField(source='track.is_premium', read_only=True)
    cover_image_url = serializers.CharField(source='track.cover_image_url', read_only=True, allow_null=True)

    class Meta:
        model = PlaylistTrack
        fields = [
            'id',
            'track_id',
            'title',
            'speaker_name',
            'duration_seconds',
            'is_premium',
            'cover_image_url',
            'position',
        ]


class PlaylistTracksUpsertSerializer(serializers.Serializer):
    track_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        allow_empty=True,
    )
    track_id = serializers.UUIDField(required=False)
    position = serializers.IntegerField(required=False, min_value=0)

    def validate(self, attrs):
        has_track_ids = 'track_ids' in attrs
        has_single_track = 'track_id' in attrs
        if not has_track_ids and not has_single_track:
            raise serializers.ValidationError('Provide either track_ids or track_id.')
        if has_track_ids:
            deduped_track_ids = []
            seen = set()
            for track_id in attrs['track_ids']:
                if track_id in seen:
                    raise serializers.ValidationError({'track_ids': 'Duplicate track ids are not allowed.'})
                seen.add(track_id)
                deduped_track_ids.append(track_id)
            attrs['track_ids'] = deduped_track_ids
        return attrs


class AdminPlaylistTracksAddView(APIView):
    def get(self, request, id, **kwargs):
        playlist = Playlist.objects.filter(id=id, deleted_at__isnull=True).first()
        if playlist is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        playlist_tracks = (
            PlaylistTrack.objects.filter(playlist=playlist)
            .select_related('track')
            .order_by('position', 'created_at')
        )
        serializer = PlaylistTrackListItemSerializer(playlist_tracks, many=True)
        return Response({'ok': True, 'count': len(serializer.data), 'results': serializer.data})

    def post(self, request, id, **kwargs):
        playlist = Playlist.objects.filter(id=id, deleted_at__isnull=True).first()
        if playlist is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = PlaylistTracksUpsertSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        if 'track_ids' in validated:
            track_ids = validated['track_ids']
            tracks = list(Track.objects.filter(id__in=track_ids, deleted_at__isnull=True))
            found_ids = {track.id for track in tracks}
            missing_ids = [str(track_id) for track_id in track_ids if track_id not in found_ids]
            valid_track_ids = [track_id for track_id in track_ids if track_id in found_ids]
            if not valid_track_ids:
                return Response(
                    {'detail': 'No valid tracks were found.', 'missing_track_ids': missing_ids},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            with transaction.atomic():
                PlaylistTrack.objects.filter(playlist=playlist).delete()
                PlaylistTrack.objects.bulk_create(
                    [
                        PlaylistTrack(
                            playlist=playlist,
                            track_id=track_id,
                            position=index,
                        )
                        for index, track_id in enumerate(valid_track_ids)
                    ]
                )
            _audit(
                request,
                action='playlist.tracks.replace',
                entity_type='playlist',
                entity_id=playlist.id,
                metadata={
                    'track_ids': [str(track_id) for track_id in valid_track_ids],
                    'skipped_missing_track_ids': missing_ids,
                },
            )
            return Response(
                {
                    'ok': True,
                    'count': len(valid_track_ids),
                    'skipped_missing_track_ids': missing_ids,
                }
            )

        track_id = validated['track_id']
        track = Track.objects.filter(id=track_id, deleted_at__isnull=True).first()
        if track is None:
            return Response({'detail': 'Track not found.'}, status=status.HTTP_404_NOT_FOUND)

        existing = PlaylistTrack.objects.filter(playlist=playlist, track=track).first()
        if existing is not None:
            return Response({'ok': True, 'playlist_track_id': str(existing.id), 'already_exists': True})

        desired_position = validated.get('position')
        if desired_position is None:
            desired_position = PlaylistTrack.objects.filter(playlist=playlist).count()

        playlist_track = PlaylistTrack.objects.create(
            playlist=playlist,
            track=track,
            position=desired_position,
        )
        _audit(
            request,
            action='playlist.track.add',
            entity_type='playlist',
            entity_id=playlist.id,
            metadata={
                'track_id': str(track.id),
                'playlist_track_id': str(playlist_track.id),
                'position': desired_position,
            },
        )
        return Response(
            {'ok': True, 'playlist_track_id': str(playlist_track.id), 'already_exists': False},
            status=status.HTTP_201_CREATED,
        )


class AdminPlaylistTrackRemoveView(APIView):
    def delete(self, request, id, track_id, **kwargs):
        playlist = Playlist.objects.filter(id=id, deleted_at__isnull=True).first()
        if playlist is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        deleted, _ = PlaylistTrack.objects.filter(playlist=playlist, track_id=track_id).delete()
        if deleted == 0:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        _audit(
            request,
            action='playlist.track.remove',
            entity_type='playlist',
            entity_id=playlist.id,
            metadata={'track_id': str(track_id)},
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


DEFAULT_RECOMMENDATION_RULES = [
    {
        'rule_key': 'top_played',
        'name': 'Top Played',
        'description': 'Show most played tracks in the configured recent window.',
        'priority': 1,
        'config': {'days': 7, 'limit': 10},
    },
    {
        'rule_key': 'recently_added',
        'name': 'Recently Added',
        'description': 'Highlight newly uploaded tracks.',
        'priority': 2,
        'config': {'limit': 10},
    },
    {
        'rule_key': 'based_on_history',
        'name': 'Based on History',
        'description': 'Recommend tracks based on user listening history.',
        'priority': 3,
        'config': {'min_listens': 3, 'limit': 10},
    },
]


def ensure_default_recommendation_rules():
    key_aliases = {
        'recent': 'recently_added',
        'category_based': 'based_on_history',
    }
    for old_key, new_key in key_aliases.items():
        old_rule = RecommendationRule.objects.filter(rule_key=old_key).first()
        if old_rule is not None and not RecommendationRule.objects.filter(rule_key=new_key).exists():
            old_rule.rule_key = new_key
            old_rule.save(update_fields=['rule_key', 'updated_at'])

    for default_rule in DEFAULT_RECOMMENDATION_RULES:
        RecommendationRule.objects.get_or_create(
            rule_key=default_rule['rule_key'],
            defaults={
                'name': default_rule['name'],
                'description': default_rule['description'],
                'priority': default_rule['priority'],
                'is_active': True,
                'config': default_rule['config'],
            },
        )


class RecommendationRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecommendationRule
        fields = [
            'id',
            'rule_key',
            'name',
            'description',
            'priority',
            'is_active',
            'config',
            'created_at',
            'updated_at',
        ]


class RecommendationRuleCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecommendationRule
        fields = ['rule_key', 'name', 'description', 'priority', 'is_active', 'config']


class RecommendationRuleUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255, required=False)
    description = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    priority = serializers.IntegerField(required=False)
    is_active = serializers.BooleanField(required=False)
    config = serializers.JSONField(required=False, allow_null=True)


class RecommendationReorderSerializer(serializers.Serializer):
    rule_ids = serializers.ListField(
        child=serializers.UUIDField(),
        allow_empty=False,
    )

    def validate_rule_ids(self, value):
        if len(value) != len(set(value)):
            raise serializers.ValidationError('Duplicate rule ids are not allowed.')
        return value


class AdminRecommendationRulesCollectionView(APIView):
    def get(self, request, **kwargs):
        ensure_default_recommendation_rules()
        queryset = RecommendationRule.objects.order_by('priority', 'created_at')
        serializer = RecommendationRuleSerializer(queryset, many=True)
        return Response({'ok': True, 'count': len(serializer.data), 'results': serializer.data})

    def post(self, request, **kwargs):
        serializer = RecommendationRuleCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule = serializer.save()
        _audit(
            request,
            action='recommendation_rule.create',
            entity_type='recommendation_rule',
            entity_id=rule.id,
            metadata={
                'rule_key': rule.rule_key,
                'name': rule.name,
                'priority': rule.priority,
                'is_active': rule.is_active,
            },
        )
        return Response(
            {'ok': True, 'rule': RecommendationRuleSerializer(rule).data},
            status=status.HTTP_201_CREATED,
        )


class AdminRecommendationRuleDetailView(APIView):
    def _get_rule(self, rule_id):
        return RecommendationRule.objects.filter(id=rule_id).first()

    def get(self, request, id, **kwargs):
        ensure_default_recommendation_rules()
        rule = self._get_rule(id)
        if rule is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'ok': True, 'rule': RecommendationRuleSerializer(rule).data})

    def patch(self, request, id, **kwargs):
        rule = self._get_rule(id)
        if rule is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        old_values = {
            'name': rule.name,
            'description': rule.description,
            'priority': rule.priority,
            'is_active': rule.is_active,
            'config': rule.config,
        }

        serializer = RecommendationRuleUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        for key, value in serializer.validated_data.items():
            setattr(rule, key, value)
        rule.save()
        new_values = {
            'name': rule.name,
            'description': rule.description,
            'priority': rule.priority,
            'is_active': rule.is_active,
            'config': rule.config,
        }
        changed = {
            key: {'from': old_values[key], 'to': new_values[key]}
            for key in old_values
            if old_values[key] != new_values[key]
        }
        _audit(
            request,
            action='recommendation_rule.update',
            entity_type='recommendation_rule',
            entity_id=rule.id,
            metadata={'changed_fields': changed},
        )
        return Response({'ok': True, 'rule': RecommendationRuleSerializer(rule).data})

    def delete(self, request, id, **kwargs):
        rule = self._get_rule(id)
        if rule is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        rule_info = {'rule_key': rule.rule_key, 'name': rule.name}
        rule.delete()
        _audit(
            request,
            action='recommendation_rule.delete',
            entity_type='recommendation_rule',
            entity_id=rule.id,
            metadata=rule_info,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminRecommendationRuleActivateView(APIView):
    def post(self, request, id, **kwargs):
        rule = RecommendationRule.objects.filter(id=id).first()
        if rule is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        rule.is_active = True
        rule.save(update_fields=['is_active', 'updated_at'])
        _audit(
            request,
            action='recommendation_rule.activate',
            entity_type='recommendation_rule',
            entity_id=rule.id,
            metadata={'rule_key': rule.rule_key},
        )
        return Response({'ok': True, 'rule': RecommendationRuleSerializer(rule).data})


class AdminRecommendationRuleDeactivateView(APIView):
    def post(self, request, id, **kwargs):
        rule = RecommendationRule.objects.filter(id=id).first()
        if rule is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        rule.is_active = False
        rule.save(update_fields=['is_active', 'updated_at'])
        _audit(
            request,
            action='recommendation_rule.deactivate',
            entity_type='recommendation_rule',
            entity_id=rule.id,
            metadata={'rule_key': rule.rule_key},
        )
        return Response({'ok': True, 'rule': RecommendationRuleSerializer(rule).data})


class AdminRecommendationReorderView(APIView):
    def post(self, request, **kwargs):
        ensure_default_recommendation_rules()
        serializer = RecommendationReorderSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule_ids = serializer.validated_data['rule_ids']

        existing_ids = set(RecommendationRule.objects.values_list('id', flat=True))
        payload_ids = set(rule_ids)
        if existing_ids != payload_ids:
            return Response(
                {'detail': 'rule_ids must include all recommendation rules exactly once.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            for index, rule_id in enumerate(rule_ids, start=1):
                RecommendationRule.objects.filter(id=rule_id).update(priority=index)
        _audit(
            request,
            action='recommendation_rule.reorder',
            entity_type='recommendation_rule',
            metadata={'rule_ids': [str(rule_id) for rule_id in rule_ids]},
        )

        queryset = RecommendationRule.objects.order_by('priority', 'created_at')
        return Response({'ok': True, 'count': queryset.count(), 'results': RecommendationRuleSerializer(queryset, many=True).data})


def ensure_platform_settings():
    settings, _ = PlatformSettings.objects.get_or_create(singleton_key=1)
    return settings


class PlatformSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlatformSettings
        fields = [
            'id',
            'platform_visible',
            'maintenance_mode',
            'allow_public_signup',
            'require_email_verification',
            'allow_guest_access',
            'display_advertisement',
            'enable_email_notifications',
            'enable_push_notifications',
            'updated_at',
        ]


class PlatformSettingsUpdateSerializer(serializers.Serializer):
    platform_visible = serializers.BooleanField(required=False)
    maintenance_mode = serializers.BooleanField(required=False)
    allow_public_signup = serializers.BooleanField(required=False)
    require_email_verification = serializers.BooleanField(required=False)
    allow_guest_access = serializers.BooleanField(required=False)
    display_advertisement = serializers.BooleanField(required=False)
    enable_email_notifications = serializers.BooleanField(required=False)
    enable_push_notifications = serializers.BooleanField(required=False)


class AdminPlatformSettingsView(APIView):
    def get(self, request, **kwargs):
        settings = ensure_platform_settings()
        return Response({'ok': True, 'settings': PlatformSettingsSerializer(settings).data})

    def patch(self, request, **kwargs):
        settings = ensure_platform_settings()
        serializer = PlatformSettingsUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        old_values = {
            'platform_visible': settings.platform_visible,
            'maintenance_mode': settings.maintenance_mode,
            'allow_public_signup': settings.allow_public_signup,
            'require_email_verification': settings.require_email_verification,
            'allow_guest_access': settings.allow_guest_access,
            'display_advertisement': settings.display_advertisement,
            'enable_email_notifications': settings.enable_email_notifications,
            'enable_push_notifications': settings.enable_push_notifications,
        }

        for key, value in serializer.validated_data.items():
            setattr(settings, key, value)
        settings.save()
        new_values = {
            'platform_visible': settings.platform_visible,
            'maintenance_mode': settings.maintenance_mode,
            'allow_public_signup': settings.allow_public_signup,
            'require_email_verification': settings.require_email_verification,
            'allow_guest_access': settings.allow_guest_access,
            'display_advertisement': settings.display_advertisement,
            'enable_email_notifications': settings.enable_email_notifications,
            'enable_push_notifications': settings.enable_push_notifications,
        }
        changed = {
            key: {'from': old_values[key], 'to': new_values[key]}
            for key in old_values
            if old_values[key] != new_values[key]
        }
        _audit(
            request,
            action='platform_settings.update',
            entity_type='platform_settings',
            entity_id=settings.id,
            metadata={'changed_fields': changed},
        )

        return Response({'ok': True, 'settings': PlatformSettingsSerializer(settings).data})


def _percent_change(current_value, previous_value):
    if previous_value == 0:
        return 100.0 if current_value > 0 else 0.0
    return round(((current_value - previous_value) / previous_value) * 100.0, 1)


def _series_date_labels(days):
    now = timezone.now()
    labels = []
    for offset in range(days - 1, -1, -1):
        labels.append((now - timezone.timedelta(days=offset)).date())
    return labels


class AdminAnalyticsOverviewView(APIView):
    def get(self, request, **kwargs):
        now = timezone.now()
        period_days = int(request.query_params.get('days', 30) or 30)
        period_days = min(max(period_days, 1), 365)
        current_start = now - timezone.timedelta(days=period_days)
        previous_start = current_start - timezone.timedelta(days=period_days)

        total_tracks = Track.objects.filter(deleted_at__isnull=True).count()
        total_playlists = Playlist.objects.filter(deleted_at__isnull=True).count()
        active_users = (
            PlayEvent.objects.filter(created_at__gte=current_start)
            .values('user_id')
            .distinct()
            .count()
        )
        premium_users = (
            Subscription.objects.filter(status=Subscription.Status.ACTIVE)
            .values('user_id')
            .distinct()
            .count()
        )

        prev_total_tracks = Track.objects.filter(
            deleted_at__isnull=True,
            created_at__gte=previous_start,
            created_at__lt=current_start,
        ).count()
        prev_total_playlists = Playlist.objects.filter(
            deleted_at__isnull=True,
            created_at__gte=previous_start,
            created_at__lt=current_start,
        ).count()
        prev_active_users = (
            PlayEvent.objects.filter(created_at__gte=previous_start, created_at__lt=current_start)
            .values('user_id')
            .distinct()
            .count()
        )
        prev_premium_users = (
            Subscription.objects.filter(
                status=Subscription.Status.ACTIVE,
                created_at__gte=previous_start,
                created_at__lt=current_start,
            )
            .values('user_id')
            .distinct()
            .count()
        )

        kpis = [
            {
                'key': 'total_tracks',
                'label': 'Total Tracks',
                'value': total_tracks,
                'trend_pct': _percent_change(total_tracks, prev_total_tracks),
            },
            {
                'key': 'total_playlists',
                'label': 'Total Playlists',
                'value': total_playlists,
                'trend_pct': _percent_change(total_playlists, prev_total_playlists),
            },
            {
                'key': 'active_users',
                'label': 'Active Users',
                'value': active_users,
                'trend_pct': _percent_change(active_users, prev_active_users),
            },
            {
                'key': 'premium_users',
                'label': 'Premium Users',
                'value': premium_users,
                'trend_pct': _percent_change(premium_users, prev_premium_users),
            },
        ]

        upload_rows = (
            Track.objects.filter(deleted_at__isnull=True, created_at__gte=now - timezone.timedelta(days=7))
            .annotate(day=TruncDay('created_at'))
            .values('day')
            .annotate(count=Count('id'))
            .order_by('day')
        )
        upload_by_day = {row['day'].date(): row['count'] for row in upload_rows if row['day']}
        upload_activity = [
            {
                'date': day.strftime('%a'),
                'uploads': upload_by_day.get(day, 0),
            }
            for day in _series_date_labels(7)
        ]

        engagement_rows = (
            PlayEvent.objects.filter(created_at__gte=now - timezone.timedelta(days=180))
            .annotate(month=TruncMonth('created_at'))
            .values('month')
            .annotate(plays=Count('id'), users=Count('user_id', distinct=True))
            .order_by('month')
        )
        engagement = [
            {
                'month': row['month'].strftime('%b') if row['month'] else '',
                'plays': row['plays'],
                'users': row['users'],
            }
            for row in engagement_rows
        ]

        recent_tracks = (
            Track.objects.filter(deleted_at__isnull=True)
            .order_by('-created_at')[:5]
        )
        recent_uploads = [
            {
                'id': str(track.id),
                'title': track.title,
                'artist': track.speaker_name,
                'duration_seconds': track.duration_seconds,
                'audio_url': track.audio_url,
                'video_url': track.video_url,
                'cover_image_url': track.cover_image_url,
            }
            for track in recent_tracks
        ]

        top_played_rows = (
            PlayEvent.objects.filter(created_at__gte=now - timezone.timedelta(days=30))
            .values(
                'track_id',
                'track__title',
                'track__speaker_name',
                'track__audio_url',
                'track__video_url',
                'track__cover_image_url',
                'track__duration_seconds',
            )
            .annotate(plays=Count('id'))
            .order_by('-plays', 'track__title')[:5]
        )
        top_played = [
            {
                'rank': idx + 1,
                'track_id': str(row['track_id']),
                'title': row['track__title'],
                'speaker_name': row['track__speaker_name'],
                'audio_url': row['track__audio_url'],
                'video_url': row['track__video_url'],
                'cover_image_url': row['track__cover_image_url'],
                'duration_seconds': row['track__duration_seconds'],
                'plays': row['plays'],
            }
            for idx, row in enumerate(top_played_rows)
        ]

        total_duration = Track.objects.filter(deleted_at__isnull=True).aggregate(
            duration_sum=Sum('duration_seconds')
        )['duration_sum'] or 0
        played_seconds_30d = PlayEvent.objects.filter(
            created_at__gte=current_start
        ).aggregate(played_sum=Sum('played_seconds'))['played_sum'] or 0

        return Response(
            {
                'ok': True,
                'period_days': period_days,
                'kpis': kpis,
                'upload_activity': upload_activity,
                'engagement': engagement,
                'recent_uploads': recent_uploads,
                'top_played': top_played,
                'quick_stats': {
                    'total_hours_content': round(total_duration / 3600.0, 1),
                    'played_hours_period': round(played_seconds_30d / 3600.0, 1),
                },
            }
        )


class AdminAnalyticsUsersView(APIView):
    def get(self, request, **kwargs):
        now = timezone.now()
        days = int(request.query_params.get('days', 30) or 30)
        days = min(max(days, 1), 365)
        start = now - timezone.timedelta(days=days)

        new_users = User.objects.filter(created_at__gte=start).count()
        active_users = (
            PlayEvent.objects.filter(created_at__gte=start)
            .values('user_id')
            .distinct()
            .count()
        )
        avg_completion = PlayEvent.objects.filter(created_at__gte=start).aggregate(
            value=Avg('completion_percentage')
        )['value'] or 0.0

        daily_rows = (
            PlayEvent.objects.filter(created_at__gte=start)
            .annotate(day=TruncDay('created_at'))
            .values('day')
            .annotate(active_users=Count('user_id', distinct=True))
            .order_by('day')
        )
        daily_series = [
            {
                'date': row['day'].date().isoformat() if row['day'] else '',
                'active_users': row['active_users'],
            }
            for row in daily_rows
        ]

        return Response(
            {
                'ok': True,
                'days': days,
                'summary': {
                    'new_users': new_users,
                    'active_users': active_users,
                    'avg_completion_pct': round(float(avg_completion), 1),
                },
                'daily_active_users': daily_series,
            }
        )


class AdminAnalyticsConversionsView(APIView):
    def get(self, request, **kwargs):
        total_users = User.objects.count()
        trial_users = (
            Subscription.objects.filter(status=Subscription.Status.TRIAL)
            .values('user_id')
            .distinct()
            .count()
        )
        premium_users = (
            Subscription.objects.filter(status=Subscription.Status.ACTIVE)
            .values('user_id')
            .distinct()
            .count()
        )
        non_free_users = (
            User.objects.filter(subscription__status__in=[Subscription.Status.TRIAL, Subscription.Status.ACTIVE])
            .distinct()
            .count()
        )
        free_users = max(total_users - non_free_users, 0)

        free_to_trial_rate = 0.0 if free_users == 0 else round((trial_users / free_users) * 100.0, 1)
        trial_to_premium_rate = 0.0 if trial_users == 0 else round((premium_users / trial_users) * 100.0, 1)

        return Response(
            {
                'ok': True,
                'funnel': {
                    'free_users': free_users,
                    'trial_users': trial_users,
                    'premium_users': premium_users,
                },
                'rates': {
                    'free_to_trial_pct': free_to_trial_rate,
                    'trial_to_premium_pct': trial_to_premium_rate,
                },
            }
        )


class AdminAnalyticsRevenueView(APIView):
    def get(self, request, **kwargs):
        now = timezone.now()
        start = now - timezone.timedelta(days=180)
        monthly_subscriptions = (
            Subscription.objects.filter(status=Subscription.Status.ACTIVE, created_at__gte=start)
            .annotate(month=TruncMonth('created_at'))
            .values('month')
            .annotate(active_subscriptions=Count('id'))
            .order_by('month')
        )

        settings_row = PremiumSettings.objects.first()
        price = float(settings_row.subscription_price) if settings_row else 0.0
        monthly = []
        for row in monthly_subscriptions:
            subscriptions = row['active_subscriptions']
            monthly.append(
                {
                    'month': row['month'].strftime('%Y-%m') if row['month'] else '',
                    'active_subscriptions': subscriptions,
                    'estimated_revenue': round(subscriptions * price, 2),
                }
            )

        total_estimated = round(sum(row['estimated_revenue'] for row in monthly), 2)
        return Response(
            {
                'ok': True,
                'subscription_price': price,
                'total_estimated_revenue': total_estimated,
                'monthly': monthly,
            }
        )


class AdminUserListItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'role',
            'status',
            'last_login_at',
            'created_at',
        ]


class AdminUserRoleUpdateSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=User.Role.choices)


class AdminUsersCollectionView(APIView):
    def get(self, request, **kwargs):
        queryset = User.objects.all().order_by('-created_at')

        q = (request.query_params.get('q') or '').strip()
        if q:
            queryset = queryset.filter(email__icontains=q)

        role = (request.query_params.get('role') or '').strip()
        if role:
            queryset = queryset.filter(role=role)

        status_filter = (request.query_params.get('status') or '').strip()
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        page = request.query_params.get('page', '1')
        page_size = request.query_params.get('page_size', '25')
        try:
            page = max(int(page), 1)
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(page_size)
        except (TypeError, ValueError):
            page_size = 25
        page_size = min(max(page_size, 1), 100)

        total_count = queryset.count()
        total_pages = max((total_count + page_size - 1) // page_size, 1)
        if page > total_pages:
            page = total_pages

        start = (page - 1) * page_size
        end = start + page_size
        page_qs = queryset[start:end]
        serializer = AdminUserListItemSerializer(page_qs, many=True)
        return Response(
            {
                'ok': True,
                'results': serializer.data,
                'total_count': total_count,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages,
            }
        )


class AdminUserDetailView(APIView):
    def get(self, request, id, **kwargs):
        user = User.objects.filter(id=id).first()
        if user is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'ok': True, 'user': AdminUserListItemSerializer(user).data})


class AdminUserActivateView(APIView):
    def post(self, request, id, **kwargs):
        user = User.objects.filter(id=id).first()
        if user is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        old_status = user.status
        user.status = User.Status.ACTIVE
        user.save(update_fields=['status', 'updated_at'])
        _audit(
            request,
            action='user.activate',
            entity_type='user',
            entity_id=user.id,
            metadata={'from': old_status, 'to': user.status},
        )
        return Response({'ok': True, 'user': AdminUserListItemSerializer(user).data})


class AdminUserDeactivateView(APIView):
    def post(self, request, id, **kwargs):
        user = User.objects.filter(id=id).first()
        if user is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        old_status = user.status
        user.status = User.Status.BLOCKED
        user.save(update_fields=['status', 'updated_at'])
        _audit(
            request,
            action='user.deactivate',
            entity_type='user',
            entity_id=user.id,
            metadata={'from': old_status, 'to': user.status},
        )
        return Response({'ok': True, 'user': AdminUserListItemSerializer(user).data})


class AdminRolesListView(APIView):
    def get(self, request, **kwargs):
        roles = [{'key': key, 'label': label} for key, label in User.Role.choices]
        return Response({'ok': True, 'results': roles})


class AdminUserRoleUpdateView(APIView):
    def patch(self, request, id, **kwargs):
        user = User.objects.filter(id=id).first()
        if user is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminUserRoleUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_role = serializer.validated_data['role']
        old_role = user.role
        user.role = new_role
        user.save(update_fields=['role', 'updated_at'])
        _audit(
            request,
            action='user.role.update',
            entity_type='user',
            entity_id=user.id,
            metadata={'from': old_role, 'to': new_role},
        )
        return Response({'ok': True, 'user': AdminUserListItemSerializer(user).data})


class AdminUserResetPasswordView(APIView):
    def post(self, request, id, **kwargs):
        user = User.objects.filter(id=id).first()
        if user is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Generate a temporary password. In production you'd trigger an email flow.
        temporary_password = uuid.uuid4().hex[:10] + "A1!"
        user.password_hash = make_password(temporary_password)
        user.save(update_fields=['password_hash', 'updated_at'])
        _audit(
            request,
            action='user.reset_password',
            entity_type='user',
            entity_id=user.id,
            metadata={},
        )

        payload = {'ok': True}
        if getattr(settings, 'DEBUG', False):
            payload['temporary_password'] = temporary_password
        return Response(payload)


class AdminPremiumSummaryView(APIView):
    """
    Paywall & Premium stat cards for the admin UI.

    Note: payments are not implemented yet, so revenue is an estimate (MRR):
    active subscriptions * premium_settings.subscription_price.
    """

    def get(self, request, **kwargs):
        now = timezone.now()
        period_days = int(request.query_params.get('days', 30) or 30)
        period_days = min(max(period_days, 1), 365)
        previous_now = now - timezone.timedelta(days=period_days)

        def _active_subscriptions(as_of):
            # "Active" is based on both status and time bounds.
            return Subscription.objects.filter(
                status=Subscription.Status.ACTIVE,
                started_at__lte=as_of,
                ends_at__gt=as_of,
            )

        active_now = _active_subscriptions(now)
        active_prev = _active_subscriptions(previous_now)

        premium_users = active_now.values('user_id').distinct().count()
        prev_premium_users = active_prev.values('user_id').distinct().count()

        active_subscriptions = active_now.count()
        prev_active_subscriptions = active_prev.count()

        settings_row = PremiumSettings.objects.first()
        subscription_price = float(settings_row.subscription_price) if settings_row else 0.0
        currency = 'USD'

        monthly_revenue = round(active_subscriptions * subscription_price, 2)
        prev_monthly_revenue = round(prev_active_subscriptions * subscription_price, 2)

        premium_tracks = Track.objects.filter(deleted_at__isnull=True, is_premium=True).count()
        premium_playlists = Playlist.objects.filter(
            deleted_at__isnull=True,
            visibility=Playlist.Visibility.PREMIUM,
        ).count()
        premium_content = premium_tracks + premium_playlists

        total_users = User.objects.count()
        prev_total_users = User.objects.filter(created_at__lte=previous_now).count()

        conversion_rate = 0.0 if total_users == 0 else round((premium_users / total_users) * 100.0, 1)
        prev_conversion_rate = (
            0.0 if prev_total_users == 0 else round((prev_premium_users / prev_total_users) * 100.0, 1)
        )

        return Response(
            {
                'ok': True,
                'period_days': period_days,
                'computed_at': now,
                'stats': {
                    'premium_users': {
                        'value': premium_users,
                        'trend_pct': _percent_change(premium_users, prev_premium_users),
                    },
                    'monthly_revenue': {
                        'value': monthly_revenue,
                        'trend_pct': _percent_change(monthly_revenue, prev_monthly_revenue),
                        'currency': currency,
                        'subscription_price': subscription_price,
                        'active_subscriptions': active_subscriptions,
                    },
                    'premium_content': {
                        'value': premium_content,
                        'subtitle': 'items locked',
                        'breakdown': {
                            'tracks': premium_tracks,
                            'playlists': premium_playlists,
                        },
                    },
                    'conversion_rate': {
                        'value': conversion_rate,
                        'trend_pct': _percent_change(conversion_rate, prev_conversion_rate),
                    },
                },
            }
        )


def _parse_support_limit_offset(request, *, default_limit=20, max_limit=200):
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


def _parse_support_datetime(raw_value):
    value = (raw_value or '').strip()
    if not value:
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _serialize_support_user(user):
    if user is None:
        return None
    return {
        'id': str(user.id),
        'email': user.email,
        'username': user.username,
        'role': user.role,
    }


def _serialize_support_ticket(ticket):
    return {
        'id': str(ticket.id),
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


def _serialize_support_message(row):
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


class SupportTicketAssignSerializer(serializers.Serializer):
    admin_id = serializers.UUIDField(required=False, allow_null=True)


class SupportTicketStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=SupportTicket.Status.choices)


class AdminSupportTicketsCollectionView(APIView):
    def get(self, request, **kwargs):
        queryset = SupportTicket.objects.select_related('user', 'assigned_admin').all()

        status_filter = (request.query_params.get('status') or '').strip().lower()
        if status_filter in {SupportTicket.Status.OPEN, SupportTicket.Status.IN_PROGRESS, SupportTicket.Status.CLOSED}:
            queryset = queryset.filter(status=status_filter)

        q = (request.query_params.get('q') or '').strip()
        if q:
            queryset = queryset.filter(
                Q(subject__icontains=q)
                | Q(user__email__icontains=q)
                | Q(user__username__icontains=q)
            )

        queryset = queryset.order_by('-last_message_at', '-updated_at', '-created_at')
        limit, offset = _parse_support_limit_offset(request, default_limit=20, max_limit=100)

        total_count = queryset.count()
        tickets = list(queryset[offset:offset + limit])
        results = []
        for ticket in tickets:
            latest = (
                SupportMessage.objects.filter(ticket=ticket)
                .order_by('-created_at', '-id')
                .first()
            )
            row = _serialize_support_ticket(ticket)
            row['last_message_preview'] = (latest.message[:160] if latest else None)
            results.append(row)

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
                'results': results,
            }
        )


class AdminSupportTicketDetailView(APIView):
    def get(self, request, id, **kwargs):
        ticket = (
            SupportTicket.objects.select_related('user', 'assigned_admin')
            .filter(id=id)
            .first()
        )
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)
        latest = (
            SupportMessage.objects.filter(ticket=ticket)
            .order_by('-created_at', '-id')
            .first()
        )
        payload = _serialize_support_ticket(ticket)
        payload['last_message_preview'] = (latest.message[:160] if latest else None)
        payload['message_count'] = SupportMessage.objects.filter(ticket=ticket).count()
        return Response({'ok': True, 'ticket': payload})


class AdminSupportTicketMessagesView(APIView):
    def _get_ticket(self, ticket_id):
        return (
            SupportTicket.objects.select_related('user', 'assigned_admin')
            .filter(id=ticket_id)
            .first()
        )

    def get(self, request, id, **kwargs):
        ticket = self._get_ticket(id)
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)

        limit, offset = _parse_support_limit_offset(request, default_limit=30, max_limit=200)
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
        rows = list(queryset[offset:offset + limit])
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
        ticket = self._get_ticket(id)
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)
        if ticket.status == SupportTicket.Status.CLOSED:
            return Response(
                {
                    'detail': 'Ticket is closed.',
                    'code': 'ticket_closed',
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
                        sender_type=SupportMessage.SenderType.ADMIN,
                        sender_user=getattr(request, 'admin_user', None),
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
                    user_unread_count=F('user_unread_count') + 1,
                    updated_at=timezone.now(),
                )

        ticket.refresh_from_db()
        if created:
            _audit(
                request,
                action='support.reply',
                entity_type='support_ticket',
                entity_id=ticket.id,
                metadata={'message_id': str(message_row.id)},
            )
        return Response(
            {
                'ok': True,
                'created': created,
                'ticket': _serialize_support_ticket(ticket),
                'message': _serialize_support_message(message_row),
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class AdminSupportTicketAssignView(APIView):
    def post(self, request, id, **kwargs):
        ticket = (
            SupportTicket.objects.select_related('user', 'assigned_admin')
            .filter(id=id)
            .first()
        )
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = SupportTicketAssignSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        admin_id = serializer.validated_data.get('admin_id')

        target_admin = getattr(request, 'admin_user', None)
        if admin_id:
            target_admin = User.objects.filter(
                id=admin_id,
                status=User.Status.ACTIVE,
                role__in=[User.Role.ADMIN, User.Role.MANAGER],
            ).first()
            if target_admin is None:
                return Response({'detail': 'Admin user not found.'}, status=status.HTTP_404_NOT_FOUND)

        ticket.assigned_admin = target_admin
        ticket.save(update_fields=['assigned_admin', 'updated_at'])
        _audit(
            request,
            action='support.assign',
            entity_type='support_ticket',
            entity_id=ticket.id,
            metadata={'assigned_admin_id': str(target_admin.id) if target_admin else None},
        )
        return Response({'ok': True, 'ticket': _serialize_support_ticket(ticket)})


class AdminSupportTicketStatusView(APIView):
    def post(self, request, id, **kwargs):
        ticket = (
            SupportTicket.objects.select_related('user', 'assigned_admin')
            .filter(id=id)
            .first()
        )
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = SupportTicketStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        next_status = serializer.validated_data['status']

        ticket.status = next_status
        ticket.closed_at = timezone.now() if next_status == SupportTicket.Status.CLOSED else None
        ticket.save(update_fields=['status', 'closed_at', 'updated_at'])
        _audit(
            request,
            action='support.status_update',
            entity_type='support_ticket',
            entity_id=ticket.id,
            metadata={'status': next_status},
        )
        return Response({'ok': True, 'ticket': _serialize_support_ticket(ticket)})


class AdminSupportTicketReadView(APIView):
    def post(self, request, id, **kwargs):
        ticket = (
            SupportTicket.objects.select_related('user', 'assigned_admin')
            .filter(id=id)
            .first()
        )
        if ticket is None:
            return Response({'detail': 'Ticket not found.'}, status=status.HTTP_404_NOT_FOUND)

        ticket.admin_unread_count = 0
        ticket.save(update_fields=['admin_unread_count', 'updated_at'])
        return Response({'ok': True, 'ticket': _serialize_support_ticket(ticket)})


class AdminSupportSummaryView(APIView):
    def get(self, request, **kwargs):
        queryset = SupportTicket.objects.all()
        open_count = queryset.filter(status=SupportTicket.Status.OPEN).count()
        in_progress_count = queryset.filter(status=SupportTicket.Status.IN_PROGRESS).count()
        unread_ticket_count = queryset.filter(admin_unread_count__gt=0).count()
        unread_message_count = int((queryset.aggregate(total=Sum('admin_unread_count')).get('total')) or 0)
        return Response(
            {
                'ok': True,
                'open_count': open_count,
                'in_progress_count': in_progress_count,
                'unread_ticket_count': unread_ticket_count,
                'unread_message_count': unread_message_count,
            }
        )


# 1) Auth
# Auth views implemented above.

# 2) Content / tracks
AdminTracksBulkDeleteView = _stub('content.tracks.bulk_delete')
AdminTracksBulkUpdateVisibilityView = _stub('content.tracks.bulk_update_visibility')

# 3) Playlists
AdminPlaylistReorderView = _stub('playlists.reorder')

# 4) Users & roles
# Users & roles views implemented above.

# 5) Premium
AdminPremiumSubscriptionsCollectionView = _stub('premium.subscriptions.collection')
AdminPremiumSubscriptionDetailView = _stub('premium.subscriptions.detail')
AdminPremiumPaymentsCollectionView = _stub('premium.payments.collection')
AdminPremiumPaymentDetailView = _stub('premium.payments.detail')

# 6) Recommendations
# Recommendation views implemented above.

# 7) Platform settings
# Platform settings view implemented above.

# 8) Analytics
# Analytics views implemented above.

# 9) Notifications
AdminNotificationsCollectionView = _stub('notifications.collection')
AdminNotificationsSendView = _stub('notifications.send')

# 10) System
AdminSystemHealthView = _stub('system.health')
AdminSystemStorageView = _stub('system.storage')
AdminSystemCacheView = _stub('system.cache')
