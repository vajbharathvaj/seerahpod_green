import uuid

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower


class User(models.Model):
    class AuthProvider(models.TextChoices):
        EMAIL = 'email', 'email'
        GOOGLE = 'google', 'google'
        APPLE = 'apple', 'apple'

    class Role(models.TextChoices):
        USER = 'user', 'user'
        ADMIN = 'admin', 'admin'
        MANAGER = 'manager', 'manager'

    class Status(models.TextChoices):
        ACTIVE = 'active', 'active'
        BLOCKED = 'blocked', 'blocked'
        DELETED = 'deleted', 'deleted'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, max_length=255)
    username = models.CharField(max_length=150, unique=True)
    password_hash = models.TextField(null=True, blank=True)
    auth_provider = models.CharField(max_length=20, choices=AuthProvider.choices)
    provider_id = models.TextField(null=True, blank=True)
    is_email_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.USER)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE, db_index=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'users'

    @staticmethod
    def _sanitize_username_base(value: str) -> str:
        allowed = ''.join(ch for ch in (value or '').lower() if ch.isalnum() or ch in '._-')
        allowed = allowed.strip('._-')
        return allowed[:140]

    def _generate_unique_username(self) -> str:
        email_local = (self.email or '').split('@', 1)[0]
        base = self._sanitize_username_base(email_local)
        if not base:
            base = 'user'
        candidate = base
        suffix = 2
        lookup = User.objects.all()
        if self.pk:
            lookup = lookup.exclude(pk=self.pk)
        while lookup.filter(username__iexact=candidate).exists():
            suffix_text = f'_{suffix}'
            candidate = f'{base[:150 - len(suffix_text)]}{suffix_text}'
            suffix += 1
        return candidate

    def save(self, *args, **kwargs):
        self.email = (self.email or '').strip().lower()
        if self.username:
            self.username = self._sanitize_username_base(self.username.strip())
        if not self.username:
            self.username = self._generate_unique_username()
        super().save(*args, **kwargs)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    display_name = models.CharField(max_length=150)
    avatar_url = models.TextField(null=True, blank=True)
    bio = models.TextField(null=True, blank=True)
    country = models.CharField(max_length=100)
    language = models.CharField(max_length=50)
    timezone = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_profiles'


class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    playback_speed = models.FloatField(default=1.0)
    background_play_enabled = models.BooleanField(default=True)
    notifications_enabled = models.BooleanField(default=True)
    silent_mode = models.BooleanField(default=False)
    analytics_enabled = models.BooleanField(default=True)
    personalization_enabled = models.BooleanField(default=True)
    dark_mode = models.BooleanField(default=True)
    auto_play_next = models.BooleanField(default=True)
    download_over_wifi_only = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_settings'


class UserDevice(models.Model):
    class Platform(models.TextChoices):
        ANDROID = 'android', 'android'
        IOS = 'ios', 'ios'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_token = models.TextField(unique=True)
    platform = models.CharField(max_length=20, choices=Platform.choices)
    device_model = models.CharField(max_length=100, null=True, blank=True)
    app_version = models.CharField(max_length=50, null=True, blank=True)
    os_version = models.CharField(max_length=50, null=True, blank=True)
    last_active_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_devices'
        indexes = [
            models.Index(fields=['user']),
        ]


class UserNotification(models.Model):
    class Type(models.TextChoices):
        PODCAST = 'podcast', 'podcast'
        PREMIUM = 'premium', 'premium'
        RECOMMENDATION = 'recommendation', 'recommendation'
        SYSTEM = 'system', 'system'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=30, choices=Type.choices, default=Type.SYSTEM)
    title = models.CharField(max_length=255)
    message = models.TextField()
    action_label = models.CharField(max_length=80, null=True, blank=True)
    action_route = models.CharField(max_length=255, null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_notifications'
        indexes = [
            models.Index(fields=['user', 'created_at'], name='idx_user_notif_user_created'),
            models.Index(fields=['user', 'read_at'], name='idx_user_notif_user_read'),
        ]


class Subscription(models.Model):
    class Provider(models.TextChoices):
        RAZORPAY = 'razorpay', 'razorpay'
        APPLE_IAP = 'apple_iap', 'apple_iap'
        GOOGLE_IAP = 'google_iap', 'google_iap'

    class Status(models.TextChoices):
        TRIAL = 'trial', 'trial'
        ACTIVE = 'active', 'active'
        EXPIRED = 'expired', 'expired'
        CANCELLED = 'cancelled', 'cancelled'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    plan_name = models.CharField(max_length=100)
    provider = models.CharField(max_length=20, choices=Provider.choices)
    status = models.CharField(max_length=20, choices=Status.choices, db_index=True)
    started_at = models.DateTimeField()
    ends_at = models.DateTimeField()
    auto_renew = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'subscriptions'
        indexes = [
            models.Index(fields=['user']),
        ]


class SupportTicket(models.Model):
    class Status(models.TextChoices):
        OPEN = 'open', 'open'
        IN_PROGRESS = 'in_progress', 'in_progress'
        CLOSED = 'closed', 'closed'

    class Priority(models.TextChoices):
        LOW = 'low', 'low'
        MEDIUM = 'medium', 'medium'
        HIGH = 'high', 'high'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    subject = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    priority = models.CharField(max_length=20, choices=Priority.choices, default=Priority.MEDIUM)
    last_message_at = models.DateTimeField(null=True, blank=True, db_index=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    assigned_admin = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_support_tickets',
    )
    user_unread_count = models.PositiveIntegerField(default=0)
    admin_unread_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'support_tickets'
        indexes = [
            models.Index(fields=['user', 'status', 'updated_at'], name='idx_sptkt_user_status_upd'),
            models.Index(fields=['status', 'priority', 'last_message_at'], name='idx_sptkt_status_prio_last'),
        ]


class SupportMessage(models.Model):
    class SenderType(models.TextChoices):
        USER = 'user', 'user'
        ADMIN = 'admin', 'admin'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ticket = models.ForeignKey(SupportTicket, on_delete=models.CASCADE)
    sender_type = models.CharField(max_length=10, choices=SenderType.choices)
    sender_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='support_messages_sent',
    )
    message = models.TextField()
    client_message_id = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    attachment_url = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'support_messages'
        constraints = [
            models.UniqueConstraint(
                fields=['ticket', 'client_message_id'],
                condition=models.Q(client_message_id__isnull=False),
                name='uq_spmsg_ticket_client_msg',
            ),
        ]
        indexes = [
            models.Index(fields=['ticket', 'created_at'], name='idx_spmsg_ticket_created'),
        ]


class Category(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'categories'
        constraints = [
            models.UniqueConstraint(Lower('name'), name='uq_categories_name_ci'),
        ]


class PremiumSettings(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    singleton_key = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    subscription_price = models.DecimalField(max_digits=10, decimal_places=2)
    free_trial_days = models.IntegerField(default=0)
    auto_lock_new_content = models.BooleanField(default=False)
    allow_gifting = models.BooleanField(default=False)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='premium_settings_updates')
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if PremiumSettings.objects.exclude(pk=self.pk).exists():
            raise ValidationError('Only one PremiumSettings row is allowed.')
        self.singleton_key = 1
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'premium_settings'
        constraints = [
            models.CheckConstraint(
                check=models.Q(singleton_key=1),
                name='chk_premium_settings_singleton_key',
            ),
        ]


class RecommendationRule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule_key = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    priority = models.IntegerField()
    is_active = models.BooleanField(default=True)
    config = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'recommendation_rules'
        indexes = [
            models.Index(fields=['is_active', 'priority'], name='idx_reco_rules_active_priority'),
        ]


class PlatformSettings(models.Model):
    class TrackVisibility(models.TextChoices):
        PUBLIC = 'public', 'public'
        PREMIUM = 'premium', 'premium'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    singleton_key = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)

    # Platform controls
    platform_visible = models.BooleanField(default=True)
    maintenance_mode = models.BooleanField(default=False)
    allow_public_signup = models.BooleanField(default=True)
    require_email_verification = models.BooleanField(default=True)
    allow_guest_access = models.BooleanField(default=False)
    display_advertisement = models.BooleanField(default=False)

    # Notification config
    enable_email_notifications = models.BooleanField(default=True)
    enable_push_notifications = models.BooleanField(default=True)
    email_provider_config = models.JSONField(null=True, blank=True)
    push_provider_config = models.JSONField(null=True, blank=True)

    # Content policy config
    default_track_visibility = models.CharField(
        max_length=20,
        choices=TrackVisibility.choices,
        default=TrackVisibility.PUBLIC,
    )
    max_upload_size_mb = models.PositiveIntegerField(default=100)
    allowed_audio_formats = models.JSONField(default=list, blank=True)

    # Security controls
    max_login_attempts = models.PositiveSmallIntegerField(default=5)
    session_timeout_minutes = models.PositiveIntegerField(default=60)
    password_policy = models.JSONField(default=dict, blank=True)

    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='platform_settings_updates',
    )
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if PlatformSettings.objects.exclude(pk=self.pk).exists():
            raise ValidationError('Only one PlatformSettings row is allowed.')
        self.singleton_key = 1
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'platform_settings'
        constraints = [
            models.CheckConstraint(
                check=models.Q(singleton_key=1),
                name='chk_platform_settings_singleton_key',
            ),
        ]


class AdminAuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_audit_logs')
    action = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=50)
    entity_id = models.UUIDField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'admin_audit_logs'


class AdminSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_sessions')
    access_token = models.CharField(max_length=64, unique=True)
    refresh_token = models.CharField(max_length=64, unique=True)
    access_expires_at = models.DateTimeField()
    refresh_expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'admin_sessions'
        indexes = [
            models.Index(fields=['access_token'], name='idx_admin_sessions_access'),
            models.Index(fields=['refresh_token'], name='idx_admin_sessions_refresh'),
            models.Index(fields=['user'], name='idx_admin_sessions_user'),
        ]


class UserSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_sessions')
    access_token = models.CharField(max_length=64, unique=True)
    refresh_token = models.CharField(max_length=64, unique=True)
    access_expires_at = models.DateTimeField()
    refresh_expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_sessions'
        indexes = [
            models.Index(fields=['access_token'], name='idx_user_sessions_access'),
            models.Index(fields=['refresh_token'], name='idx_user_sessions_refresh'),
            models.Index(fields=['user'], name='idx_user_sessions_user'),
        ]


class UserMfaTotp(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='mfa_totp')
    secret = models.CharField(max_length=128)
    is_enabled = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_mfa_totp'


class UserMfaBackupCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_backup_codes')
    code_hash = models.TextField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_mfa_backup_codes'
        indexes = [
            models.Index(fields=['user', 'used_at'], name='idx_mfa_backup_user_used'),
        ]


class UserDownload(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    track = models.ForeignKey('Track', on_delete=models.SET_NULL, null=True, blank=True)
    device_id = models.CharField(max_length=255, null=True, blank=True)
    downloaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_downloads'
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'track', 'device_id'],
                name='uq_user_downloads_user_track_device',
            ),
        ]


class Track(models.Model):
    class Status(models.TextChoices):
        DRAFT = 'draft', 'draft'
        PUBLISHED = 'published', 'published'
        ARCHIVED = 'archived', 'archived'

    class Visibility(models.TextChoices):
        PUBLIC = 'public', 'public'
        HIDDEN = 'hidden', 'hidden'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    speaker_name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    audio_url = models.TextField(blank=True, default='')
    video_url = models.TextField(null=True, blank=True)
    cover_image_url = models.TextField(null=True, blank=True)
    duration_seconds = models.IntegerField()
    category = models.ForeignKey('Category', on_delete=models.SET_NULL, null=True, blank=True)
    is_premium = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    visibility = models.CharField(max_length=20, choices=Visibility.choices, default=Visibility.PUBLIC)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_tracks')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'tracks'


class TrackCoverImage(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    track = models.ForeignKey(Track, on_delete=models.CASCADE, related_name='cover_images')
    image_url = models.TextField()
    position = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'track_cover_images'
        constraints = [
            models.UniqueConstraint(fields=['track', 'position'], name='uq_track_covimg_track_pos'),
        ]
        indexes = [
            models.Index(fields=['track', 'position'], name='idx_track_covimg_track_pos'),
        ]


class Playlist(models.Model):
    class Visibility(models.TextChoices):
        PUBLIC = 'public', 'public'
        PREMIUM = 'premium', 'premium'
        HIDDEN = 'hidden', 'hidden'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    cover_image_url = models.TextField(null=True, blank=True)
    visibility = models.CharField(max_length=20, choices=Visibility.choices, default=Visibility.PUBLIC)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='playlists_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'playlists'
        constraints = [
            models.CheckConstraint(
                check=models.Q(visibility__in=['public', 'premium', 'hidden']),
                name='chk_playlist_visibility',
            ),
        ]
        indexes = [
            models.Index(fields=['visibility'], name='idx_playlists_visibility'),
            models.Index(fields=['created_at'], name='idx_playlists_created_at'),
            models.Index(fields=['is_active'], name='idx_playlists_active'),
            models.Index(
                fields=['id'],
                condition=models.Q(deleted_at__isnull=True),
                name='idx_playlists_active_only',
            ),
        ]


class PlaylistTrack(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    playlist = models.ForeignKey(Playlist, on_delete=models.CASCADE)
    track = models.ForeignKey(Track, on_delete=models.CASCADE)
    position = models.IntegerField()
    added_by = models.ForeignKey(User, on_delete=models.DO_NOTHING, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'playlist_tracks'
        constraints = [
            models.UniqueConstraint(fields=['playlist', 'track'], name='uq_playlist_tracks_playlist_track'),
            models.UniqueConstraint(fields=['playlist', 'position'], name='uq_playlist_tracks_playlist_position'),
        ]
        indexes = [
            models.Index(fields=['playlist'], name='idx_playlist_tracks_playlist'),
            models.Index(fields=['track'], name='idx_playlist_tracks_track'),
        ]


class PlayEvent(models.Model):
    class Source(models.TextChoices):
        HOME = 'home', 'home'
        SEARCH = 'search', 'search'
        PLAYLIST = 'playlist', 'playlist'
        RECOMMENDED = 'recommended', 'recommended'

    class DevicePlatform(models.TextChoices):
        ANDROID = 'android', 'android'
        IOS = 'ios', 'ios'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    track = models.ForeignKey(Track, on_delete=models.CASCADE)
    session_id = models.UUIDField(default=uuid.uuid4)
    played_seconds = models.IntegerField()
    total_duration = models.IntegerField()
    completion_percentage = models.FloatField()
    source = models.CharField(max_length=20, choices=Source.choices)
    device_platform = models.CharField(max_length=20, choices=DevicePlatform.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'play_events'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['track']),
            models.Index(fields=['created_at']),
        ]


class UserTrackLike(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='liked_tracks')
    track = models.ForeignKey(Track, on_delete=models.CASCADE, related_name='liked_by_users')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_liked_tracks'
        constraints = [
            models.UniqueConstraint(fields=['user', 'track'], name='uq_ulikes_user_track'),
        ]
        indexes = [
            models.Index(fields=['user', 'created_at'], name='idx_ulikes_user_created'),
            models.Index(fields=['track'], name='idx_ulikes_track'),
        ]


class PlaylistClickEvent(models.Model):
    class Source(models.TextChoices):
        LIBRARY = 'library', 'library'
        HOME = 'home', 'home'
        SEARCH = 'search', 'search'

    class DevicePlatform(models.TextChoices):
        ANDROID = 'android', 'android'
        IOS = 'ios', 'ios'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    playlist = models.ForeignKey(Playlist, on_delete=models.CASCADE, related_name='click_events')
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='playlist_click_events',
    )
    source = models.CharField(max_length=20, choices=Source.choices, default=Source.LIBRARY)
    device_platform = models.CharField(
        max_length=20,
        choices=DevicePlatform.choices,
        default=DevicePlatform.ANDROID,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'playlist_click_events'
        indexes = [
            models.Index(fields=['playlist'], name='idx_playlist_clicks_playlist'),
            models.Index(fields=['created_at'], name='idx_playlist_clicks_created'),
            models.Index(fields=['source'], name='idx_playlist_clicks_source'),
            models.Index(fields=['user'], name='idx_playlist_clicks_user'),
        ]


class SearchLog(models.Model):
    class SourceScreen(models.TextChoices):
        HOME = 'home', 'home'
        SEARCH_PAGE = 'search_page', 'search_page'

    class DevicePlatform(models.TextChoices):
        ANDROID = 'android', 'android'
        IOS = 'ios', 'ios'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    query = models.TextField()
    normalized_query = models.TextField()
    result_count = models.IntegerField()
    source_screen = models.CharField(max_length=20, choices=SourceScreen.choices)
    device_platform = models.CharField(max_length=20, choices=DevicePlatform.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'search_logs'
        indexes = [
            models.Index(fields=['normalized_query']),
            models.Index(fields=['created_at']),
        ]
