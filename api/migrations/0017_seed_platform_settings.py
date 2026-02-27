from django.db import migrations


def seed_platform_settings(apps, schema_editor):
    PlatformSettings = apps.get_model('api', 'PlatformSettings')
    PlatformSettings.objects.get_or_create(
        singleton_key=1,
        defaults={
            'platform_visible': True,
            'maintenance_mode': False,
            'allow_public_signup': True,
            'require_email_verification': True,
            'allow_guest_access': False,
            'enable_email_notifications': True,
            'enable_push_notifications': True,
            'default_track_visibility': 'public',
            'max_upload_size_mb': 100,
            'allowed_audio_formats': [],
            'max_login_attempts': 5,
            'session_timeout_minutes': 60,
            'password_policy': {},
        },
    )


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0016_seed_recommendation_rules'),
    ]

    operations = [
        migrations.RunPython(seed_platform_settings, migrations.RunPython.noop),
    ]
