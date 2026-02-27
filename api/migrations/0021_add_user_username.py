from django.db import migrations, models


MAX_USERNAME_LENGTH = 150


def _sanitize_username_base(value):
    allowed = ''.join(ch for ch in (value or '').lower() if ch.isalnum() or ch in '._-')
    allowed = allowed.strip('._-')
    if not allowed:
        return 'user'
    return allowed[:140]


def backfill_usernames(apps, schema_editor):
    User = apps.get_model('api', 'User')

    existing = set()
    for raw in User.objects.exclude(username__isnull=True).exclude(username='').values_list('username', flat=True):
        existing.add((raw or '').strip().lower())

    users = User.objects.all().order_by('created_at', 'id')
    for user in users:
        current = (getattr(user, 'username', '') or '').strip().lower()
        if current:
            base = current
        else:
            email = (getattr(user, 'email', '') or '').strip().lower()
            email_local = email.split('@', 1)[0] if '@' in email else email
            base = _sanitize_username_base(email_local)

        candidate = base
        suffix = 2
        while candidate in existing:
            suffix_text = f'_{suffix}'
            candidate = f'{base[:MAX_USERNAME_LENGTH - len(suffix_text)]}{suffix_text}'
            suffix += 1

        User.objects.filter(pk=user.pk).update(username=candidate)
        existing.add(candidate)


def noop_reverse(apps, schema_editor):
    # Do not remove usernames on rollback.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0020_create_playlist_click_events'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='username',
            field=models.CharField(blank=True, max_length=150, null=True),
        ),
        migrations.RunPython(backfill_usernames, noop_reverse),
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=150, unique=True),
        ),
    ]
