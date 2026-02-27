from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_create_admin_sessions'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserSession',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('access_token', models.CharField(max_length=64, unique=True)),
                ('refresh_token', models.CharField(max_length=64, unique=True)),
                ('access_expires_at', models.DateTimeField()),
                ('refresh_expires_at', models.DateTimeField()),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'user',
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_sessions', to='api.user'),
                ),
            ],
            options={
                'db_table': 'user_sessions',
            },
        ),
        migrations.AddIndex(
            model_name='usersession',
            index=models.Index(fields=['access_token'], name='idx_user_sessions_access'),
        ),
        migrations.AddIndex(
            model_name='usersession',
            index=models.Index(fields=['refresh_token'], name='idx_user_sessions_refresh'),
        ),
        migrations.AddIndex(
            model_name='usersession',
            index=models.Index(fields=['user'], name='idx_user_sessions_user'),
        ),
    ]
