from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0019_create_user_sessions'),
    ]

    operations = [
        migrations.CreateModel(
            name='PlaylistClickEvent',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('source', models.CharField(choices=[('library', 'library'), ('home', 'home'), ('search', 'search')], default='library', max_length=20)),
                ('device_platform', models.CharField(choices=[('android', 'android'), ('ios', 'ios')], default='android', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('playlist', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='click_events', to='api.playlist')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='playlist_click_events', to='api.user')),
            ],
            options={
                'db_table': 'playlist_click_events',
            },
        ),
        migrations.AddIndex(
            model_name='playlistclickevent',
            index=models.Index(fields=['playlist'], name='idx_playlist_clicks_playlist'),
        ),
        migrations.AddIndex(
            model_name='playlistclickevent',
            index=models.Index(fields=['created_at'], name='idx_playlist_clicks_created'),
        ),
        migrations.AddIndex(
            model_name='playlistclickevent',
            index=models.Index(fields=['source'], name='idx_playlist_clicks_source'),
        ),
        migrations.AddIndex(
            model_name='playlistclickevent',
            index=models.Index(fields=['user'], name='idx_playlist_clicks_user'),
        ),
    ]
