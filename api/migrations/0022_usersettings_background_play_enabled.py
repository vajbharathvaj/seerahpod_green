from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0021_add_user_username'),
    ]

    operations = [
        migrations.AddField(
            model_name='usersettings',
            name='background_play_enabled',
            field=models.BooleanField(default=True),
        ),
    ]
