from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0025_usermfabackupcode_usermfatotp_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='track',
            name='audio_url',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='track',
            name='video_url',
            field=models.TextField(blank=True, null=True),
        ),
    ]
