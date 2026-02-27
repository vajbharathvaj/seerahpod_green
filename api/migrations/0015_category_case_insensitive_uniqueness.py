from django.db import migrations, models
from django.db.models.functions import Lower


def deduplicate_categories_case_insensitive(apps, schema_editor):
    Category = apps.get_model('api', 'Category')
    Track = apps.get_model('api', 'Track')

    categories = list(Category.objects.all().order_by('created_at', 'id'))
    canonical_by_key = {}

    for category in categories:
        key = category.name.strip().lower()
        if key not in canonical_by_key:
            canonical_by_key[key] = category
            continue

        canonical = canonical_by_key[key]
        Track.objects.filter(category_id=category.id).update(category_id=canonical.id)
        category.delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ('api', '0014_seed_default_categories'),
    ]

    operations = [
        migrations.RunPython(deduplicate_categories_case_insensitive, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name='category',
            constraint=models.UniqueConstraint(Lower('name'), name='uq_categories_name_ci'),
        ),
    ]
