from django.db import migrations


DEFAULT_RULES = [
    {
        'rule_key': 'top_played',
        'name': 'Top Played',
        'description': 'Show most played tracks in the configured recent window.',
        'priority': 1,
        'is_active': True,
        'config': {'days': 7, 'limit': 10},
    },
    {
        'rule_key': 'recently_added',
        'name': 'Recently Added',
        'description': 'Highlight newly uploaded tracks.',
        'priority': 2,
        'is_active': True,
        'config': {'limit': 10},
    },
    {
        'rule_key': 'based_on_history',
        'name': 'Based on History',
        'description': 'Recommend tracks based on user listening history.',
        'priority': 3,
        'is_active': True,
        'config': {'min_listens': 3, 'limit': 10},
    },
]


def seed_rules(apps, schema_editor):
    RecommendationRule = apps.get_model('api', 'RecommendationRule')

    aliases = {
        'recent': 'recently_added',
        'category_based': 'based_on_history',
    }
    for old_key, new_key in aliases.items():
        old_rule = RecommendationRule.objects.filter(rule_key=old_key).first()
        if old_rule is not None and not RecommendationRule.objects.filter(rule_key=new_key).exists():
            old_rule.rule_key = new_key
            old_rule.save(update_fields=['rule_key', 'updated_at'])

    for rule in DEFAULT_RULES:
        RecommendationRule.objects.get_or_create(
            rule_key=rule['rule_key'],
            defaults={
                'name': rule['name'],
                'description': rule['description'],
                'priority': rule['priority'],
                'is_active': rule['is_active'],
                'config': rule['config'],
            },
        )


def unseed_rules(apps, schema_editor):
    RecommendationRule = apps.get_model('api', 'RecommendationRule')
    RecommendationRule.objects.filter(
        rule_key__in=['top_played', 'recently_added', 'based_on_history'],
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0015_category_case_insensitive_uniqueness'),
    ]

    operations = [
        migrations.RunPython(seed_rules, unseed_rules),
    ]
