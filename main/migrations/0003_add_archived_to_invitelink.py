from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0002_alter_invitelink_options_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='invitelink',
            name='archived',
            field=models.BooleanField(default=False),
        ),
    ]
