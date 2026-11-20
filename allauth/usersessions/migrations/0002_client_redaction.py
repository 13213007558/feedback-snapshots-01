from django.db import migrations, models


def redact_existing_sessions(apps, schema_editor):
    UserSession = apps.get_model("usersessions", "UserSession")
    # Import the live adapter rather than the historical model so that the
    # currently configured collection policy is applied to existing records.
    from allauth.usersessions.adapter import get_adapter

    adapter = get_adapter()
    for session in UserSession.objects.all().iterator():
        session.ip = adapter.redact_client_ip(session.ip)
        session.user_agent = adapter.redact_user_agent(session.user_agent)
        session.save(update_fields=["ip", "user_agent"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("usersessions", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usersession",
            name="ip",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="usersession",
            name="user_agent",
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.RunPython(redact_existing_sessions, noop),
    ]
