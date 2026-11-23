from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("axes", "0010_accessattemptexpiration"),
    ]

    operations = [
        migrations.AddField(
            model_name="accessattempt",
            name="subject",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text=(
                    "Registered subject identifier that owns this record. "
                    "Records written by pre-subject workers leave this empty."
                ),
                max_length=128,
                verbose_name="Subject",
            ),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="subject",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text=(
                    "Registered subject identifier that owns this record. "
                    "Records written by pre-subject workers leave this empty."
                ),
                max_length=128,
                verbose_name="Subject",
            ),
        ),
        migrations.AddField(
            model_name="accessfailurelog",
            name="subject",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text=(
                    "Registered subject identifier that owns this record. "
                    "Records written by pre-subject workers leave this empty."
                ),
                max_length=128,
                verbose_name="Subject",
            ),
        ),
        migrations.AddField(
            model_name="accessfailurelog",
            name="event_key",
            field=models.CharField(
                blank=True,
                help_text=(
                    "Idempotency key for the failed login event. Used to avoid recording "
                    "the same failure twice when it is written by more than one worker."
                ),
                max_length=64,
                null=True,
                unique=True,
                verbose_name="Failure event key",
            ),
        ),
        migrations.AlterUniqueTogether(
            name="accessattempt",
            unique_together={("subject", "username", "ip_address", "user_agent")},
        ),
        migrations.CreateModel(
            name="AccessFailureEvent",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "key",
                    models.CharField(
                        help_text=(
                            "Idempotency key for the failed login event. A failure is counted "
                            "once even when it is processed by multiple workers or backfilled."
                        ),
                        max_length=64,
                        unique=True,
                        verbose_name="Failure event key",
                    ),
                ),
                (
                    "subject",
                    models.CharField(
                        blank=True,
                        db_index=True,
                        default="",
                        max_length=128,
                        verbose_name="Subject",
                    ),
                ),
                (
                    "username",
                    models.CharField(
                        blank=True,
                        db_index=True,
                        max_length=255,
                        null=True,
                        verbose_name="Username",
                    ),
                ),
                (
                    "ip_address",
                    models.GenericIPAddressField(
                        blank=True,
                        db_index=True,
                        null=True,
                        verbose_name="IP Address",
                    ),
                ),
                (
                    "user_agent",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=255,
                        verbose_name="User Agent",
                    ),
                ),
                (
                    "attempt_time",
                    models.DateTimeField(
                        auto_now_add=True, verbose_name="Attempt Time"
                    ),
                ),
            ],
            options={
                "verbose_name": "access failure event",
                "verbose_name_plural": "access failure events",
                "ordering": ["-attempt_time"],
            },
        ),
    ]
