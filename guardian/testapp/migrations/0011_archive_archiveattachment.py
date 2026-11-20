# Generated migration for the inline admin parent/child permissions tests

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("testapp", "0010_textpkmodel"),
    ]

    operations = [
        migrations.CreateModel(
            name="Archive",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=128)),
            ],
        ),
        migrations.CreateModel(
            name="ArchiveAttachment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=128)),
                ("body", models.TextField(blank=True)),
                (
                    "archive",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="attachments",
                        to="testapp.archive",
                    ),
                ),
            ],
        ),
    ]
