from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_cas_ng', '0003_auto_20210813_1226'),
    ]

    operations = [
        migrations.CreateModel(
            name='SessionServiceGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_key', models.CharField(db_index=True, max_length=736)),
                ('service', models.CharField(max_length=1024)),
            ],
            options={
                'unique_together': {('session_key', 'service')},
            },
        ),
    ]
