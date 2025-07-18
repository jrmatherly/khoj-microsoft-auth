# Generated by Django 5.1.10 on 2025-06-18 01:25

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('database', '0090_alter_khojuser_uuid'),
    ]

    operations = [
        migrations.CreateModel(
            name='MicrosoftUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sub', models.CharField(max_length=200)),
                ('email', models.CharField(max_length=200)),
                ('name', models.CharField(blank=True, default=None, max_length=200, null=True)),
                ('given_name', models.CharField(blank=True, default=None, max_length=200, null=True)),
                ('family_name', models.CharField(blank=True, default=None, max_length=200, null=True)),
                ('tenant_id', models.CharField(blank=True, default=None, max_length=200, null=True)),
                ('picture', models.CharField(default=None, max_length=200, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
