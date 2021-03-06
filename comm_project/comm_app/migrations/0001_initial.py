# Generated by Django 3.2.5 on 2021-07-16 15:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Person',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='auth.user')),
                ('rating', models.PositiveIntegerField(default=0)),
                ('invite_code', models.CharField(max_length=20)),
                ('verification_code', models.CharField(max_length=20)),
                ('inviter', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='invited_persons', to='comm_app.person')),
            ],
        ),
    ]
