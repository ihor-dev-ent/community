from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


# Create your models here.
class Person(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE,
                                primary_key=True)
    rating = models.PositiveIntegerField(default=0)
    inviter = models.ForeignKey(
        'self', blank=True, null=True,
        related_name='invited_persons', on_delete=models.SET_NULL)
    invite_code = models.CharField(max_length=20)
    verification_code = models.CharField(max_length=20)

    def __str__(self):
        return (self.user.username + " ( rating: " +
                str(self.rating) + ", invited: " +
                str(self.invited_persons) + ", vcode: " +
                self.invite_code + " )")


@receiver(post_save, sender=User)
def create_user_person(sender, instance, created, **kwargs):
    if created:
        Person.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_person(sender, instance, **kwargs):
    instance.person.save()
