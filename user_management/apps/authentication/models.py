from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _

from user_management.manager import SoftDeleteManager
from user_management.model import SoftDeleteModel


class UserManager(BaseUserManager, SoftDeleteManager):
    def create_user(self, **kwargs):
        """
        Creates and saves a User with the given credentials.
        """
        email = kwargs.pop("email")
        password = kwargs.pop("password")

        user = self.model.objects.filter(email=email).first()

        if user:
            raise ValueError("User with given email already exists")

        user = self.model(email=self.normalize_email(email), **kwargs)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, **kwargs):
        user = self.create_user(**kwargs)
        user.is_active = user.is_admin = user.is_staff \
            = user.is_superuser = True
        user.role = User.Role.ADMIN
        user.save(using=self._db)
        return user


class User(SoftDeleteModel, AbstractBaseUser, PermissionsMixin):

    class Role(models.TextChoices):
        ADMIN = 'AD', _('Admin')
        USER = 'US', _('User')

    username = models.CharField(max_length=100, null=True, blank=True)
    name = models.CharField(max_length=100, null=True, blank=True)
    email = models.EmailField(max_length=100, unique=True, null=False)
    password = models.CharField(max_length=100)
    birthday = models.DateField(auto_now=False, null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    role = models.CharField(
        max_length=2,
        choices=Role.choices,
        default=Role.USER,
        null=False
    )

    USERNAME_FIELD = "email"
    objects = UserManager()
    all_objects = UserManager(alive_only=False)

    def __str__(self):
        return self.email

    @property
    def role_(self) -> Role:
        return self.Role(self.role)
