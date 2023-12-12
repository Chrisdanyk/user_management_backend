import factory
from faker import Faker

from user_management.apps.authentication.models import User

fake = Faker()


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User

    email = fake.email()
    name = fake.first_name()
    is_active = True


class AdminFactory(UserFactory):
    email = "admin@domain.test"
    is_superuser = True
    is_staff = True
