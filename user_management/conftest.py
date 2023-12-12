from faker import Faker
from pytest import fixture
from pytest_factoryboy import register
from rest_framework_simplejwt.tokens import RefreshToken

from user_management.apps.authentication.models import User
from user_management.factories import AdminFactory, UserFactory

fake = Faker()

for fact in [
    UserFactory, AdminFactory,
]:
    register(fact)

TEST_DATA_RANGE = {'min_value': 50, 'max_value': 80}


@fixture(autouse=True)
def database(db):
    pass


@fixture(scope='function')
def new_user(user_factory):
    user = user_factory.create(role=User.Role.USER)
    user.set_password('9874Pass')
    user.save()
    return user


@fixture(scope='function')
def another_user(user_factory):
    user = user_factory.create(
        role=User.Role.USER,
        email='dd@domain.test')
    user.set_password('9874Pass')
    user.save()
    return user


@fixture(scope='function')
def new_user_no_active(user_factory):
    user = user_factory.create(is_active=False)
    user.set_password('9874Pass')
    user.save()
    return user


@fixture
def headers(new_user):
    token = RefreshToken.for_user(new_user)
    access_token = str(token.access_token)
    return {
        'HTTP_AUTHORIZATION': f'Bearer {access_token}',
        'content_type': 'application/json'
    }


@fixture(scope='module')
def user_data():
    fake = Faker()
    return {
        "password": fake.password(),
        "username": fake.first_name(),
        "email": fake.email(),
        "birthday": "1993-02-02"
    }


@fixture(scope='module')
def create_user_data():
    fake = Faker()
    return {
        "password": fake.password(),
        "username": fake.first_name(),
        "email": fake.email(),
        "name": fake.first_name(),
        "birthday": "1993-02-02",
        "role": "US"
    }


@fixture(scope='function')
def admin_user(admin_factory):
    user = admin_factory.create()
    user.set_password('9874Pass')
    user.role = User.Role.ADMIN
    user.save()
    return user


@fixture
def admin_headers(admin_user):
    token = RefreshToken.for_user(admin_user)
    access_token = str(token.access_token)
    return {
        'HTTP_AUTHORIZATION': f'Bearer {access_token}',
        'content_type': 'application/json'
    }


@fixture
def another_user_headers(another_user):
    token = RefreshToken.for_user(another_user)
    access_token = str(token.access_token)
    return {
        'HTTP_AUTHORIZATION': f'Bearer {access_token}',
        'content_type': 'application/json'
    }


@fixture(scope='module')
def register_user_data(create_user_data):
    return {
        **create_user_data,
        "birthday": "1993-02-02",
        "is_active": False,
        "role": User.Role.USER
    }


@fixture(scope='module')
def reset_password_user_data(create_user_data):
    fake = Faker()
    return {
        **create_user_data,
        "birthday": fake.date(),
        "is_active": True
    }


@fixture(scope='function')
def new_inactive_user(user_factory):
    user = user_factory.create()
    user.set_password('9874Pass')
    user.is_active = False
    user.save()
    return user
