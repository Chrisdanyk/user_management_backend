from datetime import datetime, timedelta
from unittest.mock import patch

import jwt
from django.contrib.auth.hashers import check_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes
from django.utils.http import urlsafe_base64_encode
from pytest import mark, raises
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
)
from rest_framework_simplejwt.tokens import RefreshToken

from user_management.apps.authentication.models import User
from user_management.settings import REGISTRATION_JWT_KEY


def test_create_user_model(user_data):
    user = User.objects.create_user(**user_data)
    assert user.username == user_data['username']
    assert user.__str__() == user_data['email']
    assert user.id
    assert user.check_password(user_data['password'])


def test_create_user_model_with_used_email(user_data):
    User.objects.create_user(**user_data)
    with raises(ValueError):
        User.objects.create_user(**user_data)


def test_create_superuser(user_data):
    user = User.objects.create_superuser(**user_data)
    assert user.is_admin


@mark.parametrize("soft", [True, False])
def test_model_delete_user(soft, user_data):
    user = User.objects.create_user(**user_data)
    assert not user.deleted_at
    if soft:
        user.delete()
        assert user.deleted_at
        assert User.all_objects.filter(username=user_data['username']).first()
    else:
        user.hard_delete()
        assert not User.all_objects.filter(
            username=user_data['username']).first()
    assert not User.objects.filter(username=user_data['username']).first()


def test_successful_login(client, new_user):
    data = {'email': new_user.email, 'password': '9874Pass'}
    response = client.post('/auth/login', data=data)
    assert response.status_code == HTTP_200_OK
    assert response.data['data']['token']
    assert response.data['data']['email'] == new_user.email
    assert response.data['message'] == 'success'


def test_login_with_no_active(client, new_user_no_active):
    data = {'email': new_user_no_active.email,
            'password': '9874Pass'}
    response = client.post('/auth/login', data=data)
    assert response.status_code == HTTP_400_BAD_REQUEST


@mark.parametrize("wrong_attr", ['email', 'password'])
def test_invalid_credentials(wrong_attr, client, new_user):
    data = {
        'email': new_user.email,
        'password': '9874Pass',
        wrong_attr: 'me@ex.com'
    }
    response = client.post('/auth/login', data=data)
    assert response.status_code == HTTP_400_BAD_REQUEST
    assert (response.data['error'] == 'Invalid email or password'
            == response.data['message'])


def test_logout(client, new_user):
    refresh = RefreshToken.for_user(new_user)
    data = {'refresh_token': str(refresh)}
    response = client.post(
        '/auth/logout', data=data,)
    assert response.status_code == HTTP_200_OK
    assert response.data['message'] == 'success'


def test_logout_invalid_token(client):
    data = {'refresh_token': "Invalid token"}
    response = client.post(
        '/auth/logout', data=data,)
    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.data['message'] == 'Refresh token is invalid'


def test_create_user(client, create_user_data, admin_headers):
    response = client.post(
        '/auth/users/create_user', data=create_user_data, **admin_headers)
    assert response.status_code == HTTP_201_CREATED
    assert response.data['message'] == 'user created'


def test_create_user_with_user_role(client, create_user_data, headers):
    response = client.post(
        '/auth/users/create_user', data=create_user_data, **headers)
    assert response.status_code == HTTP_403_FORBIDDEN


def test_create_user_with_future_birth_day(
        client, create_user_data, admin_headers):
    create_user_data['birthday'] = '2024-02-02'
    response = client.post(
        '/auth/users/create_user', data=create_user_data, **admin_headers)
    assert response.status_code == HTTP_400_BAD_REQUEST


def test_create_user_existing_email(client, create_user_data,
                                    admin_headers, new_user):
    response = client.post(
        '/auth/users/create_user', data={
            **create_user_data,
            "email": new_user.email},
        **admin_headers)
    assert response.status_code == HTTP_400_BAD_REQUEST


def test_get_users(client, admin_headers):
    response = client.get('/auth/users/get_users', **admin_headers)
    assert response.status_code == HTTP_200_OK
    assert len(response.data) > 0


def test_get_users_with_user_role(client, headers):
    response = client.get('/auth/users/get_users', **headers)
    assert response.status_code == HTTP_403_FORBIDDEN


def test_get_user_by_id(client, admin_headers, new_user):
    response = client.get(
        f'/auth/users/get_user/{new_user.id}', **admin_headers)
    assert response.status_code == HTTP_200_OK
    assert response.data['data']['email'] == new_user.email


def test_get_user_by_id_with_user_role(client, headers, new_user):
    response = client.get(
        f'/auth/users/get_user/{new_user.id}', **headers)
    assert response.status_code == HTTP_403_FORBIDDEN


def test_update_user(client, admin_headers, create_user_data):
    user = User.objects.create_user(**create_user_data)
    data = {
        'email': 'newemail@barbatos.com',
        'password': '9874Pass',
    }
    response = client.put(
        f'/auth/users/update_user/{user.id}', data=data, **admin_headers)
    assert response.status_code == HTTP_200_OK
    assert response.data['message'] == 'success'
    assert response.data['data']['email'] == data['email']
    assert not User.objects.filter(email=create_user_data['email']).first()
    updated_user = User.objects.filter(email=data['email']).first()
    assert updated_user.check_password(data['password'])
    assert not check_password(
        create_user_data['password'], updated_user.password)


def test_update_user_with_user_role(client, headers, create_user_data):
    user = User.objects.create_user(**create_user_data)
    data = {
        'email': 'newemail@barbatos.com',
        'password': '9874Pass',
    }
    response = client.put(
        f'/auth/users/update_user/{user.id}', data=data, **headers)
    assert response.status_code == HTTP_403_FORBIDDEN


def test_delete_user(client, admin_headers, create_user_data):
    user = User.objects.create_user(**create_user_data)
    response = client.delete(
        f'/auth/users/delete_user/{user.id}', **admin_headers)
    assert response.status_code == HTTP_200_OK
    assert response.data['message'] == 'success'
    assert not User.objects.filter(id=user.id).first()


def test_delete_user_with_user_role(client, headers, create_user_data):
    user = User.objects.create_user(**create_user_data)
    response = client.delete(
        f'/auth/users/delete_user/{user.id}', **headers)
    assert response.status_code == HTTP_403_FORBIDDEN


@mark.parametrize("method", ["get"])
def test_get_unexisting_user_by_id(client, admin_headers,
                                   method):
    response = getattr(client, method)(
        '/auth/users/get_user/10000', **admin_headers)
    assert response.status_code == HTTP_404_NOT_FOUND
    assert response.data['message'] == 'User with id 10000 does not exist'
    assert response.data['error'] == 'User not found error'


@mark.parametrize("method", ["put"])
def test_update_unexisting_user_by_id(client, admin_headers,
                                      method):
    response = getattr(client, method)(
        '/auth/users/update_user/10000', **admin_headers)
    assert response.status_code == HTTP_404_NOT_FOUND
    assert response.data['message'] == 'User with id 10000 does not exist'
    assert response.data['error'] == 'User not found error'


@mark.parametrize("method", ["delete"])
def test_delete_unexisting_user_by_id(client, admin_headers,
                                      method):
    response = getattr(client, method)(
        '/auth/users/delete_user/10000', **admin_headers)
    assert response.status_code == HTTP_404_NOT_FOUND
    assert response.data['message'] == 'User with id 10000 does not exist'
    assert response.data['error'] == 'User not found error'


def test_register_user(client, register_user_data):
    with patch('user_management.utils.Utils.send_email.delay') as mock_task:
        response = client.post(
            '/auth/register', data=register_user_data)
        mock_task.assert_called_once()
        assert response.status_code == HTTP_201_CREATED
        assert response.data['message'] == 'user created'
        new_user = User.objects.filter(
            email=register_user_data['email']).first()
        assert new_user


def test_register_existing_user(client, register_user_data):
    User.objects.create_user(**register_user_data)
    response = client.post(
        '/auth/register', data=register_user_data)
    assert User.objects.count() == 1
    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.data['message'] == 'Email Already taken'
    assert User.objects.count() == 1


@mark.parametrize("jwt_key", [REGISTRATION_JWT_KEY, ''])
def test_verify_email(client, register_user_data, jwt_key):
    user = User.objects.create_user(**register_user_data)
    payload = {
        'exp': datetime.utcnow() + timedelta(minutes=10, seconds=0),
        'id': user.id
    }
    if jwt_key == REGISTRATION_JWT_KEY:
        token = jwt.encode(payload, key=jwt_key, algorithm="HS256")
        response = client.get(
            f'/auth/email-verify?token={token}')
        new_user = User.objects.get(pk=user.id)
        assert new_user
        assert response.status_code == HTTP_200_OK
        assert response.data['message'] == 'Successfully activated'
    else:
        token = jwt.encode(payload, key=jwt_key, algorithm="HS256")
        response = client.get(
            f'/auth/email-verify?token={token}')
        assert response.status_code == HTTP_400_BAD_REQUEST
        assert response.data['error'] == 'Invalid token'


def test_token_expired(client, register_user_data):
    user = User.objects.create_user(**register_user_data)
    payload = {
        'exp': datetime.utcnow() - timedelta(minutes=10, seconds=0),
        'id': user.id
    }

    token = jwt.encode(payload, key=REGISTRATION_JWT_KEY, algorithm="HS256")
    response = client.get(
        f'/auth/email-verify?token={token}')
    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.data['error'] == 'Token Expired'


def test_request_reset_email_not_existing_user(client):
    data = {
        'email': 'newemail@barbatos.com'
    }
    response = client.post(
        '/auth/request-reset-email', data=data)
    assert response.status_code == HTTP_404_NOT_FOUND
    assert response.data['message'] == 'User with this email is not found'


def test_request_reset_email_inactive_account(client, new_inactive_user):
    data = {
        'email': new_inactive_user.email
    }
    response = client.post(
        '/auth/request-reset-email', data=data)
    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.data['message'] == 'Account is not active'


def test_successfull_request_reset_email(client, reset_password_user_data,
                                         mocker):
    with patch('user_management.utils.Utils.send_email.delay') as mock_task:
        User.objects.create_user(**reset_password_user_data)
        data = {
            'email': reset_password_user_data['email']
        }
        response = client.post(
            '/auth/request-reset-email', data=data)
        mock_task.assert_called_once()
        assert User.objects.count() == 1
        assert response.status_code == HTTP_200_OK


def test_failure_verify_token_reset_password(client):
    response = client.get(
        '/auth/verify-token/Mdg/M3rjefln43D03rnlf/')
    assert response.status_code == HTTP_401_UNAUTHORIZED


def test_success_verify_token_reset_password(client, new_user):
    token = PasswordResetTokenGenerator().make_token(new_user)
    uidb64 = urlsafe_base64_encode(smart_bytes(new_user.id))
    response = client.get(
        f'/auth/verify-token/{uidb64}/{token}/')
    assert response.status_code == HTTP_200_OK


def test_verify_token_reset_password_with_different_users(
        client, new_user, another_user):
    token = PasswordResetTokenGenerator().make_token(new_user)
    uidb64 = urlsafe_base64_encode(smart_bytes(another_user.id))
    response = client.get(
        f'/auth/verify-token/{uidb64}/{token}/')
    assert response.status_code == HTTP_401_UNAUTHORIZED


def test_success_reset_password(client, new_user):
    token = PasswordResetTokenGenerator().make_token(new_user)
    uidb64 = urlsafe_base64_encode(smart_bytes(new_user.id))
    payload = {
        "uidb64": uidb64,
        "token": token,
        "password": "P4ssWo7ld"
    }
    response = client.post(
        '/auth/reset-password', data=payload)
    assert response.status_code == HTTP_200_OK


def test_failure_reset_password(client, new_user):
    uidb64 = urlsafe_base64_encode(smart_bytes(new_user.id))
    payload = {
        "uidb64": uidb64,
        "token": "54fvdniet4mfnvweisuf",
        "password": "P4ssWo7ld"
    }
    response = client.post(
        '/auth/reset-password', data=payload)
    assert response.status_code == HTTP_401_UNAUTHORIZED


def test_get_user_profile(client, new_user, headers):
    response = client.get('/auth/profile', **headers)
    assert response.status_code == HTTP_200_OK


def test_get_user_profile_no_auth(client, new_user):
    response = client.get('/auth/profile')
    assert response.status_code == HTTP_401_UNAUTHORIZED


def test_update_user_profile(client, headers, new_user):
    sample_data = {
        "name": "Chris"
    }
    response = client.put('/auth/profile',
                          data=sample_data,
                          **headers)
    assert response.status_code == HTTP_200_OK
    assert response.data['data']["name"] == "Chris"


def test_update_user_profile_with_no_auth(client, new_user):
    sample_data = {
        "name": "Chris"
    }
    response = client.put('/auth/profile',
                          data=sample_data)
    assert response.status_code == HTTP_401_UNAUTHORIZED
