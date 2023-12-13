# User Management Backend System

The system is responsible for managing user data, including:

- Creating new users
- Retrieving user details
- Updating user information
- Deleting users

# How to run the project

- Create a virtual environement using this command: `python3 -m venv venv`
- Activate the environement with `source venv/bin/activate`
- Install the dependencies with `pip install -r requirements.txt`
- Create a `.env` in the root folder and populate with values needed,
  here is an example:

```
SECRET_KEY=secret-key-should-be-changed
JWT_SECRET_KEY=secret-key-should-be-changed
REGISTRATION_JWT_KEY=secret-key-should-be-changed
ACCESS_TOKEN_LIFETIME_UNIT=days
ACCESS_TOKEN_LIFETIME=1
TOKEN_LIFETIME_UNIT=days
TOKEN_LIFETIME=1
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=http://localhost,http://127.0.0.1
HOSTNAME=localhost
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST='smtp.gmail.com'
EMAIL_HOST_USER=an_email_here
EMAIL_HOST_PASSWORD=a_password_here
EMAIL_USE_TLS=True
EMAIL_PORT=587
DEFAULT_FROM_EMAIL=an_email_here
FRONT_END_URL=https://frontend.com
SWAGGER_URL=http://127.0.0.1:8000
```

- Apply migrations with `python3 manage.py migrate`
- Create an initial user with `python3 manage.py createsuperuser`. You'll authenticate as that user.
- Start the app with `python3 manage.py runserver` and access your app on `http://localhost:8000` where you will land on the api documentation.

- Start an other tab inside your terminal to run celery tasks as follow (used for asynchronous sending of emails):
  `celery -A user_management worker -l INFO`

# Run Tests

Tests can be run by using the `tox` command inside your terminal, at the end of running tests you will be presented results of the project coverage.

# API Documentation

The documentation should be accessible at the url `http://localhost:8000`
Note that The System accepts 2 roles the admin `ADMIN` and regular user `USER`.
With the created superuser which is also an admin, you can call the login endpoint by passing the `email` and `password` into the body.
If the credentials are correct, you will be presented with a response containing the `token`, Please copy its value and hit the `authorize` button which is on the upper right of your page, you will be presented to a modal where you need to insert the token.
Please Bear in mind that it's a bearer token, you need to pass the token in that format: `Bearer xxxxxxxx` then hit authorize.
The Admin Role can perform all the operations(crud on users) while the User Role has limited permissions ( can get and modify his profile)
