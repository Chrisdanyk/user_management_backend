from django.contrib import admin

from user_management.apps.authentication.models import User

admin.site.register(User)
