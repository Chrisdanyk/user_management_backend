from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    CreateUserView,
    CustomAuthToken,
    DeleteUserView,
    GetUpdateUserProfileView,
    GetUsersView,
    GetUserView,
    LogOutView,
    MailConfirmationView,
    RegistrationView,
    RequestPasswordResetEmailView,
    ResetPasswordView,
    UpdateUserView,
    VerifyTokenView,
)

urlpatterns = [
    path('login', CustomAuthToken.as_view()),
    path('refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout', LogOutView.as_view()),
    path('users/create_user', CreateUserView.as_view()),
    path('users/get_users', GetUsersView.as_view()),
    path('users/get_user/<int:id>', GetUserView.as_view()),
    path('users/update_user/<int:id>', UpdateUserView.as_view()),
    path('users/delete_user/<int:id>', DeleteUserView.as_view()),
    path('email-verify', MailConfirmationView.as_view(),
         name='email-verify'),
    path('request-reset-email', RequestPasswordResetEmailView.as_view(),
         name='request-reset-email'),
    path('reset-password', ResetPasswordView.as_view(),
         name='reset-password'),
    path('verify-token/<uidb64>/<token>/', VerifyTokenView.as_view(),
         name='verify-token'),
    path('register', RegistrationView.as_view()),
    path('profile', GetUpdateUserProfileView.as_view()),
]
