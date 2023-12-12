# Create your views here.
from datetime import datetime, timedelta

import jwt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import Http404
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, mixins, status
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from user_management.apps.authentication.models import User
from user_management.exception_handler import (
    BadReqException,
    InvalidTokenException,
    NotFoundException,
)
from user_management.permissions import AdminPermission
from user_management.settings import (
    FRONT_END_URL, HOSTNAME, REGISTRATION_JWT_KEY)
from user_management.utils import Utils

from .serializers import (
    LoginSerializer,
    LogOutSerializer,
    SetNewPasswordSerializer,
    UserMailSerializer,
    UserRegistrationSerializer,
    UserSerializer,
    VerifyTokenSerializer,
)


class CustomAuthToken(APIView):
    serializer_class = LoginSerializer

    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = User.objects.filter(email=email).first()
        if user and not user.is_active:
            raise BadReqException(message="Account is not active")

        if not user or not user.check_password(password):
            raise BadReqException(message="Invalid email or password")

        refresh = RefreshToken.for_user(user)

        return Response({
            'message': 'success',
            'data': {
                'token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user_id': user.pk,
                'email': user.email,
            },
        })


class LogOutView(APIView):
    @swagger_auto_schema(request_body=LogOutSerializer)
    def post(self, request):
        serializer = LogOutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh = RefreshToken(request.data['refresh_token'])
            refresh.blacklist()
        except TokenError:
            raise BadReqException(
                message="Refresh token is invalid",
                error="Invalid refresh token error"
            )

        return Response({"message": "success"})


class BaseUserView(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response,
                                             *args, **kwargs)
        if response.status_code in [status.HTTP_200_OK,
                                    status.HTTP_201_CREATED]:
            response.data = {
                "message": "success",
                "data": response.data
            }

        return response

    def handle_exception(self, exc):
        if isinstance(exc, Http404):
            return Response(
                {"message": f"User with id {self.kwargs['id']} does not exist",
                 "error": "User not found error"},
                status=status.HTTP_404_NOT_FOUND)
        return super().handle_exception(exc)


class CreateUserView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [AdminPermission]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.validated_data['is_active'] = True
        new_user = User(**serializer.validated_data)
        password = make_password(serializer.validated_data['password'])
        new_user.password = password
        new_user.save()
        return Response({
            'message': 'user created',
        }, status=status.HTTP_201_CREATED)


class GetUsersView(mixins.ListModelMixin, BaseUserView):
    def get(self, request, *args, **kwargs):
        self.serializer_class = UserSerializer
        return self.list(request, *args, **kwargs)


class GetUserView(mixins.RetrieveModelMixin, BaseUserView):
    lookup_field = 'id'

    def get(self, request, *args, **kwargs):
        self.permission_classes = [AdminPermission]
        return self.retrieve(request, *args, **kwargs)


class UpdateUserView(mixins.UpdateModelMixin, BaseUserView):
    lookup_field = 'id'

    def put(self, request, *args, **kwargs):
        self.serializer_class = UserSerializer
        return self.update(request, partial=True, *args, **kwargs)

    def perform_update(self, serializer):
        if serializer.validated_data.get('password'):
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

        return super().perform_update(serializer)


class DeleteUserView(mixins.DestroyModelMixin, BaseUserView):
    lookup_field = 'id'

    def delete(self, request, *args, **kwargs):
        self.destroy(request, *args, **kwargs)
        return Response({"success": "User deleted successfully"})


class RegistrationView(APIView):
    serializer_class = UserRegistrationSerializer

    @swagger_auto_schema(request_body=UserRegistrationSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.validated_data['is_active'] = True
        new_user = User(**serializer.validated_data)
        password = make_password(serializer.validated_data['password'])
        new_user.password = password
        new_user.save()

        # generate token and send verification mail
        payload = {
            'exp': datetime.utcnow() + timedelta(minutes=10, seconds=0),
            'id': new_user.id
        }
        token = jwt.encode(
            payload, key=REGISTRATION_JWT_KEY, algorithm="HS256")
        absurl = f"{FRONT_END_URL}/email-verify?token="\
            + str(token)
        email_body = 'Thank you for choosing us.<br><br> Kindly use the link '\
            'below to verify your email.<br><br>'
        subject = 'Verify your email'
        context = {'username': new_user.name,
                   'email_body': email_body, 'email_subject': subject,
                   'link': absurl if absurl else ''}
        html_template = render_to_string(
            'emails/verify-email.html', context)
        Utils.send_email.delay(
            subject=subject, body=html_template,
            recipients=[new_user.email])
        return Response({
            'message': 'user created',
        }, status=status.HTTP_201_CREATED)


class MailConfirmationView(APIView):
    @swagger_auto_schema(
        manual_parameters=[openapi.Parameter(
            name='token', in_=openapi.IN_QUERY,
            type=openapi.TYPE_STRING, description='Token')])
    def get(self, request):
        token = request.GET.get('token')
        payload = Utils.decode_token(token, REGISTRATION_JWT_KEY)
        if isinstance(payload, dict):
            user = User.objects.get(id=payload['id'])
            if not user.is_active:
                user.is_active = True
                user.save()
            return Response({'message': 'Successfully activated'},
                            status=status.HTTP_200_OK)
        return payload


class RequestPasswordResetEmailView(APIView):
    serializer_class = UserMailSerializer

    @swagger_auto_schema(request_body=UserMailSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if not user:
            raise NotFoundException(
                message="User with this email is not found")
        if not user.is_active:
            raise BadReqException(message="Account is not active")

        # generate token and send mail for reset password
        token = PasswordResetTokenGenerator().make_token(user)
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        relative_link = reverse(
            'verify-token', kwargs={'uidb64': uidb64, 'token': token})
        absurl = HOSTNAME+relative_link
        email_body = ' Use the link below to reset your password.<br><br>'
        subject = 'Reset Password'
        context = {'username': user.name,
                   'email_body': email_body, 'email_subject': subject,
                   'url': absurl if absurl else ''}
        html_template = render_to_string(
            'emails/verify-email.html', context)
        Utils.send_email.delay(
            subject=subject, body=html_template,
            recipients=[user.email])
        return Response({
            'message': 'Reset password mail sent',
        }, status=status.HTTP_200_OK)


class VerifyTokenView(generics.GenericAPIView):
    serializer_class = VerifyTokenSerializer

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(name='token', in_=openapi.IN_QUERY,
                              type=openapi.TYPE_STRING, description='Token'),
            openapi.Parameter(name='uidb64', in_=openapi.IN_QUERY,
                              type=openapi.TYPE_STRING, description='uidb64')
        ]
    )
    def get(self, request, uidb64, token):
        try:
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.filter(id=id).first()
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise InvalidTokenException('The reset link is invalid')
            else:
                return Response({'message': 'Reset link is valid'},
                                status=status.HTTP_200_OK)
        except Exception:
            raise InvalidTokenException('The reset link is invalid')


class ResetPasswordView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            uidb64 = serializer.validated_data['uidb64']
            token = serializer.validated_data['token']
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise InvalidTokenException('The reset link is invalid')

            password = make_password(serializer.validated_data['password'])
            user.password = password
            user.save()
            return Response({'success': True,
                             'message': 'Password reset successes'},
                            status=status.HTTP_200_OK)

        except Exception:
            raise InvalidTokenException('The reset link is invalid')


class GetUpdateUserProfileView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(self.request.user)
        return Response({"message": "success",
                         "data": serializer.data},
                        status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            self.request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(
            {
                "message": "Profile updated successfuly",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )
