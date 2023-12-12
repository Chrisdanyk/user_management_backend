from datetime import date

from rest_framework import serializers

from user_management.apps.authentication.models import User
from user_management.exception_handler import EmailExistException


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class LogOutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(min_length=8, write_only=True)

    class Meta:
        model = User
        fields = "__all__"
        writeonly = ('password',)
        readonly = ('id', 'created_at', 'updated_at', 'deleted_at',
                    'user_permissions', 'groups', )
        extra_kwargs = {
            'password': {'write_only': True},
            'user_permissions': {'read_only': True},
            'groups': {'read_only': True},
        }

    def validate(self, attrs):
        email = attrs.get('email', '')
        birthday = attrs.get('birthday')
        today = date.today()
        if birthday:
            age = today.year - birthday.year - (
                (today.month, today.day) < (birthday.month, birthday.day))
            if age < 18:
                raise serializers.ValidationError(
                    "You must be at least 18 years old to register.")
        user = User.objects.filter(email=email).first()
        if user:
            raise EmailExistException("Email Already taken")
        return super().validate(attrs)


class UserRegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    name = serializers.CharField()
    birthday = serializers.DateField(format="%d-%m-%Y",
                                     input_formats=['%d-%m-%Y', 'iso-8601'])
    password = serializers.CharField()
    role = serializers.ChoiceField(choices=User.Role, allow_blank=False)

    def validate(self, attrs):
        email = attrs.get('email', '')
        birthday = attrs.get('birthday')
        today = date.today()
        if birthday:
            age = today.year - birthday.year - (
                (today.month, today.day) < (birthday.month, birthday.day))
            if age < 18:
                raise serializers.ValidationError(
                    "You must be at least 18 years old to register.")
        user = User.objects.filter(email=email).first()
        if user:
            raise EmailExistException("Email Already taken")
        return super().validate(attrs)


class UserMailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=1, max_length=68, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1,)
    token = serializers.CharField(
        min_length=1)


class VerifyTokenSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)
