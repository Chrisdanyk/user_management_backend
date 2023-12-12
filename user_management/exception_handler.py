from traceback import print_exc

from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    NotAuthenticated,
    PermissionDenied,
)
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    print_exc()  # Print the traceback
    response = exception_handler(exc, context)
    if isinstance(exc, CustomAPIException):
        return response
    if isinstance(exc, ValidationError):
        response.data = {
            'error': response.data,
            'message': "Could not validate the data"
        }
        return response
    if isinstance(exc, (AuthenticationFailed, NotAuthenticated)):
        response.data = {
            'message': "Authentication failed",
            'error': response.data
        }
        return response
    if isinstance(exc, PermissionDenied):
        response.data = {
            'message': "You do not have permission to perform this action",
            'error': "Permission denied"
        }
        return response
    code = HTTP_500_INTERNAL_SERVER_ERROR
    if response:
        code = response.status_code

    return Response({
        "message": "Please try again",
        "error": "Internal Server Error"
    }, code)


class CustomAPIException(APIException):
    """Exception to raise anywhere in the application"""

    def __init__(self, code: int, message: str, error: str = ""):
        self.status_code = code
        error = error if error else message
        self.detail = {"message": message, "error": error}


class BadReqException(CustomAPIException):

    def __init__(self, message: str, error: str = ""):
        super().__init__(HTTP_400_BAD_REQUEST, message, error)


class NotFoundException(CustomAPIException):

    def __init__(self, message: str, error: str = ""):
        super().__init__(HTTP_404_NOT_FOUND, message, error)


class AccessDeniedException(CustomAPIException):

    def __init__(self, message: str):
        super().__init__(HTTP_403_FORBIDDEN, message, "Permission denied")


class EmailExistException(CustomAPIException):

    def __init__(self, message: str, error: str = ""):
        super().__init__(HTTP_400_BAD_REQUEST, message, "Email already taken")


class InvalidTokenException(CustomAPIException):

    def __init__(self, message: str, error: str = ""):
        super().__init__(HTTP_401_UNAUTHORIZED, message, "Invalid token")
