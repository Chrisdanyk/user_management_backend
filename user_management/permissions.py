from dataclasses import dataclass

from rest_framework import permissions

from user_management.apps.authentication.models import User
from user_management.exception_handler import AccessDeniedException


class RolePermission(permissions.BasePermission):
    allowed_roles = {}

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role in self.allowed_roles
        )

    class Meta:
        abstract = True


class AdminPermission(RolePermission):
    allowed_roles = {User.Role.ADMIN}


class UserPermission(RolePermission):
    allowed_roles = {User.Role.USER}


@dataclass
class Iam:

    user: User
    raise_exc: bool = False
    resource: str = ""

    def admin(self):
        matches = (self.user.role == User.Role.ADMIN.value)
        return self._post_check(matches, "Admin")

    def _post_check(self, matches, role):
        if not matches and self.raise_exc:
            raise AccessDeniedException(
                f"{self.resource}  is reserved to {role}")
        return matches
