from django.db import models
from django.utils import timezone

from user_management.manager import SoftDeleteManager


class SoftDeleteModel(models.Model):
    """
    Base model for all our application models
    """
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)

    objects = SoftDeleteManager()
    all_objects = SoftDeleteManager(alive_only=False)

    def delete(self, using=None, keep_parents=False):
        self.deleted_at = timezone.now()
        self.save()

    def hard_delete(self):
        super().delete()

    class Meta:
        abstract = True

    @staticmethod
    def concat_values(*args):
        return ''.join(args)
