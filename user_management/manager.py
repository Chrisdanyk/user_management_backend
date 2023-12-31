from django.db import models
from django.utils import timezone


class SoftDeleteQuerySet(models.QuerySet):
    """
    Soft delete queries handler
    """
    def delete(self):
        return super(SoftDeleteQuerySet, self).\
            update(deleted_at=timezone.now())

    def hard_delete(self):
        return super(SoftDeleteQuerySet, self).delete()


class SoftDeleteManager(models.Manager):
    """
    Soft delete manager
    """
    def __init__(self, *args, **kwargs):
        self.alive_only = kwargs.pop('alive_only', True)
        super(SoftDeleteManager, self).__init__(*args, **kwargs)

    def get_queryset(self):
        if self.alive_only:
            return SoftDeleteQuerySet(self.model).filter(deleted_at=None)
        return SoftDeleteQuerySet(self.model)
