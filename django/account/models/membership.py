from django.db import models
# from django.db.models import Q
from django.conf import settings

from rest.models import RestModel, MetaDataModel, MetaDataBase


DEFAULT_ROLE = getattr(settings, "MEMBERSHIP_DEFAULT_ROLE", "guest")


class Membership(models.Model, RestModel, MetaDataModel):
    class RestMeta:
        CAN_DELETE = True
        SEARCH_FIELDS = ["role", "member__username", "member__first_name", "member__last_name", "member__email"]
        SEARCH_TERMS = [
            ("username", "member__username"),
            ("email", "member__email"),
            ("first_name", "member__first_name"),
            ("last_name", "member__last_name"),
            ("last_activity", "member__last_activity#datetime"),
            ("created", "member__datejoined#datetime"),
            ("perms", "permissions__name"),
            "role"]
        METADATA_FIELD_PROPERTIES = getattr(settings, "MEMBERSHIP_METADATA_PROPERTIES", None)
        GRAPHS = {
            "base": {
                "fields": [
                    'id',
                    'created',
                    'role',
                    'status',
                    'state',
                    'perms'
                ],
                "graphs": {
                    "member": "basic"
                },
            },
            "basic": {
                "graphs": {
                    "self": "base",
                }
            },
            "default": {
                "graphs": {
                    "self": "basic",
                }
            },
            "detailed": {
                "extra": ["metadata"],
                "graphs": {
                    "self": "basic",
                    "member": "detailed",
                }
            }
        }

    member = models.ForeignKey("account.Member", related_name="memberships", on_delete=models.CASCADE)
    group = models.ForeignKey("account.Group", related_name="memberships", on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    role = models.CharField(max_length=64, blank=True, null=True, default=DEFAULT_ROLE)
    state = models.IntegerField(default=0)

    @property
    def is_enabled(self):
        return self.state >= -10

    def addPermission(self, perm):
        self.setProperty(perm, 1, "permissions")

    def removePermission(self, perm):
        self.setProperty(perm, None, "permissions")

    def hasPermission(self, perm):
        return self.hasPerm(perm)

    def hasPerm(self, perm):
        if isinstance(perm, list):
            for i in perm:
                if self.hasPerm(i):
                    return True
            return False
        return self.getProperty(perm, 0, "permissions", bool)

    def hasRole(self, role):
        if not self.is_enabled:
            return False
        if type(role) is list:
            return self.role in role
        return self.role == role


class MembershipMetaData(MetaDataBase):
    parent = models.ForeignKey(Membership, related_name="properties", on_delete=models.CASCADE)

