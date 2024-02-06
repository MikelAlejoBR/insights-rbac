#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""API models for import organization."""
from django.conf import settings
from django.db import models
from django.db.models import Q

from api.cross_access.model import CrossAccountRequest  # noqa: F401
from api.status.model import Status  # noqa: F401


class TenantModifiedQuerySet(models.QuerySet):
    """Queryset for modified tenants."""

    def modified_only(self):
        """Return only modified tenants."""
        return (
            self.filter(Q(group__system=False) | Q(role__system=False))
            .prefetch_related("group_set", "role_set")
            .distinct()
        )


class Tenant(models.Model):
    """The model used to create a tenant schema."""

    ready = models.BooleanField(default=False)
    tenant_name = models.CharField(max_length=63)
    account_id = models.CharField(max_length=36, default=None, null=True)
    org_id = models.CharField(max_length=36, unique=True, default=None, db_index=True, null=True)
    objects = TenantModifiedQuerySet.as_manager()

    def __str__(self):
        """Get string representation of Tenant."""
        if settings.AUTHENTICATE_WITH_ORG_ID:
            return f"Tenant ({self.org_id})"
        else:
            return f"Tenant ({self.tenant_name})"


class TenantAwareModel(models.Model):
    """Abstract model for inheriting `Tenant`."""

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)

    class Meta:
        abstract = True


class User:
    """A request User. Might also represent a service account."""

    username = None
    account = None
    admin = False
    access = {}
    system = False
    is_active = True
    org_id = None
    # Service account properties.
    bearer_token: str = None
    client_id: str = None
    is_service_account: bool = False
