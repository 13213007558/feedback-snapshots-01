"""URL configuration with dedicated admin sites used by the revert tests."""

from django.contrib.admin import AdminSite
from django.urls import path

from simple_history.admin import SimpleHistoryAdmin

from .models import Poll


class FullRevertPollAdmin(SimpleHistoryAdmin):
    pass


class LockedFieldPollAdmin(SimpleHistoryAdmin):
    """Governance policy: ``question`` is locked when reverting."""

    def get_revert_locked_fields(self, request, obj=None):
        return ("question",)


class DeniedRevertPollAdmin(SimpleHistoryAdmin):
    """Explicit authorization entry point that refuses every revert."""

    def has_revert_permission(self, request, obj=None):
        return False


class RevokedOnWritePollAdmin(SimpleHistoryAdmin):
    """Permission disappears after the form has been rendered."""

    def has_revert_permission(self, request, obj=None):
        if request.method == "POST":
            return False
        return super().has_revert_permission(request, obj)


class LateLockedPollAdmin(SimpleHistoryAdmin):
    """Governance rules start locking ``question`` only for the write."""

    def get_revert_locked_fields(self, request, obj=None):
        if request.method == "POST":
            return ("question",)
        return ()


def build_site(name, admin_class):
    site = AdminSite(name=name)
    site.register(Poll, admin_class)
    return site


full_site = build_site("revert_full", FullRevertPollAdmin)
locked_site = build_site("revert_locked", LockedFieldPollAdmin)
denied_site = build_site("revert_denied", DeniedRevertPollAdmin)
revoked_site = build_site("revert_revoked", RevokedOnWritePollAdmin)
late_locked_site = build_site("revert_late_locked", LateLockedPollAdmin)

urlpatterns = [
    path("revert-full/", full_site.urls),
    path("revert-locked/", locked_site.urls),
    path("revert-denied/", denied_site.urls),
    path("revert-revoked/", revoked_site.urls),
    path("revert-late-locked/", late_locked_site.urls),
]
