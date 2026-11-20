from collections import OrderedDict
from collections.abc import Mapping, Sequence

from django import VERSION, forms
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.contrib.auth import get_user_model
from django.forms.formsets import DELETION_FIELD_NAME
from django.forms.models import _get_foreign_key
from django.http import HttpRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import path, reverse
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _

from guardian.forms import GroupObjectPermissionsForm, UserObjectPermissionsForm
from guardian.shortcuts import (
    get_group_perms,
    get_groups_with_perms,
    get_objects_for_user,
    get_perms_for_model,
    get_user_perms,
    get_users_with_perms,
)
from guardian.utils import get_group_obj_perms_model


class GuardedInlineFormSet(forms.BaseInlineFormSet):
    """Inline formset that applies the declared parent and child permissions.

    Django decides inline permissions once for the whole section, and a
    view-only row is protected only by rendering its fields as disabled. A
    crafted POST can still submit values for those rows. This formset keeps
    both permission layers in the loop for every row: it hides children the
    user may not view, locks the fields of children the user may not change or
    delete, and re-checks the layers again while saving, so a denied edit never
    reaches the database while allowed edits still save normally.
    """

    guarded_inline = None
    guarded_request = None
    guarded_parent = None

    def _guard(self):
        inline = self.guarded_inline
        if inline is None or self.guarded_request is None:
            return None
        if not inline.has_declared_permissions():
            return None
        return inline

    def _unfiltered_children(self):
        queryset = self.model._default_manager.all()
        parent = self.guarded_parent
        if parent is not None and parent.pk is not None:
            queryset = queryset.filter(**{self.fk.name: parent})
        return queryset

    def _existing_object(self, pk):
        obj = super()._existing_object(pk)
        if obj is not None or self._guard() is None:
            return obj
        # The submitted primary key may belong to a child hidden from this
        # user. Resolve it anyway so the form is handled as an edit of that
        # object and the save-time check can deny it, instead of treating the
        # payload as a brand new child.
        return self._unfiltered_children().filter(pk=pk).first()

    def get_queryset(self):
        queryset = super().get_queryset()
        inline = self._guard()
        if inline is None:
            return queryset
        return inline.filter_permitted_children(self.guarded_request, ("view", "change"), queryset)

    def add_fields(self, form, index):
        super().add_fields(form, index)
        inline = self._guard()
        if inline is None:
            return
        child = form.instance
        is_new = child is None or child.pk is None or child._state.adding
        action = "add" if is_new else "change"
        if not self._allowed(action, None if is_new else child):
            self._lock_form(form, is_new=is_new)
        elif not is_new and not self._allowed("delete", child):
            self._lock_deletion(form)

    def _lock_form(self, form, is_new):
        protected = {self.model._meta.pk.name, self.fk.name, self._pk_field.name}
        for name, field in form.fields.items():
            if name not in protected:
                field.disabled = True
        self._lock_deletion(form)

    @staticmethod
    def _lock_deletion(form):
        deletion_field = form.fields.get(DELETION_FIELD_NAME)
        if deletion_field is not None:
            deletion_field.disabled = True

    def _allowed(self, action, child):
        inline = self._guard()
        if inline is None:
            return True
        if not inline.has_parent_permission(self.guarded_request, self.guarded_parent, action):
            return False
        return inline.has_child_permission(action, self.guarded_request, self.guarded_parent, child)

    def save_existing_objects(self, commit=True):
        if self._guard() is None or not self.initial_forms:
            return super().save_existing_objects(commit=commit)

        saved_instances = []
        self.changed_objects = []
        self.deleted_objects = []
        forms_to_delete = self.deleted_forms
        for form in self.initial_forms:
            obj = form.instance
            if obj is None or not obj._is_pk_set() or obj._state.adding:
                continue
            if form in forms_to_delete:
                if self._allowed("delete", obj):
                    self.deleted_objects.append(obj)
                    self.delete_existing(obj, commit=commit)
            elif form.has_changed() and self._allowed("change", obj):
                self.changed_objects.append((obj, form.changed_data))
                saved_instances.append(self.save_existing(form, obj, commit=commit))
                if not commit:
                    self.saved_forms.append(form)
        return saved_instances

    def save_new_objects(self, commit=True):
        if self._guard() is None:
            return super().save_new_objects(commit=commit)
        self.new_objects = []
        for form in self.extra_forms:
            if not form.has_changed():
                continue
            if self.can_delete and self._should_delete_form(form):
                continue
            existing = self._posted_existing_child(form)
            if existing is not None:
                # A row beyond INITIAL_FORMS can still carry the primary key of
                # an existing child. Treat it as an edit, never as a new child.
                if self._allowed("change", existing):
                    self.changed_objects.append((existing, form.changed_data))
                    saved = self.save_existing(form, existing, commit=commit)
                    if not commit:
                        self.saved_forms.append(form)
                    self.new_objects.append(saved)
                continue
            if not self._allowed("add", None):
                continue
            self.new_objects.append(self.save_new(form, commit=commit))
            if not commit:
                self.saved_forms.append(form)
        return self.new_objects

    def _posted_existing_child(self, form):
        """Return an existing child referenced by a posted primary key, if any."""
        posted_pk = form.data.get(form.add_prefix(self._pk_field.name))
        if not posted_pk:
            return None
        try:
            return self._unfiltered_children().filter(pk=posted_pk).first()
        except (TypeError, ValueError):
            return None


class GuardedInlineAdminMixin:
    """Mixin for Django admin inline classes to work with Guardian permissions.

    This mixin provides the necessary permission checking methods that Django's
    inline admin forms expect, integrating with Guardian's object-level permissions.

    Inlines often sit on a parent record owned by a different team, so being
    allowed to change the parent does not imply being allowed to change every
    inline child. Declare both layers explicitly to model that:

        class AttachmentInline(GuardedInlineAdminMixin, admin.StackedInline):
            model = Attachment
            parent_permissions = {
                "view": "records.view_record",
                "change": "records.change_record",
            }
            child_permissions = {
                "view": "records.view_attachment",
                "change": "records.change_attachment",
                "delete": "records.delete_attachment",
                "add": "records.add_attachment",
            }

    ``parent_permissions`` is checked against the parent instance.
    ``child_permissions`` is checked against each child instance, so a user may
    edit one attachment and not another. Admin users who may only view still
    see the children they were granted, rendered without editable fields;
    children outside their view grants are omitted from the page. The same two
    layers are checked again when the inline formset is saved, so a crafted
    POST cannot write a child the user is not allowed to change or delete.

    Leave both mappings empty to keep the historical behaviour, where the
    inline model's default ``<action>_<model_name>`` permission is checked
    against the object supplied by Django.

    Usage:
        class MyInline(GuardedInlineAdminMixin, admin.StackedInline):
            model = MyModel

        class MyAdmin(GuardedModelAdminMixin, admin.ModelAdmin):
            inlines = [MyInline]
    """

    #: Permissions required on the parent object, keyed by action
    #: (``add``, ``view``, ``change``, ``delete``). Actions missing from the
    #: mapping are not checked at the parent layer.
    parent_permissions: Mapping[str, str] = {}
    #: Permissions required on each child object, keyed by action. Actions
    #: missing from the mapping fall back to the inline model's default
    #: ``<action>_<model_name>`` permission.
    child_permissions: Mapping[str, str] = {}

    def has_declared_permissions(self):
        """Return whether either permission layer was declared explicitly."""
        return bool(self.parent_permissions or self.child_permissions)

    def _default_permission(self, action):
        opts = self.model._meta
        return f"{opts.app_label}.{action}_{opts.model_name}"

    def get_parent_permission(self, action):
        """Return the permission string required on the parent for ``action``."""
        return self.parent_permissions.get(action)

    def get_child_permission(self, action):
        """Return the permission string required on a child for ``action``."""
        return self.child_permissions.get(action) or self._default_permission(action)

    def has_parent_permission(self, request, obj, action):
        """Return whether the user passes the parent layer for ``action``."""
        permission = self.get_parent_permission(action)
        if permission is None:
            return True
        if obj is None:
            return request.user.has_perm(permission)
        return request.user.has_perm(permission, obj)

    def has_child_permission(self, action, request, obj, child=None):
        """Return whether the user passes the child layer for ``action``.

        ``obj`` is the parent instance the inline is attached to. ``child`` is
        the concrete child for a per-object check; pass ``None`` to ask whether
        the user can act on any child of this inline.
        """
        permission = self.get_child_permission(action)
        if child is not None:
            return request.user.has_perm(permission, child)
        if request.user.has_perm(permission):
            return True
        return self._has_any_child_permission(request, action, obj)

    def _has_any_child_permission(self, request, action, obj):
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return False
        cache = getattr(request, "_guarded_inline_child_cache", None)
        if cache is None:
            cache = {}
            request._guarded_inline_child_cache = cache
        key = (action, id(self), getattr(obj, "pk", None))
        if key not in cache:
            queryset = self.model._default_manager.all()
            if obj is not None:
                fk = _get_foreign_key(self.parent_model, self.model, fk_name=self.fk_name)
                queryset = queryset.filter(**{fk.name: obj})
            cache[key] = self.filter_permitted_children(request, (action,), queryset).exists()
        return cache[key]

    def filter_permitted_children(self, request, actions, queryset):
        """Return the subset of ``queryset`` the user may act on."""
        permissions = []
        for action in actions:
            permission = self.get_child_permission(action)
            if permission is not None:
                permissions.append(permission)
        if not permissions:
            return queryset
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return queryset.none()
        if user.is_superuser:
            return queryset
        return get_objects_for_user(
            user,
            permissions,
            klass=queryset,
            any_perm=True,
            accept_global_perms=True,
        )

    def _has_permission(self, action, request, obj):
        if not self.has_declared_permissions():
            permission = self._default_permission(action)
            if obj is None:
                return request.user.has_perm(permission)
            return request.user.has_perm(permission, obj)
        return self.has_parent_permission(request, obj, action) and self.has_child_permission(
            action, request, obj, None
        )

    def has_add_permission(self, request, obj=None):
        """Check if the user has permission to add instances of this inline model."""
        return self._has_permission("add", request, obj)

    def has_view_permission(self, request, obj=None):
        """Check if the user has permission to view instances of this inline model."""
        return self._has_permission("view", request, obj)

    def has_change_permission(self, request, obj=None):
        """Check if the user has permission to change instances of this inline model."""
        return self._has_permission("change", request, obj)

    def has_delete_permission(self, request, obj=None):
        """Check if the user has permission to delete instances of this inline model."""
        return self._has_permission("delete", request, obj)

    def get_formset(self, request, obj=None, **kwargs):
        """Return an inline formset that applies both permission layers."""
        formset = super().get_formset(request, obj, **kwargs)

        class GuardedFormSet(GuardedInlineFormSet, formset):
            pass

        GuardedFormSet.guarded_inline = self
        GuardedFormSet.guarded_request = request
        GuardedFormSet.guarded_parent = obj
        return GuardedFormSet


class AdminUserObjectPermissionsForm(UserObjectPermissionsForm):
    """Admin form for user object permissions.

    Extends the `UserObjectPermissionsForm` and overrides the
    `get_obj_perms_field_widget` method so it returns the
    `django.contrib.admin.widgets.FilteredSelectMultiple` widget.
    """

    def get_obj_perms_field_widget(self):
        return FilteredSelectMultiple(_("Permissions"), False)


class AdminGroupObjectPermissionsForm(GroupObjectPermissionsForm):
    """Admin form for group object permissions.

    Extends the `GroupObjectPermissionsForm` and overrides the
    `get_obj_perms_field_widget` method so it returns the
    `django.contrib.admin.widgets.FilteredSelectMultiple` widget.
    """

    def get_obj_perms_field_widget(self):
        return FilteredSelectMultiple(_("Permissions"), False)


class GuardedModelAdminMixin:
    """Mixin helper for custom subclassing `admin.ModelAdmin`."""

    change_form_template: str = "admin/guardian/model/change_form.html"
    obj_perms_manage_template: str = "admin/guardian/model/obj_perms_manage.html"
    obj_perms_manage_user_template: str = "admin/guardian/model/obj_perms_manage_user.html"
    obj_perms_manage_group_template: str = "admin/guardian/model/obj_perms_manage_group.html"
    user_can_access_owned_objects_only: bool = False
    user_owned_objects_field: str = "user"
    user_can_access_owned_by_group_objects_only: bool = False
    group_owned_objects_field: str = "group"
    user_can_access_permitted_objects_only: bool = False
    permitted_objects_perms: Sequence[str] | str = ()
    permitted_objects_any_perm: bool = True
    permitted_objects_accept_global_perms: bool = False
    include_object_permissions_urls: bool = True

    def get_queryset(self, request):
        qs = super().get_queryset(request)

        if request.user.is_superuser:
            return qs

        if self.user_can_access_permitted_objects_only:
            perms = (
                self.permitted_objects_perms
                if isinstance(self.permitted_objects_perms, str)
                else list(self.permitted_objects_perms)
            )
            qs = get_objects_for_user(
                user=request.user,
                perms=perms,
                klass=qs,
                any_perm=self.permitted_objects_any_perm,
                accept_global_perms=self.permitted_objects_accept_global_perms,
            )
        if self.user_can_access_owned_objects_only:
            filters = {self.user_owned_objects_field: request.user}
            qs = qs.filter(**filters)
        if self.user_can_access_owned_by_group_objects_only:
            qs_key = f"{self.group_owned_objects_field}__in"
            filters = {qs_key: request.user.groups.all()}
            qs = qs.filter(**filters)
        return qs

    def get_urls(self):
        """

        Extends standard admin model urls with the following:
        - `.../permissions/` under `app_mdodel_permissions` url name (params: object_pk)
        - `.../permissions/user-manage/<user_id>/` under `app_model_permissions_manage_user` url name (params: object_pk, user_pk)
        - `.../permissions/group-manage/<group_id>/` under `app_model_permissions_manage_group` url name (params: object_pk, group_pk)

        Note:
           `...` above are standard, instance detail url (i.e. `/admin/flatpages/1/`)

        """
        urls = super().get_urls()
        if self.include_object_permissions_urls:
            info = self.model._meta.app_label, self.model._meta.model_name
            myurls = [
                path(
                    "<object_pk>/permissions/",
                    view=self.admin_site.admin_view(self.obj_perms_manage_view),
                    name="%s_%s_permissions" % info,
                ),
                path(
                    "<object_pk>/permissions/user-manage/<user_id>/",
                    view=self.admin_site.admin_view(self.obj_perms_manage_user_view),
                    name="%s_%s_permissions_manage_user" % info,
                ),
                path(
                    "<object_pk>/permissions/group-manage/<group_id>/",
                    view=self.admin_site.admin_view(self.obj_perms_manage_group_view),
                    name="%s_%s_permissions_manage_group" % info,
                ),
            ]
            urls = myurls + urls
        return urls

    def get_obj_perms_base_context(self, request, obj):
        """Get context dict with common admin and object permissions related content.

        Returns context dictionary with common admin and object permissions
        related content. It uses AdminSite.each_context,
        making sure all required template vars are in the context.

        Returns:
            django template context
        """
        context = self.admin_site.each_context(request)
        context.update(
            {
                "adminform": {"model_admin": self},
                "media": self.media,
                "object": obj,
                "app_label": self.model._meta.app_label,
                "opts": self.model._meta,
                "original": str(obj),
                "has_change_permission": self.has_change_permission(request, obj),
                "model_perms": get_perms_for_model(obj),
                "title": _("Object permissions"),
                # see https://github.com/django/django/pull/19492
                "legacy_breadcrumbs": VERSION < (6, 1),
            }
        )
        return context

    def obj_perms_manage_view(self, request, object_pk):
        """Main object permissions view.

        Presents all users and groups with any object permissions for the current model *instance*.
        Users or groups without object permissions for related *instance* would **not** be shown.
        To add or manage user or group, one should use links or forms presented within the page.
        """
        if not self.has_change_permission(request, None):
            post_url = reverse("admin:index", current_app=self.admin_site.name)
            return redirect(post_url)

        from django.contrib.admin.utils import unquote

        obj = get_object_or_404(self.get_queryset(request), pk=unquote(object_pk))
        users_perms = OrderedDict(
            sorted(
                get_users_with_perms(obj, attach_perms=True, with_group_users=False).items(),
                key=lambda user: getattr(user[0], get_user_model().USERNAME_FIELD),
            )
        )

        groups_perms = OrderedDict(
            sorted(get_groups_with_perms(obj, attach_perms=True).items(), key=lambda group: group[0].name)
        )

        if request.method == "POST" and "submit_manage_user" in request.POST:
            user_form = self.get_obj_perms_user_select_form(request)(request.POST)
            group_form = self.get_obj_perms_group_select_form(request)(request.POST)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.model_name,
            )
            if user_form.is_valid():
                user_id = user_form.cleaned_data["user"].pk
                url = reverse("%s:%s_%s_permissions_manage_user" % info, args=[obj.pk, user_id])
                return redirect(url)
        elif request.method == "POST" and "submit_manage_group" in request.POST:
            user_form = self.get_obj_perms_user_select_form(request)(request.POST)
            group_form = self.get_obj_perms_group_select_form(request)(request.POST)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.model_name,
            )
            if group_form.is_valid():
                group_id = group_form.cleaned_data["group"].id
                url = reverse("%s:%s_%s_permissions_manage_group" % info, args=[obj.pk, group_id])
                return redirect(url)
        else:
            user_form = self.get_obj_perms_user_select_form(request)()
            group_form = self.get_obj_perms_group_select_form(request)()

        context = self.get_obj_perms_base_context(request, obj)
        context["users_perms"] = users_perms
        context["groups_perms"] = groups_perms
        context["user_form"] = user_form
        context["group_form"] = group_form

        # https://github.com/django/django/commit/cf1f36bb6eb34fafe6c224003ad585a647f6117b
        request.current_app = self.admin_site.name

        return render(request, self.get_obj_perms_manage_template(), context)

    def get_obj_perms_manage_template(self):
        """
        Returns main object permissions admin template.  May be overridden if
        need to change it dynamically.

        Note:
           If `INSTALLED_APPS` contains `grappelli` this function would
           return `"admin/guardian/grappelli/obj_perms_manage.html"`.

        """
        if "grappelli" in settings.INSTALLED_APPS:
            return "admin/guardian/contrib/grappelli/obj_perms_manage.html"
        return self.obj_perms_manage_template

    def obj_perms_manage_user_view(self, request, object_pk, user_id):
        """Manages selected users' permissions for the current object."""
        if not self.has_change_permission(request, None):
            post_url = reverse("admin:index", current_app=self.admin_site.name)
            return redirect(post_url)

        user = get_object_or_404(get_user_model(), pk=user_id)
        obj = get_object_or_404(self.get_queryset(request), pk=object_pk)
        form_class = self.get_obj_perms_manage_user_form(request)
        form = form_class(user, obj, request.POST or None)

        if request.method == "POST" and form.is_valid():
            form.save_obj_perms()
            msg = gettext("Permissions saved.")
            messages.success(request, msg)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.model_name,
            )
            url = reverse("%s:%s_%s_permissions_manage_user" % info, args=[obj.pk, user.pk])
            return redirect(url)

        context = self.get_obj_perms_base_context(request, obj)
        context["user_obj"] = user
        context["user_perms"] = get_user_perms(user, obj)
        context["form"] = form

        request.current_app = self.admin_site.name

        return render(request, self.get_obj_perms_manage_user_template(), context)

    def get_obj_perms_manage_user_template(self) -> str:
        """Returns object permissions for user admin template.

        May be overridden if dynamic behavior is needed.

        Note:
           If `INSTALLED_APPS` contains "grappelli" this function returns
           `"admin/guardian/grappelli/obj_perms_manage_user.html"`.
           Else, it returns `self.obj_perms_manage_user_template`.
        """
        if "grappelli" in settings.INSTALLED_APPS:
            return "admin/guardian/contrib/grappelli/obj_perms_manage_user.html"
        return self.obj_perms_manage_user_template

    def get_obj_perms_user_select_form(self, request: HttpRequest) -> type[forms.Form]:
        """Get the form class for selecting a user for permissions management.

        Parameters:
            request (HttpRequest): The HTTP request object.

        Returns:
            The form class for selecting a user for permissions management.
                Default is `UserManage`
        """
        return UserManage

    def get_obj_perms_group_select_form(self, request: HttpRequest) -> type[forms.Form]:
        """Get the form class for group object permissions management.
        Parameters:
            request (HttpRequest): The HTTP request object.

        Returns:
            The form class for group object permissions management.
                Default is `GroupManage`
        """
        return GroupManage

    def get_obj_perms_manage_user_form(self, request: HttpRequest) -> type[forms.Form]:
        """Get the form class for user object permissions management.

        Parameters:
            request (HttpRequest): The HTTP request object.

        Returns:
            The form class for user object permissions management.
                Default is `AdminUserObjectPermissionsForm`.
        """
        return AdminUserObjectPermissionsForm

    def obj_perms_manage_group_view(self, request, object_pk, group_id):
        """Manages selected groups' permissions for the current object."""
        if not self.has_change_permission(request, None):
            post_url = reverse("admin:index", current_app=self.admin_site.name)
            return redirect(post_url)

        obj = get_object_or_404(self.get_queryset(request), pk=object_pk)
        GroupModel = get_group_obj_perms_model(obj).group.field.related_model
        group = get_object_or_404(GroupModel, id=group_id)
        form_class = self.get_obj_perms_manage_group_form(request)
        form = form_class(group, obj, request.POST or None)

        if request.method == "POST" and form.is_valid():
            form.save_obj_perms()
            msg = gettext("Permissions saved.")
            messages.success(request, msg)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.model_name,
            )
            url = reverse("%s:%s_%s_permissions_manage_group" % info, args=[obj.pk, group.id])
            return redirect(url)

        context = self.get_obj_perms_base_context(request, obj)
        context["group_obj"] = group
        context["group_perms"] = get_group_perms(group, obj)
        context["form"] = form

        request.current_app = self.admin_site.name

        return render(request, self.get_obj_perms_manage_group_template(), context)

    def get_obj_perms_manage_group_template(self):
        """Returns object permissions for group admin template.

        May be overridden if dynamic behavior is needed.

        Returns:
            template name

        Note:
           If `INSTALLED_APPS` contains `grappelli` this function would
           return `"admin/guardian/grappelli/obj_perms_manage_group.html"`.
        """
        if "grappelli" in settings.INSTALLED_APPS:
            return "admin/guardian/contrib/grappelli/obj_perms_manage_group.html"
        return self.obj_perms_manage_group_template

    def get_obj_perms_manage_group_form(self, request):
        """Get the form class for group object permissions management.

        Parameters:
            request (HttpRequest): The HTTP request object.

        Returns:
            The form class for group object permissions management.
                Default is `AdminGroupObjectPermissionsForm`.
        """
        return AdminGroupObjectPermissionsForm


class ReinforcedGuardedModelAdminMixin(GuardedModelAdminMixin):
    """Mixin helper for custom subclassing `admin.ModelAdmin`.

    Like `GuardedModelAdminMixin`, but also requires the guardian
    view/change permissions for the object permissions management views
    themselves. `GuardedModelAdminMixin` only checks `has_change_permission`
    for the underlying model, so any staff user allowed to change a model
    instance can also view and edit *every* user's and group's object
    permissions for it, whether or not they hold the guardian permission
    for that. This mixin is opt-in to avoid changing the behavior of
    existing `GuardedModelAdminMixin` subclasses.
    """

    def obj_perms_manage_view(self, request, object_pk):
        # The delegated view always renders both users_perms and
        # groups_perms on the same page, with no way to omit either half,
        # so reaching it requires both view permissions. Requiring just
        # one would let a user who can only view user-object permissions
        # see every group's object permissions too, and vice versa.
        if not request.user.has_perm("guardian.view_userobjectpermission") or not request.user.has_perm(
            "guardian.view_groupobjectpermission"
        ):
            post_url = reverse("admin:index", current_app=self.admin_site.name)
            return redirect(post_url)
        return super().obj_perms_manage_view(request, object_pk)

    def obj_perms_manage_user_view(self, request, object_pk, user_id):
        if not request.user.has_perm("guardian.change_userobjectpermission"):
            post_url = reverse("admin:index", current_app=self.admin_site.name)
            return redirect(post_url)
        return super().obj_perms_manage_user_view(request, object_pk, user_id)

    def obj_perms_manage_group_view(self, request, object_pk, group_id):
        if not request.user.has_perm("guardian.change_groupobjectpermission"):
            post_url = reverse("admin:index", current_app=self.admin_site.name)
            return redirect(post_url)
        return super().obj_perms_manage_group_view(request, object_pk, group_id)


class GuardedModelAdmin(GuardedModelAdminMixin, admin.ModelAdmin):
    """Provide views for managing object permissions on the Django admin panel.

    Extends the `django.contrib.admin.ModelAdmin` class.
    It uses `'admin/guardian/model/change_form.html'` as the
    default `change_form_template` attribute which is required for proper
    url (object permissions related) being shown at the model pages.

    Attributes:
        obj_perms_manage_template (str): Defaults to `admin/guardian/model/obj_perms_manage.html`
        obj_perms_manage_user_template (str): Defaults to `admin/guardian/model/obj_perms_manage_user.html`
        obj_perms_manage_group_template (str): Defaults to `admin/guardian/model/obj_perms_manage_group.html`
        user_can_access_owned_objects_only (bool): Defaults to `False`.
            If `True`, `request.user` would be used to filter out objects they don't own
            checking `user` field of used model -
            field name may be overridden by the `user_owned_objects_field` option.
        user_can_access_owned_by_group_objects_only (bool): *Default*: `False`
            If `True`, `request.user` is used to filter out objects her or his group doesn't own
            (checking if any group the user belongs to is set as `group` field of the object;
            name of the field can be changed by overriding `group_owned_objects_field`).
        group_owned_objects_field (str): *Default*: `group`
            Name of the field to check for group ownership.
        user_can_access_permitted_objects_only (bool): *Default*: `False`
            If `True`, `guardian.shortcuts.get_objects_for_user` is used to filter out objects
            for which the user does not have permissions.
        permitted_objects_perms (Sequence[str] | str): *Default*: `()`
            Permissions to check when `user_can_access_permitted_objects_only` is `True`.
            If empty sequence (default), checks for any object-level permission on the model.
        permitted_objects_any_perm (bool): *Default*: `True`
            Whether having any of the permissions in `permitted_objects_perms` is sufficient.
        permitted_objects_accept_global_perms (bool): *Default*: `False`
            Whether global permissions are taken into account when filtering objects.
        include_object_permissions_urls (bool): *Default*: `True`
            Added in version 1.2.
            If `False` guardian-specific URLs are **NOT** included in the admin

    Warning:
       Setting `user_can_access_owned_objects_only` to `True` will **NOT** affect superusers!
       Admins would still see all items.

    Warning:
       Setting `user_can_access_owned_by_group_objects_only` to `True` will **NOT** affect superusers!
       Admins would still see all items.

    Warning:
       Setting `user_can_access_permitted_objects_only` to `True` will **NOT** affect superusers!
       Admins would still see all items.


    Example:
        ```python
        # Just use GuardedModelAdmin instead of django.contrib.admin.ModelAdmin.

        from django.contrib import admin
        from guardian.admin import GuardedModelAdmin
        from myapp.models import Author

        class AuthorAdmin(GuardedModelAdmin):
            pass

        admin.site.register(Author, AuthorAdmin)
        ```
    """


class ReinforcedGuardedModelAdmin(ReinforcedGuardedModelAdminMixin, admin.ModelAdmin):
    """Like `GuardedModelAdmin`, but requires the guardian view/change
    permissions for the object permissions management views themselves.

    See `ReinforcedGuardedModelAdminMixin` for details.
    """


class UserManage(forms.Form):
    user = forms.CharField(
        label=_("User identification"),
        max_length=200,
        error_messages={"does_not_exist": _("This user does not exist")},
        help_text=_("Enter a value compatible with User.USERNAME_FIELD"),
    )

    def clean_user(self):
        """Returns `User` instance based on the given identification."""
        identification = self.cleaned_data["user"]
        user_model = get_user_model()
        try:
            username_field = user_model.USERNAME_FIELD
        except AttributeError:
            username_field = "username"
        try:
            user = user_model.objects.get(**{username_field: identification})
            return user
        except user_model.DoesNotExist:
            raise forms.ValidationError(self.fields["user"].error_messages["does_not_exist"])


class GroupManage(forms.Form):
    group = forms.CharField(max_length=80, error_messages={"does_not_exist": _("This group does not exist")})

    def clean_group(self):
        """Returns `Group` instance based on the given group name."""
        name = self.cleaned_data["group"]
        GroupModel = get_group_obj_perms_model().group.field.related_model
        try:
            group = GroupModel.objects.get(name=name)
            return group
        except GroupModel.DoesNotExist:
            raise forms.ValidationError(self.fields["group"].error_messages["does_not_exist"])
