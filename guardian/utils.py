"""
django-guardian helper functions.

Functions defined within this module are a part of django-guardian's internal functionality
and be considered unstable; their APIs may change in any future releases.
"""

from dataclasses import dataclass, field
import gc
from itertools import chain
import logging
from math import ceil
import os
import time
from typing import Any

from django.apps import apps as django_apps
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import DEFAULT_DB_ALIAS
from django.db.models import Model, QuerySet
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotFound,
    HttpResponseRedirect,
)
from django.shortcuts import render

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type
from guardian.exceptions import NotUserNorGroup

logger = logging.getLogger(__name__)


def abspath(*args):
    """Join path arguments and return their absolute path"""
    return os.path.abspath(os.path.join(*args))


def _get_anonymous_user_cached() -> Any:
    """Internal cached version of get_anonymous_user using Django's cache system."""
    cache_key = f"guardian:anonymous_user:{guardian_settings.ANONYMOUS_USER_NAME}"

    # Try to get from cache first
    user = cache.get(cache_key)
    if user is not None:
        return user

    # If not in cache, get from database and cache it
    user_model = get_user_model()
    lookup = {user_model.USERNAME_FIELD: guardian_settings.ANONYMOUS_USER_NAME}  # type: ignore[attr-defined]
    user = user_model.objects.get(**lookup)

    # Cache with TTL from settings
    # -1 means cache indefinitely (None), positive number is TTL in seconds
    ttl = None if guardian_settings.ANONYMOUS_USER_CACHE_TTL == -1 else guardian_settings.ANONYMOUS_USER_CACHE_TTL
    cache.set(cache_key, user, ttl)
    return user


def _get_anonymous_user_uncached() -> Any:
    """Internal uncached version of get_anonymous_user."""
    user_model = get_user_model()
    lookup = {user_model.USERNAME_FIELD: guardian_settings.ANONYMOUS_USER_NAME}  # type: ignore[attr-defined]
    return user_model.objects.get(**lookup)


def get_anonymous_user() -> Any:
    """Get the django-guardian equivalent of the anonymous user.

    It returns a `User` model instance (not `AnonymousUser`) depending on
    `ANONYMOUS_USER_NAME` configuration.

    This function can be cached to avoid repetitive database queries based on the
    `GUARDIAN_ANONYMOUS_USER_CACHE_TTL` setting:
    - 0 (default): No caching, each call performs a fresh database query
    - Positive number: Cache for that many seconds
    - -1: Cache indefinitely (not recommended)

    See Also:
        See the configuration docs that explain that the Guardian anonymous user is
        not equivalent to Django's AnonymousUser.

        - [Guardian Configuration](https://django-guardian.readthedocs.io/en/stable/configuration.html)
        - [ANONYMOUS_USER_NAME configuration](https://django-guardian.readthedocs.io/en/stable/configuration.html#anonymous-user-nam)
        - [ANONYMOUS_USER_CACHE_TTL configuration](https://django-guardian.readthedocs.io/en/stable/configuration.html#anonymous-user-cache-ttl)
    """
    if guardian_settings.ANONYMOUS_USER_CACHE_TTL > 0 or guardian_settings.ANONYMOUS_USER_CACHE_TTL == -1:
        return _get_anonymous_user_cached()
    else:
        return _get_anonymous_user_uncached()


def get_identity(identity: Model) -> tuple[Any | None, Any | None]:
    """Get a tuple with the identity of the given input.

    Returns a tuple with one of the members set to `None` depending on whether the input is
    a `Group` instance or a `User` instance.
    Also accepts AnonymousUser instance but would return `User` instead.
    It is convenient and needed for authorization backend to support anonymous users.

    Returns:
         Either (user_obj, None) or (None, group_obj) depending on the input type.

    Parameters:
        identity (User | Group): Instance of `User` or `Group` to get identity from.

    Raises:
        NotUserNorGroup: If the function cannot return proper identity instance

    Examples:
        ```shell
        >>> from django.contrib.auth.models import User, Group
        >>> user = User.objects.create(username='joe')
        >>> get_identity(user)
        (<User: joe>, None)

        >>> group = Group.objects.create(name='users')
        >>> get_identity(group)
        (None, <Group: users>)

        >>> anon = AnonymousUser()
        >>> get_identity(anon)
        (<User: AnonymousUser>, None)

        >>> get_identity("not instance")
        ...
        NotUserNorGroup: User/AnonymousUser or Group instance is required (got )
        ```
    """
    if isinstance(identity, AnonymousUser):
        identity = get_anonymous_user()

    group_model = get_group_obj_perms_model().group.field.related_model  # type: ignore[attr-defined]

    # get identity from queryset model type
    if isinstance(identity, QuerySet):
        identity_model_type = identity.model
        if issubclass(identity_model_type, get_user_model()):
            return identity, None
        elif issubclass(identity_model_type, group_model):
            return None, identity

    # get identity from the first element in the list
    if isinstance(identity, list):
        if not identity:
            return None, None
        if isinstance(identity[0], get_user_model()):
            return identity, None
        if isinstance(identity[0], group_model):
            return None, identity

    if isinstance(identity, get_user_model()):
        return identity, None
    if isinstance(identity, group_model):
        return None, identity

    raise NotUserNorGroup("User/AnonymousUser or Group instance is required (got %s)" % identity)


def get_40x_or_None(
    request: HttpRequest,
    perms: list[str],
    obj: Any | None = None,
    login_url: Any | None = None,
    redirect_field_name: str | None = None,
    return_403: bool = False,
    return_404: bool = False,
    permission_denied_message: str = "",
    accept_global_perms: bool = False,
    any_perm: bool = False,
) -> HttpResponseForbidden | HttpResponseNotFound | HttpResponseRedirect | HttpResponse | None:
    login_url = login_url or settings.LOGIN_URL
    redirect_field_name = redirect_field_name or REDIRECT_FIELD_NAME

    # Handles both original and with object provided permission check
    # as `obj` defaults to None

    has_permissions = False
    # global perms check first (if accept_global_perms)
    if accept_global_perms:
        if any_perm:
            has_permissions = any(request.user.has_perm(perm) for perm in perms)  # type: ignore[union-attr]
        else:
            has_permissions = all(request.user.has_perm(perm) for perm in perms)  # type: ignore[union-attr]
    # if still no permission granted, try obj perms
    if not has_permissions:
        if any_perm:
            has_permissions = any(request.user.has_perm(perm, obj) for perm in perms)  # type: ignore[union-attr]
        else:
            has_permissions = all(request.user.has_perm(perm, obj) for perm in perms)  # type: ignore[union-attr]

    if not has_permissions:
        if return_403:
            if guardian_settings.RENDER_403:
                response = render(
                    request,
                    guardian_settings.TEMPLATE_403,
                    context={"exception": permission_denied_message},
                )
                response.status_code = 403
                return response
            elif guardian_settings.RAISE_403:
                raise PermissionDenied(permission_denied_message)
            return HttpResponseForbidden()
        if return_404:
            if guardian_settings.RENDER_404:
                response = render(request, guardian_settings.TEMPLATE_404)
                response.status_code = 404
                return response
            elif guardian_settings.RAISE_404:
                raise Http404
            return HttpResponseNotFound()
        else:
            from django.contrib.auth.views import redirect_to_login

            return redirect_to_login(request.get_full_path(), login_url, redirect_field_name)
    return None


def get_obj_perm_model_by_conf(setting_name: str) -> type[Model]:
    """Return the model that matches the guardian settings.

    Parameters:
        setting_name (str): The name of the setting to get the model from.

    Returns:
        The model class that matches the guardian settings.

    Raises:
        ImproperlyConfigured: If the setting value is not an installed model or
            does not follow the format 'app_label.model_name'.
    """
    setting_value: str = getattr(guardian_settings, setting_name)
    try:
        return django_apps.get_model(setting_value, require_ready=False)  # type: ignore
    except ValueError as e:
        raise ImproperlyConfigured(f"{setting_value} must be of the form 'app_label.model_name'") from e
    except LookupError as e:
        raise ImproperlyConfigured(
            f"{setting_name} refers to model '{setting_value}' that has not been installed"
        ) from e


def clean_orphan_obj_perms(
    batch_size: int | None = None,
    max_batches: int | None = None,
    max_duration_secs: int | None = None,
    skip_batches: int = 0,
    using: str | None = None,
) -> int:
    """
    Removes orphan object permissions using queryset slice-based batching,
    batch skipping, batch limit, and time-based interruption.

    ``using`` nominates the database alias to scan and clean; defaults to the
    default database.
    """

    UserObjectPermission = get_user_obj_perms_model()
    GroupObjectPermission = get_group_obj_perms_model()

    deleted = 0
    scanned = 0
    processed_batches = 0
    batch_count = 0
    start_time = time.monotonic()

    if batch_size is None:
        all_objs = list(
            chain(
                UserObjectPermission.objects.using(using).order_by("pk"),
                GroupObjectPermission.objects.using(using).order_by("pk"),
            )
        )

        for obj in all_objs:
            if max_duration_secs is not None and (time.monotonic() - start_time >= max_duration_secs):
                logger.info(f"Time limit of {max_duration_secs}s reached.")
                break

            scanned += 1
            if obj.content_object is None:
                logger.debug("Removing %s (pk=%d)", obj, obj.pk)
                obj.delete()
                deleted += 1
        processed_batches = 1
    else:
        total_user = UserObjectPermission.objects.using(using).count()
        total_group = GroupObjectPermission.objects.using(using).count()

        # User and group permissions are batched separately, so a partial last
        # user batch is followed by full group batches. Count them per table.
        total_batches_possible = ceil(total_user / batch_size) + ceil(total_group / batch_size)

        remaining_batches = total_batches_possible - skip_batches
        if max_batches is not None:
            remaining_batches = min(remaining_batches, max_batches)

        logger.info(
            f"Starting orphan object permissions cleanup with batch_size={batch_size}, "
            f"max_batches={max_batches}, max_duration_secs={max_duration_secs}, skip_batches={skip_batches}"
        )

        # Process User permissions first
        user_processed = 0
        user_deleted = 0
        user_last_pk = None
        user_total = UserObjectPermission.objects.using(using).count()

        # Skip user batches if needed
        user_skip_records = min(skip_batches * batch_size, user_total)
        user_remaining = user_total - user_skip_records

        while user_remaining > 0 and remaining_batches > 0:
            if max_duration_secs is not None and (time.monotonic() - start_time >= max_duration_secs):
                logger.info(f"Time limit of {max_duration_secs}s reached.")
                break

            gc.collect()

            current_batch_size = min(batch_size, user_remaining)
            # Only the first batch uses an offset. Deleting orphans shifts the
            # remaining rows down, so later batches continue after the last
            # seen pk instead of at a growing offset that would skip rows.
            user_qs = UserObjectPermission.objects.using(using).order_by("pk")
            if user_last_pk is None:
                user_batch = list(user_qs[user_skip_records : user_skip_records + current_batch_size])
            else:
                user_batch = list(user_qs.filter(pk__gt=user_last_pk)[:current_batch_size])

            if not user_batch:
                break

            user_last_pk = user_batch[-1].pk
            scanned += len(user_batch)
            user_processed += len(user_batch)
            user_remaining -= len(user_batch)

            orphan_pks = [obj.pk for obj in user_batch if obj.content_object is None]

            if orphan_pks:
                logger.info(
                    f"!!! Found {len(orphan_pks)} orphan user permissions in batch {processed_batches + 1}. !!!"
                )
                UserObjectPermission.objects.using(using).filter(pk__in=orphan_pks).delete()
                deleted += len(orphan_pks)
                user_deleted += len(orphan_pks)

            processed_batches += 1
            batch_count += 1
            remaining_batches -= 1

            logger.info(f"Processed user batch {processed_batches}, scanned {scanned} objects.")

        # Process Group permissions
        group_processed = 0
        group_deleted = 0
        group_skip_records = 0
        if remaining_batches > 0:
            group_last_pk = None
            group_total = GroupObjectPermission.objects.using(using).count()

            # Calculate skip for group permissions
            total_user_batches = ceil(user_total / batch_size) if user_total > 0 else 0
            group_skip_batches = max(0, skip_batches - total_user_batches)
            group_skip_records = min(group_skip_batches * batch_size, group_total)
            group_remaining = group_total - group_skip_records

            while group_remaining > 0 and remaining_batches > 0:
                if max_duration_secs is not None and (time.monotonic() - start_time >= max_duration_secs):
                    logger.info(f"Time limit of {max_duration_secs}s reached.")
                    break

                gc.collect()

                current_batch_size = min(batch_size, group_remaining)
                group_qs = GroupObjectPermission.objects.using(using).order_by("pk")
                if group_last_pk is None:
                    group_batch = list(group_qs[group_skip_records : group_skip_records + current_batch_size])
                else:
                    group_batch = list(group_qs.filter(pk__gt=group_last_pk)[:current_batch_size])

                if not group_batch:
                    break

                group_last_pk = group_batch[-1].pk
                scanned += len(group_batch)
                group_processed += len(group_batch)
                group_remaining -= len(group_batch)

                orphan_pks = [obj.pk for obj in group_batch if obj.content_object is None]

                if orphan_pks:
                    logger.info(
                        f"!!! Found {len(orphan_pks)} orphan group permissions in batch {processed_batches + 1}. !!!"
                    )
                    GroupObjectPermission.objects.using(using).filter(pk__in=orphan_pks).delete()
                    deleted += len(orphan_pks)
                    group_deleted += len(orphan_pks)

                processed_batches += 1
                batch_count += 1
                remaining_batches -= 1

                logger.info(f"Processed group batch {processed_batches}, scanned {scanned} objects.")

        # skip_batches counts batches of rows that still exist, so base the
        # resume point on the rows kept rather than the rows scanned. Rounding
        # down may rescan a few rows on resume, but never skips any.
        if user_remaining > 0:
            resume_skip_batches = (user_skip_records + user_processed - user_deleted) // batch_size
        else:
            resume_skip_batches = (
                ceil((user_total - user_deleted) / batch_size)
                + (group_skip_records + group_processed - group_deleted) // batch_size
            )

    logger.info(
        f"Finished orphan object permissions cleanup. "
        f"Scanned: {scanned} | Removed: {deleted} | "
        f"Batches processed: {processed_batches}"
    )

    if batch_size:
        suggestion = (
            f"To resume cleanup, call:\n"
            f"clean_orphan_obj_perms(batch_size={batch_size}, "
            f"skip_batches={resume_skip_batches}, "
        )
        if max_batches is not None:
            suggestion += f"max_batches={max_batches - batch_count}, "
        if max_duration_secs is not None:
            suggestion += f"max_duration_secs={max_duration_secs}, "
        suggestion = suggestion.rstrip(", ") + ")"
        logger.info(suggestion)

    return deleted


@dataclass(frozen=True)
class OrphanObjPermRecord:
    """A single object permission entry whose target could not be found.

    Attributes:
        model: Which permission model holds the entry, ``"user"`` or ``"group"``.
        pk: Primary key of the permission entry.
        content_type_id: Content type id of the missing target.
        object_pk: Primary key of the missing target, as stored on the entry
            (string, regardless of the target's primary key type).
    """

    model: str
    pk: int
    content_type_id: int
    object_pk: str


@dataclass
class OrphanObjPermsPreview:
    """Verifiable outcome of :func:`preview_orphan_obj_perms`.

    Pass an instance to :func:`delete_orphan_obj_perms` to remove exactly
    these entries; every entry is re-checked at deletion time.
    """

    database: str
    records: list[OrphanObjPermRecord] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.records)

    def for_model(self, model: str) -> list[OrphanObjPermRecord]:
        """Return the records of one permission model (``"user"`` or ``"group"``)."""
        return [record for record in self.records if record.model == model]


@dataclass
class OrphanObjPermsCleanResult:
    """Verifiable outcome of :func:`delete_orphan_obj_perms`.

    Attributes:
        database: Database alias the cleanup ran against.
        removed_records: Previewed entries that were still orphaned and got deleted.
        skipped_records: Previewed entries kept because their target exists again.
        failed_batches: Number of batches that raised an error and were skipped.
        batches_processed: Number of batches that completed successfully.
    """

    database: str
    removed_records: list[OrphanObjPermRecord] = field(default_factory=list)
    skipped_records: list[OrphanObjPermRecord] = field(default_factory=list)
    failed_batches: int = 0
    batches_processed: int = 0

    @property
    def removed(self) -> int:
        return len(self.removed_records)

    @property
    def skipped(self) -> int:
        return len(self.skipped_records)


def _orphan_obj_perms_models() -> tuple[tuple[str, type[Model]], tuple[str, type[Model]]]:
    return (
        ("user", get_user_obj_perms_model()),
        ("group", get_group_obj_perms_model()),
    )


def preview_orphan_obj_perms(using: str | None = None) -> OrphanObjPermsPreview:
    """Collect object permission entries whose targets no longer exist.

    Nothing is deleted. The returned preview can be inspected to verify what
    would be removed, and then passed to :func:`delete_orphan_obj_perms`,
    which re-checks every entry before removing it.

    Orphan detection resolves each entry's ``content_object``, so targets with
    any primary key type (including UUIDs) are matched correctly.

    Parameters:
        using: Database alias to scan. Defaults to the default database.
    """
    database = using or DEFAULT_DB_ALIAS
    records = []
    for model_key, model in _orphan_obj_perms_models():
        for obj in model.objects.using(using).order_by("pk").iterator():
            if obj.content_object is None:
                records.append(
                    OrphanObjPermRecord(
                        model=model_key,
                        pk=obj.pk,
                        content_type_id=obj.content_type_id,
                        object_pk=str(obj.object_pk),
                    )
                )
    return OrphanObjPermsPreview(database=database, records=records)


def delete_orphan_obj_perms(
    preview: OrphanObjPermsPreview,
    batch_size: int | None = None,
    max_batches: int | None = None,
    max_duration_secs: int | None = None,
    skip_batches: int = 0,
    using: str | None = None,
) -> OrphanObjPermsCleanResult:
    """Remove the entries of a preview that are still orphaned.

    Every candidate is re-fetched on the preview's database and only deleted
    when its target is still missing, so targets re-created after the preview
    keep their permissions. A batch that raises an error is logged and
    skipped, and later batches still run; rerun with a fresh preview to retry
    the failed entries.

    Parameters:
        preview: Result of :func:`preview_orphan_obj_perms`.
        batch_size: Number of entries to process per batch. If not specified,
            each permission model is processed in a single batch.
        max_batches: Maximum number of batches to process. Use with ``batch_size``.
        max_duration_secs: Maximum duration in seconds for the cleanup operation.
        skip_batches: Number of batches to skip before starting. Use with ``batch_size``.
        using: Database alias to clean. Defaults to the preview's database.

    Returns:
        An :class:`OrphanObjPermsCleanResult` listing exactly which entries
        were removed and which were skipped.
    """
    using = using or preview.database
    models = dict(_orphan_obj_perms_models())
    result = OrphanObjPermsCleanResult(database=using)

    batches: list[tuple[str, list[OrphanObjPermRecord]]] = []
    for model_key in ("user", "group"):
        records = preview.for_model(model_key)
        if batch_size is None:
            if records:
                batches.append((model_key, records))
        else:
            batches.extend(
                (model_key, records[offset : offset + batch_size]) for offset in range(0, len(records), batch_size)
            )

    if batch_size is not None:
        batches = batches[skip_batches:]
        if max_batches is not None:
            batches = batches[:max_batches]

    start_time = time.monotonic()
    for model_key, records in batches:
        if max_duration_secs is not None and (time.monotonic() - start_time >= max_duration_secs):
            logger.info(f"Time limit of {max_duration_secs}s reached.")
            break

        model = models[model_key]
        record_by_pk = {record.pk: record for record in records}
        try:
            gc.collect()
            candidates = list(model.objects.using(using).filter(pk__in=record_by_pk))
            found_pks = {obj.pk for obj in candidates}
            still_orphan_pks = [obj.pk for obj in candidates if obj.content_object is None]
            if still_orphan_pks:
                model.objects.using(using).filter(pk__in=still_orphan_pks).delete()
        except Exception:
            result.failed_batches += 1
            logger.exception(
                f"Failed to remove a batch of {len(records)} orphan {model_key} permissions; "
                "continuing with the next batch."
            )
            continue

        removed_pks = set(still_orphan_pks)
        result.removed_records.extend(record_by_pk[pk] for pk in still_orphan_pks)
        result.skipped_records.extend(
            record_by_pk[pk] for pk in record_by_pk if pk in found_pks and pk not in removed_pks
        )
        result.batches_processed += 1
        logger.info(
            f"Processed {model_key} batch {result.batches_processed}: "
            f"removed {len(still_orphan_pks)} of {len(records)} previewed entries."
        )

    logger.info(
        f"Finished orphan object permissions cleanup on database '{result.database}'. "
        f"Removed: {result.removed} | Skipped (targets restored): {result.skipped} | "
        f"Batches processed: {result.batches_processed} | Failed batches: {result.failed_batches}"
    )
    return result


# TODO: should raise error when multiple UserObjectPermission direct relations
# are defined


def get_obj_perms_model(obj: Model | None, base_cls: type[Model], generic_cls: type[Model]) -> type[Model]:
    """Return the matching object permission model for the obj class.

    Defaults to returning the generic object permission when no direct foreignkey is defined, or obj is None.
    """
    # Default to the generic object permission model
    # when None obj is provided
    if obj is None:
        return generic_cls

    if isinstance(obj, Model):
        obj = obj.__class__

    fields = (
        f
        for f in obj._meta.get_fields()  # type: ignore[union-attr] # obj is already checked for None
        if (f.one_to_many or f.one_to_one) and f.auto_created
    )

    for attr in fields:
        model = getattr(attr, "related_model", None)
        if model and issubclass(model, base_cls) and model is not generic_cls and getattr(model, "enabled", True):
            # if model is generic one it would be returned anyway
            if not model.objects.is_generic():
                # make sure that content_object's content_type is the same as
                # the one of given obj
                fk = model._meta.get_field("content_object")
                if get_content_type(obj) == get_content_type(fk.remote_field.model):
                    return model
    return generic_cls


def get_direct_obj_perms_models(base_cls: type[Model], generic_cls: type[Model]) -> list[type[Model]]:
    """Return every installed, enabled direct object permission model.

    A "direct" model is a subclass of `base_cls` that targets one specific
    model via a `content_object` foreign key, as opposed to `generic_cls`
    which stores permissions for any model via the contenttypes framework.
    Unlike `get_obj_perms_model`, this is not scoped to a single target
    model - it is used by prefetching, which has no single `obj` to resolve
    against and needs every direct model that might hold a match.
    """
    return [
        model
        for model in django_apps.get_models()
        if (
            issubclass(model, base_cls)
            and model is not generic_cls
            and not model._meta.abstract
            and not model._meta.proxy
            and getattr(model, "enabled", True)
            and not model.objects.is_generic()
            # Only the model that declares `content_object` itself owns the
            # relation; proxies and multi-table subclasses inherit it and would
            # query the same rows twice.
            and any(f.name == "content_object" for f in model._meta.local_fields)
        )
    ]


def get_user_obj_perms_model(obj: Model | None = None) -> type[Model]:
    """Returns model class that connects given `obj` and User class.

    If obj is not specified, then the user generic object permission model
    that is returned is determined by the guardian settings for 'USER_OBJ_PERMS_MODEL'.
    """
    from guardian.models import UserObjectPermissionBase

    UserObjectPermission = get_obj_perm_model_by_conf("USER_OBJ_PERMS_MODEL")
    return get_obj_perms_model(obj, UserObjectPermissionBase, UserObjectPermission)


def get_group_obj_perms_model(obj: Model | None = None) -> type[Model]:
    """Returns model class that connects given `obj` and Group class.

    If obj is not specified, then the group generic object permission model
    that is returned is determined by the guardian settings for 'GROUP_OBJ_PERMS_MODEL'.
    """
    from guardian.models import GroupObjectPermissionBase

    GroupObjectPermission = get_obj_perm_model_by_conf("GROUP_OBJ_PERMS_MODEL")
    return get_obj_perms_model(obj, GroupObjectPermissionBase, GroupObjectPermission)


def evict_obj_perms_cache(obj: Any) -> bool:
    if hasattr(obj, "_guardian_perms_cache"):
        delattr(obj, "_guardian_perms_cache")
        return True
    return False
