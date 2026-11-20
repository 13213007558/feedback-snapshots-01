from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db.models import Model
from django.utils.module_loading import import_string

from guardian.conf import settings as guardian_settings

PROXY_MODE_INHERIT = "inherit"
PROXY_MODE_ISOLATE = "isolate"

# Attribute a proxy model can set to override the project wide setting.
PROXY_MODE_ATTRIBUTE = "guardian_proxy_permission_mode"


def _resolve_model(obj: Model | type[Model]) -> type[Model] | None:
    if isinstance(obj, Model):
        return type(obj)
    if isinstance(obj, type) and issubclass(obj, Model):
        return obj
    return None


def get_proxy_permission_mode(obj: Model | type[Model]) -> str:
    """Return the proxy permission mode that applies to ``obj``.

    A proxy model can set ``guardian_proxy_permission_mode`` to ``"inherit"``
    or ``"isolate"``. When it does not, ``GUARDIAN_PROXY_PERMISSION_MODE``
    decides. The attribute follows normal Python inheritance, so a proxy
    subclass that declares nothing reuses its parent proxy's policy. Exactly
    like Django's own content type lookup, the mode only applies to the model
    class itself: a concrete subclass of a proxy is not treated as a proxy.
    """
    model = _resolve_model(obj)
    if model is None or not model._meta.proxy:
        return PROXY_MODE_INHERIT

    mode = getattr(model, PROXY_MODE_ATTRIBUTE, None)
    if mode is None:
        mode = getattr(guardian_settings, "PROXY_PERMISSION_MODE", PROXY_MODE_INHERIT)
    if mode not in (PROXY_MODE_INHERIT, PROXY_MODE_ISOLATE):
        raise ValueError(
            f"{model._meta.label}: {PROXY_MODE_ATTRIBUTE} must be either "
            f"'{PROXY_MODE_INHERIT}' or '{PROXY_MODE_ISOLATE}' (got {mode!r})"
        )
    return mode


def get_content_type(obj: Model | type[Model]) -> Any:
    get_content_type_function = import_string(guardian_settings.GET_CONTENT_TYPE)
    return get_content_type_function(obj)


def get_default_content_type(obj: Model | type[Model]) -> ContentType:
    """Get content type for a given object using Django's content type framework.

    Proxy models inherit their concrete model's content type, and therefore its
    object permissions, unless they opt into isolation. Opting in can be done
    per proxy with ``guardian_proxy_permission_mode = "isolate"`` or globally
    with ``GUARDIAN_PROXY_PERMISSION_MODE = "isolate"``.

    Parameters:
        obj (Model | type[Model]): Object for which content type is to be fetched.

    Returns:
        Content type for the given object.

    See Also:
        https://docs.djangoproject.com/en/5.1/ref/contrib/contenttypes/

    """
    model = _resolve_model(obj)
    if model is not None and model._meta.proxy and get_proxy_permission_mode(model) == PROXY_MODE_ISOLATE:
        return ContentType.objects.get_for_model(model, for_concrete_model=False)
    return ContentType.objects.get_for_model(obj)
