"""A registry of :class:`Schema <marshmallow.Schema>` classes. This allows for string
lookup of schemas, which may be used with
:class:`fields.Nested <marshmallow.fields.Nested>`.

.. warning::

    This module is treated as private API.
    Users should not need to use this module directly.
"""
# ruff: noqa: ERA001

from __future__ import annotations

import typing

from marshmallow.exceptions import RegistryError

if typing.TYPE_CHECKING:
    from marshmallow import Schema

    SchemaType = type[Schema]

# {
#   <class_name>: <list of class objects>
#   <module_path_to_class>: <list of class objects>
# }
_registry = {}  # type: dict[str, list[SchemaType]]


def register(classname: str, cls: SchemaType) -> None:
    """Add a class to the registry of serializer classes. When a class is
    registered, an entry for both its classname and its full, module-qualified
    path are added to the registry.

    Example: ::

        class MyClass:
            pass


        register("MyClass", MyClass)
        # Registry:
        # {
        #   'MyClass': [path.to.MyClass],
        #   'path.to.MyClass': [path.to.MyClass],
        # }

    """
    # Module where the class is located
    module = cls.__module__
    # Full module path to the class
    # e.g. user.schemas.UserSchema
    fullpath = f"{module}.{classname}"
    # If the class is already registered; need to check if the entries are
    # in the same module as cls to avoid having multiple instances of the same
    # class in the registry
    if classname in _registry and not any(
        each.__module__ == module for each in _registry[classname]
    ):
        _registry[classname].append(cls)
    elif classname not in _registry:
        _registry[classname] = [cls]

    # Also register the full path
    if fullpath not in _registry:
        _registry.setdefault(fullpath, []).append(cls)
    else:
        # If fullpath does exist, replace existing entry
        _registry[fullpath] = [cls]


@typing.overload
def get_class(classname: str, *, all: typing.Literal[False] = ...) -> SchemaType: ...


@typing.overload
def get_class(
    classname: str, *, all: typing.Literal[True] = ...
) -> list[SchemaType]: ...


def get_class(classname: str, *, all: bool = False) -> list[SchemaType] | SchemaType:  # noqa: A002
    """Retrieve a class from the registry.

    :raises: `marshmallow.exceptions.RegistryError` if the class cannot be found
        or if there are multiple entries for the given class name.
    """
    try:
        classes = _registry[classname]
    except KeyError as error:
        raise RegistryError(
            f"Class with name {classname!r} was not found. You may need "
            "to import the class."
        ) from error
    if len(classes) > 1:
        if all:
            return _registry[classname]
        raise RegistryError(
            f"Multiple classes with name {classname!r} "
            "were found. Please use the full, "
            "module-qualified path."
        )
    return _registry[classname][0]


class Registry:
    """An isolated namespace for resolving schemas by name.

    A plugin owns its own `Registry` and declares it on every schema it ships
    through ``class Meta: registry = <instance>``. Those schemas are recorded
    here instead of the process-wide :data:`_registry`, and string references
    in :class:`fields.Nested <marshmallow.fields.Nested>` are then resolved
    only against this instance. Two plugins may therefore declare nested types
    that share a name (for example both call theirs ``"Invoice"``) without
    colliding, and resolution never depends on the order in which plugins are
    imported.

    Authorization is membership based: a name can only be resolved when a class
    has been registered in this registry. Referencing a name that lives in the
    global registry or in another plugin's registry is rejected with a
    `~marshmallow.exceptions.RegistryError`, so a plugin can never silently pick
    up another plugin's type. Re-registering a class from the same module
    replaces the previous entry, so reloading a plugin only ever mutates its
    own registry.
    """

    def __init__(self, name: str | None = None) -> None:
        # Optional label used purely to make scoped error messages readable.
        self.name = name
        # {
        #   <class_name>: <list of class objects>
        #   <module_path_to_class>: <list of class objects>
        # }
        self._registry: dict[str, list[SchemaType]] = {}

    def register(self, classname: str, cls: SchemaType) -> None:
        """Add a class to this isolated registry.

        Both the bare class name and the full, module-qualified path are
        recorded, mirroring :func:`register`. A class re-declared from the same
        module (e.g. when the plugin is reloaded) replaces the previous entry
        rather than accumulating; classes of the same name from different
        modules are kept as separate entries.
        """
        module = cls.__module__
        fullpath = f"{module}.{classname}"

        existing = self._registry.get(classname)
        if existing is None:
            self._registry[classname] = [cls]
        elif any(each.__module__ == module for each in existing):
            # Reload of the same module: swap in the new class in place.
            self._registry[classname] = [
                cls if each.__module__ == module else each for each in existing
            ]
        else:
            existing.append(cls)

        # The full path always points at a single class and is replaced on
        # reload, so it can never become ambiguous.
        self._registry[fullpath] = [cls]

    @typing.overload
    def get_class(
        self, classname: str, *, all: typing.Literal[False] = ...
    ) -> SchemaType: ...

    @typing.overload
    def get_class(
        self, classname: str, *, all: typing.Literal[True] = ...
    ) -> list[SchemaType]: ...

    def get_class(
        self,
        classname: str,
        *,
        all: bool = False,  # noqa: A002
    ) -> list[SchemaType] | SchemaType:
        """Retrieve a class registered in this isolated registry.

        :raises: `marshmallow.exceptions.RegistryError` if the name has not been
            registered (and therefore has not been authorized) in this scope,
            or if several entries match the bare class name.
        """
        try:
            classes = self._registry[classname]
        except KeyError as error:
            scope = f" {self.name!r}" if self.name else ""
            raise RegistryError(
                f"Class with name {classname!r} is not registered or authorized "
                f"in registry{scope}. Register it with this plugin's registry "
                "before referencing it from a Nested field."
            ) from error
        if len(classes) > 1:
            if all:
                return classes
            raise RegistryError(
                f"Multiple classes with name {classname!r} were found in "
                "registry. Please use the full, module-qualified path."
            )
        return classes[0]
