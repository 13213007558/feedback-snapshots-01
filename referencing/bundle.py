"""
Controlled, offline export of a subset of a `Registry`.

Bundling differs from simply handing over a registry: only explicitly
approved roots (and approved dependencies) are considered, the resulting
registry never retains a retrieval callback, and dependencies which cannot be
delivered are reported rather than silently retrieved.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any, Generic
from urllib.parse import urldefrag, urljoin

from referencing import exceptions
from referencing._attrs import frozen
from referencing._core import (
    _fail_to_retrieve,
    Anchor,
    Registry,
    Resource,
    Resolver,
    Retrieved,
)
from referencing.typing import URI, D

_EMPTY: tuple[Any, ...] = ()


def _normalize(uri: URI) -> URI:
    return uri.rstrip("#")


def _as_uris(
    roots: URI | Iterable[URI] | None,
    additional: Iterable[URI] = (),
) -> tuple[URI, ...]:
    if roots is None:
        roots = ()
    elif isinstance(roots, str):
        roots = (roots,)
    return tuple(
        dict.fromkeys(_normalize(each) for each in (*roots, *additional)),
    )


def _as_allowed(
    allowed: Iterable[URI] | Callable[[URI], bool] | None,
) -> tuple[set[URI], Callable[[URI], bool] | None]:
    if allowed is None:
        return set(), None
    if callable(allowed):
        return set(), allowed
    return {_normalize(each) for each in allowed}, None


@frozen
class RootInfo:
    """
    An explanation of what an approved root contributes to a bundle.

    :ivar uri: the root URI which was approved
    :ivar resources: the root's own URI, its canonical ID, and any nested IDs
    :ivar anchors: each ``(resource URI, anchor name)`` within the root
    :ivar missing: dependencies of the root which could not be exported
    """

    uri: URI
    resources: tuple[URI, ...] = _EMPTY
    anchors: tuple[tuple[URI, str], ...] = _EMPTY
    missing: tuple[exceptions.MissingDependency, ...] = _EMPTY


@frozen
class Bundle(Generic[D]):
    """
    A self-contained registry produced by a controlled export.

    The bundled `registry` has no retrieval callback, so it can only resolve
    references to resources actually present within it.

    :ivar registry: the standalone registry containing the exported closure
    :ivar roots: the approved root URIs which were requested
    :ivar included: all URIs in the closure (including nested IDs and aliases)
    :ivar missing: dependencies which could not be delivered
    :ivar info: per-root explanations of nested IDs and anchors
    """

    registry: Registry[D]
    roots: tuple[URI, ...]
    included: tuple[URI, ...]
    missing: tuple[exceptions.MissingDependency, ...] = _EMPTY
    info: tuple[RootInfo, ...] = _EMPTY

    @property
    def complete(self) -> bool:
        """
        Whether every dependency of every approved root was exported.
        """
        return not self.missing

    @property
    def manifest(self) -> tuple[RootInfo, ...]:
        """
        Per-root explanations of the bundled roots, in request order.
        """
        return self.info

    @property
    def retrieval_allowed(self) -> bool:
        """
        Whether this bundle retains a retrieval function (it never does).
        """
        return False

    def __bool__(self) -> bool:
        return self.complete

    def __len__(self) -> int:
        return len(self.included)

    def __iter__(self) -> Iterator[URI]:
        return iter(self.included)

    def __contains__(self, uri: object) -> bool:
        return uri in self.registry

    def __getitem__(self, uri: URI) -> Resource[D]:
        return self.registry[uri]

    def get_or_retrieve(self, uri: URI) -> Retrieved[D, Resource[D]]:
        """
        Retrieve a resource from the bundle (never from the network).
        """
        return self.registry.get_or_retrieve(uri)

    def anchors(self) -> Mapping[tuple[URI, str], Anchor[D]]:
        """
        Return the anchors (and dynamic anchors) in the bundled resources.
        """
        return dict(self.registry._anchors)

    def contents(self, uri: URI) -> D:
        """
        Retrieve the already-crawled contents identified by the given URI.
        """
        return self.registry.contents(uri)

    def anchor(
        self,
        uri: URI,
        name: str,
    ) -> Retrieved[D, Anchor[D]]:
        """
        Retrieve an anchor from the packaged resources.
        """
        return self.registry.anchor(uri, name)

    def resolver(self, base_uri: URI = "") -> Resolver[D]:
        """
        Return a resolver backed only by this bundle's contents.
        """
        return self.registry.resolver(base_uri=base_uri)

    def missing_for(
        self,
        root: URI,
    ) -> tuple[exceptions.MissingDependency, ...]:
        """
        Return the missing dependencies of a particular approved root.
        """
        root = _normalize(root)
        return tuple(each for each in self.missing if each.root == root)

    def raise_for_missing(self) -> None:
        """
        Raise `referencing.exceptions.MissingDependencies` if incomplete.
        """
        if self.missing:
            raise exceptions.MissingDependencies(
                self.missing,
                bundle=self,
            )


class _Exporter(Generic[D]):
    def __init__(
        self,
        registry: Registry[D],
        roots: tuple[URI, ...],
        allowed: set[URI],
        deliverable: Callable[[URI], bool] | None,
        retrieve: bool,
    ) -> None:
        self._source = registry.crawl()
        self._roots = roots
        self._approved_roots = set(roots)
        self._allowed = allowed
        self._deliverable = deliverable
        self._retrieve = retrieve

        self._included: dict[URI, Resource[D]] = {}
        self._nested: set[URI] = set()
        self._scanned: set[tuple[int, URI]] = set()
        self._root_resources: dict[URI, Resource[D]] = {}
        self._missing: list[exceptions.MissingDependency] = []
        self._missing_seen: set[tuple[Any, URI, URI]] = set()
        self._references: list[
            tuple[URI, URI, Resource[D], URI, URI]
        ] = []

    def run(self) -> Bundle[D]:
        all_included: dict[URI, Resource[D]] = {}
        all_missing: list[exceptions.MissingDependency] = []
        all_missing_seen: set[tuple[Any, URI, URI]] = set()
        infos: list[RootInfo] = []

        for root in self._roots:
            self._reset()
            resource, kind = self._obtain(root, is_root=True)
            if resource is None:
                self._add_missing(kind, uri=root, ref=root, root=root)
                all_missing.extend(self._missing)
                all_missing_seen.update(self._missing_seen)
                infos.append(RootInfo(uri=root, missing=tuple(self._missing)))
                continue

            self._root_resources[root] = resource
            self._scan(
                resource,
                base_uri=root,
                origin=root,
                alias=root,
                top_level=True,
            )

            index = 0
            while index < len(self._references):
                ref, base_uri, resource, origin, current_uri = (
                    self._references[index]
                )
                index += 1
                self._follow(
                    ref=ref,
                    base_uri=base_uri,
                    resource=resource,
                    origin=origin,
                    current_uri=current_uri,
                )

            for uri, each in self._included.items():
                all_included.setdefault(uri, each)
            for each in self._missing:
                key = (each.kind, each.uri, each.root)
                if key not in all_missing_seen:
                    all_missing_seen.add(key)
                    all_missing.append(each)
            infos.append(
                self._describe(
                    root,
                    resource,
                    tuple(self._included),
                    self._reachable(resource, root),
                ),
            )

        registry = Registry().with_resources(all_included.items()).crawl()
        included = tuple(sorted(registry))
        return Bundle(
            registry=registry,
            roots=self._roots,
            included=included,
            missing=tuple(all_missing),
            info=tuple(infos),
        )

    def _reset(self) -> None:
        self._included = {}
        self._nested = set()
        self._scanned = set()
        self._root_resources = {}
        self._missing = []
        self._missing_seen = set()
        self._references = []

    def _scan(
        self,
        resource: Resource[D],
        *,
        base_uri: URI,
        origin: URI,
        alias: URI | None,
        top_level: bool,
    ) -> None:
        identifier = resource.id()
        if identifier is not None:
            base_uri = _normalize(urljoin(base_uri, identifier))

        key = (id(resource), base_uri)
        if key in self._scanned:
            if alias is not None:
                self._included.setdefault(alias, resource)
            return
        self._scanned.add(key)

        self._included.setdefault(base_uri, resource)
        if alias is not None:
            self._included.setdefault(alias, resource)
        if not top_level:
            self._nested.add(base_uri)

        for ref in resource._specification.references_of(resource.contents):
            self._references.append(
                (ref, base_uri, resource, origin, base_uri),
            )

        for subresource in resource.subresources():
            self._scan(
                subresource,
                base_uri=base_uri,
                origin=origin,
                alias=None,
                top_level=False,
            )

    def _follow(
        self,
        ref: URI,
        base_uri: URI,
        resource: Resource[D],
        origin: URI,
        current_uri: URI,
    ) -> None:
        if ref.startswith("#"):
            target_uri = current_uri
            fragment = ref[1:]
            target = resource
            kind = None
        else:
            target_uri, fragment = urldefrag(urljoin(base_uri, ref))
            target_uri = _normalize(target_uri)
            target, kind = self._obtain(target_uri)

        if target is None:
            if target_uri in self._nested:
                return
            self._add_missing(
                kind or exceptions.MissingDependencyKind.RESOURCE,
                uri=target_uri,
                ref=ref,
                root=origin,
            )
            return

        if not self._exportable(target_uri, target):
            self._add_missing(
                exceptions.MissingDependencyKind.RESTRICTED,
                uri=target_uri,
                ref=ref,
                root=origin,
            )
            return

        if not self._validate(
            target_uri,
            fragment,
            target=target,
            ref=ref,
            root=origin,
        ):
            return

        if target_uri in self._included:
            return
        if any(each is target for each in self._included.values()):
            self._included.setdefault(target_uri, target)
            return
        self._scan(
            target,
            base_uri=target_uri,
            origin=origin,
            alias=target_uri,
            top_level=True,
        )

    def _obtain(
        self,
        uri: URI,
        *,
        is_root: bool = False,
    ) -> tuple[Resource[D] | None, exceptions.MissingDependencyKind | None]:
        resource = self._source._resources.get(uri)
        if resource is not None:
            return resource, None

        if not is_root and not self._is_allowed(uri):
            return None, self._restricted_kind()

        if not self._retrieve:
            return None, self._restricted_kind()

        try:
            retrieved = self._source.get_or_retrieve(uri)
        except exceptions.NoSuchResource:
            return None, exceptions.MissingDependencyKind.RESOURCE
        except (
            exceptions.CannotDetermineSpecification,
            exceptions.Unretrievable,
        ):
            return None, exceptions.MissingDependencyKind.UNAVAILABLE
        self._source = retrieved.registry.crawl()
        return retrieved.value, None

    def _restricted_kind(self) -> exceptions.MissingDependencyKind:
        if self._source._retrieve is _fail_to_retrieve:
            return exceptions.MissingDependencyKind.RESOURCE
        return exceptions.MissingDependencyKind.RESTRICTED

    def _is_allowed(self, uri: URI) -> bool:
        if uri in self._approved_roots or uri in self._allowed:
            return True
        if self._deliverable is not None and self._deliverable(uri):
            return True
        return False

    def _exportable(self, uri: URI, resource: Resource[D]) -> bool:
        if uri in self._included or uri in self._nested:
            return True
        if self._is_allowed(uri):
            return True
        return any(each is resource for each in self._included.values())

    def _validate(
        self,
        target_uri: URI,
        fragment: str,
        *,
        target: Resource[D],
        ref: URI,
        root: URI,
    ) -> bool:
        if not fragment:
            return True

        if fragment.startswith("/"):
            try:
                target.pointer(
                    pointer=fragment,
                    resolver=self._source.resolver(base_uri=target_uri),
                )
            except (exceptions.PointerToNowhere, ValueError):
                self._add_missing(
                    exceptions.MissingDependencyKind.POINTER,
                    uri=target_uri,
                    ref=ref,
                    root=root,
                )
                return False
            return True

        if "/" in fragment:
            self._add_missing(
                exceptions.MissingDependencyKind.ANCHOR,
                uri=target_uri,
                ref=ref,
                root=root,
            )
            return False
        if target._specification.has_anchor(target.contents, fragment):
            return True
        if self._has_anchor(target_uri, fragment, target):
            return True
        self._add_missing(
            exceptions.MissingDependencyKind.ANCHOR,
            uri=target_uri,
            ref=ref,
            root=root,
        )
        return False

    def _has_anchor(
        self,
        uri: URI,
        name: str,
        target: Resource[D],
    ) -> bool:
        if (uri, name) in self._source._anchors:
            return True
        canonical = _normalize(target.id() or "")
        if canonical and (canonical, name) in self._source._anchors:
            return True
        return self._anchors_in(target, uri, name, set())

    def _anchors_in(
        self,
        resource: Resource[D],
        base_uri: URI,
        name: str,
        seen: set[int],
    ) -> bool:
        if id(resource) in seen:
            return False
        seen.add(id(resource))
        identifier = resource.id()
        if identifier is not None:
            base_uri = _normalize(urljoin(base_uri, identifier))
        if any(each.name == name for each in resource.anchors()):
            return True
        return any(
            self._anchors_in(each, base_uri, name, seen)
            for each in resource.subresources()
        )

    def _reachable(self, resource: Resource[D], root: URI) -> set[URI]:
        resources: set[URI] = set()
        seen: set[int] = set()

        def walk(each: Resource[D], base_uri: URI) -> None:
            if id(each) in seen:
                return
            seen.add(id(each))
            identifier = each.id()
            if identifier is not None:
                base_uri = _normalize(urljoin(base_uri, identifier))
            resources.add(base_uri)
            for ref in each._specification.references_of(each.contents):
                if ref.startswith("#"):
                    continue
                target_uri = _normalize(
                    urldefrag(urljoin(base_uri, ref))[0],
                )
                target = self._source._resources.get(target_uri)
                if target is not None:
                    walk(target, target_uri)
            for subresource in each.subresources():
                walk(subresource, base_uri)

        walk(resource, root)
        return resources

    def _describe(
        self,
        root: URI,
        resource: Resource[D],
        included: tuple[URI, ...],
        reachable: set[URI],
    ) -> RootInfo:
        resources: set[URI] = {root}
        anchors: set[tuple[URI, str]] = set()
        seen: set[int] = set()

        def walk(each: Resource[D], base_uri: URI) -> None:
            if id(each) in seen:
                return
            seen.add(id(each))
            identifier = each.id()
            if identifier is not None:
                base_uri = _normalize(urljoin(base_uri, identifier))
            if base_uri in reachable or base_uri == root:
                resources.add(base_uri)
                for anchor in each.anchors():
                    anchors.add((base_uri, anchor.name))
            for subresource in each.subresources():
                walk(subresource, base_uri)

        walk(resource, root)
        for uri in reachable:
            if uri not in resources and uri in included:
                resources.add(uri)
                each = self._source._resources.get(uri)
                if each is not None:
                    for anchor in each.anchors():
                        anchors.add((uri, anchor.name))
        missing = tuple(
            each
            for each in self._missing
            if each.root == root
            and (
                each.kind
                in {
                    exceptions.MissingDependencyKind.ANCHOR,
                    exceptions.MissingDependencyKind.POINTER,
                }
                or each.uri not in included
            )
        )
        return RootInfo(
            uri=root,
            resources=tuple(sorted(resources)),
            anchors=tuple(sorted(anchors)),
            missing=missing,
        )

    def _add_missing(
        self,
        kind: exceptions.MissingDependencyKind,
        *,
        uri: URI,
        ref: URI,
        root: URI,
    ) -> None:
        uri = _normalize(uri)
        key = (kind, uri, root)
        if key in self._missing_seen:
            return
        self._missing_seen.add(key)
        self._missing.append(
            exceptions.MissingDependency(
                kind=kind,
                uri=uri,
                ref=ref,
                root=root,
            ),
        )


def bundle(
    registry: Registry[D],
    roots: URI | Iterable[URI],
    *,
    allowed: Iterable[URI] | Callable[[URI], bool] = (),
    deliverable: Callable[[URI], bool] | None = None,
    retrieve: bool = True,
    strict: bool = True,
) -> Bundle[D]:
    """
    Export the given roots, and their approved dependencies, from a registry.

    Only the given roots and dependencies listed in ``allowed`` (or for which
    ``deliverable`` returns true) are exported. Nested resources with their own
    IDs, as well as anchors, are included automatically with the resource which
    contains them.

    The returned `Bundle`'s registry has no retrieval callback, so it operates
    entirely offline.

    Retrieval is only attempted for approved resources, and ``retrieve=False``
    forbids it entirely, in which case only resources already present in the
    registry are exported. In either case the returned bundle has no
    retrieval function of its own.

    Raises:

        `referencing.exceptions.MissingDependencies`

            if ``strict`` is true and a dependency could not be exported. The
            exception identifies each missing dependency, its category, and the
            approved root which needs it.

    """
    allowed_uris, allowed_predicate = _as_allowed(allowed)
    if deliverable is None:
        deliverable = allowed_predicate
    result = _Exporter(
        registry=registry,
        roots=_as_uris(roots),
        allowed=allowed_uris,
        deliverable=deliverable,
        retrieve=retrieve,
    ).run()
    if strict:
        result.raise_for_missing()
    return result


def export(
    registry: Registry[D],
    roots: URI | Iterable[URI],
    **kwargs: Any,
) -> Registry[D]:
    """
    Export a controlled bundle and return only its standalone registry.
    """
    return bundle(registry, roots, **kwargs).registry
