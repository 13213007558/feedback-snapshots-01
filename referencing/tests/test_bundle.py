from __future__ import annotations

import json

import pytest

from referencing import Registry, Resource, exceptions
from referencing import bundle as bundle_module
from referencing.bundle import bundle
from referencing.jsonschema import DRAFT202012
from referencing.retrieval import to_cached_resource

SCHEMA = {"$schema": "https://json-schema.org/draft/2020-12/schema"}


def schema(id, **body):
    return DRAFT202012.create_resource({"$id": id, **SCHEMA, **body})


class TestBundle:
    def test_bundles_a_single_root(self):
        root = schema("https://example.com/root", type="integer")
        registry = root @ Registry()

        got = bundle(registry, "https://example.com/root")

        assert got.complete
        assert got.roots == ("https://example.com/root",)
        assert got.included == ("https://example.com/root",)
        assert got.contents("https://example.com/root") == root.contents

    def test_includes_approved_transitive_dependency(self):
        root = schema("https://example.com/root", **{"$ref": "child"})
        child = schema("https://example.com/child", type="string")
        internal = schema("https://internal.example/secret", type="object")
        registry = [root, child, internal] @ Registry()

        got = bundle(
            registry,
            "https://example.com/root",
            allowed={"https://example.com/child"},
        )

        assert got.complete
        assert set(got) == {
            "https://example.com/root",
            "https://example.com/child",
        }
        assert "https://internal.example/secret" not in got

    def test_does_not_export_unapproved_cached_resources(self):
        public = schema("https://example.com/public", type="integer")
        internal = schema("https://internal.example/secret", type="object")
        retrieved = []

        def retrieve(uri):
            retrieved.append(uri)
            return internal

        registry = Registry(retrieve=retrieve).with_resource(
            "https://example.com/public",
            public,
        )
        registry = registry.get_or_retrieve(
            "https://internal.example/secret",
        ).registry
        assert registry.contents("https://internal.example/secret")

        got = bundle(registry, "https://example.com/public")

        assert got.complete
        assert set(got) == {"https://example.com/public"}
        assert retrieved == ["https://internal.example/secret"]
        assert "https://internal.example/secret" not in got

    def test_internal_dependency_is_reported_with_category_and_root(self):
        root = schema(
            "https://example.com/root",
            **{"$ref": "https://internal.example/secret"},
        )
        internal = schema("https://internal.example/secret", type="object")
        registry = [root, internal] @ Registry()

        with pytest.raises(exceptions.MissingDependencies) as excinfo:
            bundle(registry, "https://example.com/root")

        missing = excinfo.value.missing
        assert len(missing) == 1
        assert missing[0].kind is exceptions.MissingDependencyKind.RESTRICTED
        assert missing[0].uri == "https://internal.example/secret"
        assert missing[0].root == "https://example.com/root"
        assert excinfo.value.bundle is not None
        assert "https://internal.example/secret" not in excinfo.value.bundle

    def test_missing_resource_is_distinguished(self):
        root = schema(
            "https://example.com/root",
            **{"$ref": "https://example.com/not-there"},
        )
        registry = root @ Registry()

        got = bundle(registry, "https://example.com/root", strict=False)

        assert not got.complete
        assert [each.kind for each in got.missing] == [
            exceptions.MissingDependencyKind.RESOURCE,
        ]

    def test_missing_anchor_and_pointer(self):
        root = schema(
            "https://example.com/root",
            **{
                "allOf": [
                    {"$ref": "#missing"},
                    {"$ref": "#/nope"},
                ],
            },
        )
        registry = root @ Registry()

        got = bundle(registry, "https://example.com/root", strict=False)

        assert [each.kind for each in got.missing] == [
            exceptions.MissingDependencyKind.ANCHOR,
            exceptions.MissingDependencyKind.POINTER,
        ]

    def test_bundle_has_no_retriever(self):
        root = schema("https://example.com/root", type="integer")
        registry = Registry(
            retrieve=lambda uri: (_ for _ in ()).throw(AssertionError()),
        ).with_resource("https://example.com/root", root).crawl()

        got = bundle(registry, "https://example.com/root", retrieve=False)

        assert got.registry._retrieve is not registry._retrieve
        with pytest.raises(exceptions.NoSuchResource):
            got.registry.get_or_retrieve("https://example.com/unknown")

    def test_nested_ids_and_anchors_are_explained(self):
        root = schema(
            "https://example.com/root",
            **{
                "$defs": {
                    "leaf": {
                        "$id": "leaf",
                        "$anchor": "leaf-anchor",
                        "type": "string",
                    },
                },
            },
        )
        registry = root @ Registry()

        got = bundle(registry, "https://example.com/root")

        assert "https://example.com/leaf" in got
        assert got.contents("https://example.com/leaf") == {
            "$id": "leaf",
            "$anchor": "leaf-anchor",
            "type": "string",
        }
        anchor = got.anchor("https://example.com/leaf", "leaf-anchor")
        assert anchor.value.name == "leaf-anchor"

        info, = got.manifest
        assert info.uri == "https://example.com/root"
        assert info.resources == (
            "https://example.com/leaf",
            "https://example.com/root",
        )
        assert info.anchors == (("https://example.com/leaf", "leaf-anchor"),)
        assert info.missing == ()

    def test_approved_child_still_missing_internal_dependency(self):
        root = schema("https://example.com/root", **{"$ref": "child"})
        child = schema(
            "https://example.com/child",
            **{"$ref": "https://internal.example/secret"},
        )
        internal = schema("https://internal.example/secret", type="object")
        registry = [root, child, internal] @ Registry()

        got = bundle(
            registry,
            "https://example.com/root",
            allowed={"https://example.com/child"},
            strict=False,
        )

        assert not got.complete
        assert got.missing_for("https://example.com/root")[0].uri == (
            "https://internal.example/secret"
        )
        assert "https://example.com/child" in got
        assert "https://internal.example/secret" not in got

    def test_specification_references(self):
        specification = DRAFT202012
        assert list(
            specification.references_of(
                {"$ref": "a", "$dynamicRef": "b"},
            ),
        ) == ["a", "b"]
        assert list(specification.references_of(True)) == []
        assert list(specification.references_of({"$ref": 37})) == []

        assert specification.has_anchor({"$anchor": "a"}, "a")
        assert specification.has_anchor(
            {"$defs": {"x": {"$anchor": "a"}}},
            "a",
        )
        assert not specification.has_anchor({"$anchor": "b"}, "a")

    def test_bundle_module_export_returns_registry(self):
        root = schema("https://example.com/root", type="integer")
        registry = root @ Registry()

        exported = bundle_module.export(registry, "https://example.com/root")

        assert isinstance(exported, Registry)

    def test_offline_result_matches_online(self):
        root = schema(
            "https://example.com/root",
            **{
                "$defs": {
                    "leaf": {"$id": "leaf", "$anchor": "a", "type": "string"},
                },
                "$ref": "leaf#a",
            },
        )
        registry = root @ Registry()
        online = registry.resolver().lookup("https://example.com/root")

        offline = bundle(registry, "https://example.com/root")
        got = offline.resolver().lookup("https://example.com/root")

        assert got.contents == online.contents
        leaf = offline.resolver().lookup("https://example.com/leaf#a")
        assert leaf.contents == {
            "$id": "leaf",
            "$anchor": "a",
            "type": "string",
        }

    def test_prewarm_then_package_and_keep_source_working(self):
        contents = {
            "https://example.com/public": {
                "$id": "https://example.com/public",
                **SCHEMA,
                "$ref": "https://example.com/child",
            },
            "https://example.com/child": {
                "$id": "https://example.com/child",
                **SCHEMA,
                "type": "string",
            },
            "https://internal.example/secret": {
                "$id": "https://internal.example/secret",
                **SCHEMA,
                "type": "object",
            },
        }
        calls = []

        @to_cached_resource()
        def retrieve(uri):
            calls.append(uri)
            return json.dumps(contents[uri])

        shared = Registry(retrieve=retrieve)
        for uri in contents:
            shared = shared.get_or_retrieve(uri).registry
        assert len(calls) == 3

        package = bundle(
            shared,
            "https://example.com/public",
            allowed={"https://example.com/child"},
        )

        assert calls == list(contents)
        assert package.complete
        assert package.registry._retrieve is not retrieve
        assert "https://internal.example/secret" not in package
        resolved = package.resolver().lookup("https://example.com/public")
        assert resolved.contents == contents["https://example.com/public"]
        assert shared.contents("https://internal.example/secret") == contents[
            "https://internal.example/secret"
        ]

    def test_missing_root_is_reported(self):
        got = bundle(Registry(), "https://example.com/absent", strict=False)

        assert got.included == ()
        assert got.missing[0].kind is exceptions.MissingDependencyKind.RESOURCE
        assert got.missing[0].root == "https://example.com/absent"

    def test_retrieve_false_does_not_call_retriever(self):
        calls = []

        def retrieve(uri):
            calls.append(uri)
            return schema(uri, type="integer")

        registry = Registry(retrieve=retrieve)

        got = bundle(
            registry,
            "https://example.com/root",
            retrieve=False,
            strict=False,
        )

        assert calls == []
        assert got.missing[0].kind is (
            exceptions.MissingDependencyKind.RESTRICTED
        )

    def test_approved_root_may_be_retrieved(self):
        def retrieve(uri):
            return schema(uri, type="integer")

        registry = Registry(retrieve=retrieve)

        got = bundle(registry, "https://example.com/root")

        assert got.complete
        assert got.contents("https://example.com/root") == {
            "$id": "https://example.com/root",
            **SCHEMA,
            "type": "integer",
        }

    def test_export_returns_registry(self):
        root = schema("https://example.com/root", type="integer")
        registry = root @ Registry()

        exported = registry.export("https://example.com/root")

        assert isinstance(exported, Registry)
        assert exported.contents("https://example.com/root") == root.contents

    def test_registry_bundle_delegates(self):
        root = schema("https://example.com/root", type="integer")
        registry = root @ Registry()

        got = registry.bundle("https://example.com/root")

        assert got.complete
        assert got.contents("https://example.com/root") == root.contents

    def test_allowed_callable_approves_dependencies(self):
        root = schema("https://example.com/root", **{"$ref": "child"})
        child = schema("https://example.com/child", type="string")
        registry = [root, child] @ Registry()

        got = bundle(
            registry,
            "https://example.com/root",
            allowed=lambda uri: uri.startswith("https://example.com/"),
        )

        assert got.complete
        assert "https://example.com/child" in got

    def test_deliverable_controls_dependencies(self):
        root = schema("https://example.com/root", **{"$ref": "child"})
        child = schema("https://example.com/child", type="string")
        registry = [root, child] @ Registry()

        got = bundle(
            registry,
            "https://example.com/root",
            deliverable=lambda uri: uri.endswith("/child"),
        )

        assert got.complete

    def test_partial_export_returns_usable_registry(self):
        root = schema(
            "https://example.com/root",
            **{
                "allOf": [
                    {"$ref": "https://example.com/ok"},
                    {"$ref": "https://internal.example/secret"},
                ],
            },
        )
        ok = schema("https://example.com/ok", type="integer")
        internal = schema("https://internal.example/secret", type="object")
        registry = [root, ok, internal] @ Registry()

        exported = registry.export(
            "https://example.com/root",
            allowed={"https://example.com/ok"},
            strict=False,
        )

        assert exported.contents("https://example.com/ok") == ok.contents
        assert "https://internal.example/secret" not in exported

    def test_missing_category_for_unavailable_dependency(self):
        root = schema(
            "https://example.com/root",
            **{"$ref": "https://example.com/remote"},
        )

        def retrieve(uri):
            raise RuntimeError("network is down")

        registry = Registry(
            retrieve=retrieve,
        ).with_resource("https://example.com/root", root)

        got = bundle(
            registry,
            "https://example.com/root",
            allowed={"https://example.com/remote"},
            strict=False,
        )

        assert got.missing[0].kind is (
            exceptions.MissingDependencyKind.UNAVAILABLE
        )

    def test_bool_and_len(self):
        root = schema("https://example.com/root", type="integer")
        registry = root @ Registry()

        got = bundle(registry, "https://example.com/root")

        assert got
        assert len(got) == 1
        assert list(got) == ["https://example.com/root"]

    def test_relative_ids_are_resolved_from_their_root(self):
        root = schema(
            "https://example.com/root",
            **{
                "$defs": {
                    "leaf": {
                        "$id": "leaf",
                        "type": "string",
                        "$ref": "other",
                    },
                },
            },
        )
        other = schema("https://example.com/other", type="integer")
        registry = [root, other] @ Registry()

        got = bundle(
            registry,
            "https://example.com/root",
            allowed={"https://example.com/other"},
        )

        assert "https://example.com/leaf" in got
        assert got.resolver().lookup("https://example.com/leaf").contents == {
            "$id": "leaf",
            "type": "string",
            "$ref": "other",
        }


class TestAcceptanceScenario:
    """
    A prewarmed shared registry, then a package-only offline reader.
    """

    def shared(self):
        contents = {
            "https://example.com/good": {
                "$id": "https://example.com/good",
                **SCHEMA,
                "$ref": "https://example.com/shared",
            },
            "https://example.com/shared": {
                "$id": "https://example.com/shared",
                **SCHEMA,
                "$defs": {
                    "leaf": {
                        "$id": "https://example.com/leaf",
                        "$anchor": "leaf",
                        "type": "string",
                    },
                },
            },
            "https://example.com/broken": {
                "$id": "https://example.com/broken",
                **SCHEMA,
                "$ref": "https://internal.example/secret",
            },
            "https://internal.example/secret": {
                "$id": "https://internal.example/secret",
                **SCHEMA,
                "type": "object",
            },
        }
        calls = []

        @to_cached_resource()
        def retrieve(uri):
            calls.append(uri)
            return json.dumps(contents[uri])

        shared = Registry(retrieve=retrieve)
        for uri in contents:
            shared = shared.get_or_retrieve(uri).registry
        assert len(calls) == len(contents)
        return shared, contents, calls

    def test_good_root_works_fully_offline(self):
        shared, contents, _ = self.shared()

        package = bundle(
            shared,
            "https://example.com/good",
            allowed={
                "https://example.com/shared",
                "https://example.com/leaf",
            },
        )

        offline = package.registry
        assert offline._retrieve is not shared._retrieve
        assert "https://internal.example/secret" not in offline
        resolved = package.resolver().lookup("https://example.com/good")
        assert resolved.contents == contents["https://example.com/good"]
        leaf = package.resolver().lookup("https://example.com/leaf#leaf")
        assert leaf.contents["type"] == "string"

        info = {each.uri: each for each in package.manifest}
        assert info["https://example.com/good"].resources == (
            "https://example.com/good",
            "https://example.com/leaf",
            "https://example.com/shared",
        )
        assert ("https://example.com/leaf", "leaf") in info[
            "https://example.com/good"
        ].anchors

    def test_broken_root_locates_missing_category(self):
        shared, _, _ = self.shared()

        package = bundle(
            shared,
            "https://example.com/broken",
            strict=False,
        )

        assert not package.complete
        (missing,) = package.missing
        assert missing.kind is exceptions.MissingDependencyKind.RESTRICTED
        assert missing.root == "https://example.com/broken"
        assert missing.uri == "https://internal.example/secret"
        assert "https://internal.example/secret" not in package

    def test_internal_resource_is_not_in_package(self):
        shared, _, _ = self.shared()

        package = bundle(
            shared,
            "https://example.com/good",
            allowed={
                "https://example.com/shared",
                "https://example.com/leaf",
            },
        )

        for uri in package:
            assert not uri.startswith("https://internal.example/")

    def test_shared_registry_keeps_serving(self):
        shared, contents, _ = self.shared()

        bundle(shared, "https://example.com/good", strict=False)

        assert shared.contents("https://internal.example/secret") == contents[
            "https://internal.example/secret"
        ]
