"""Isolation guarantees when several configured ``Schema`` instances coexist.

A single process often keeps multiple instances of the same schema class alive
at the same time: one is configured to (de)serialize internal attributes while
another one is only used for public responses. These tests pin down that
constructing a new instance, or materializing a nested schema, never changes the
field visibility of the instances that were already in use.

They combine inheritance, external aliases and nested schemas and exercise
repeated ``load``/``dump`` cycles, so a regression that keeps the parent field
table intact but mutates an already cached child schema is still detected.
"""

from marshmallow import EXCLUDE, Schema, fields

ALL_CHILD_FIELDS = ("id", "public", "secret")
PUBLIC_CHILD_FIELDS = ("id", "public")

FULL_PAYLOAD = {"id": 1, "public": "public-value", "secret": "internal-value"}
PUBLIC_PAYLOAD = {"id": 1, "public": "public-value"}


class ChildSchema(Schema):
    """Schema exposing one internal field alongside the public ones."""

    id = fields.Int()
    public = fields.Str()
    secret = fields.Str()

    class Meta:
        unknown = EXCLUDE


def field_names(schema):
    return set(schema.fields)


def load_names(schema):
    return set(schema.load_fields)


def dump_names(schema):
    return set(schema.dump_fields)


class TestSiblingInstances:
    """Instances of the same class configured with different visibility."""

    def test_only_exclude_and_full_instances_keep_their_own_fields(self):
        public = ChildSchema(only=PUBLIC_CHILD_FIELDS)
        excluded = ChildSchema(exclude=("secret",))
        internal = ChildSchema()

        assert field_names(public) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(excluded) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(internal) == set(ALL_CHILD_FIELDS)

    def test_building_a_later_instance_does_not_change_earlier_ones(self):
        public = ChildSchema(only=PUBLIC_CHILD_FIELDS)
        internal = ChildSchema()

        # Construct additional instances after the first two have been used.
        public.dump(FULL_PAYLOAD)
        internal.dump(FULL_PAYLOAD)
        ChildSchema(exclude=("public", "secret"))
        ChildSchema(only=("id",))

        assert field_names(public) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(internal) == set(ALL_CHILD_FIELDS)
        assert public.dump(FULL_PAYLOAD) == PUBLIC_PAYLOAD
        assert internal.dump(FULL_PAYLOAD) == FULL_PAYLOAD

    def test_repeated_load_and_dump_keep_visibility_stable(self):
        public = ChildSchema(only=PUBLIC_CHILD_FIELDS)
        internal = ChildSchema()

        for _ in range(5):
            assert public.dump(FULL_PAYLOAD) == PUBLIC_PAYLOAD
            assert internal.dump(FULL_PAYLOAD) == FULL_PAYLOAD
            assert public.load(FULL_PAYLOAD) == PUBLIC_PAYLOAD
            assert internal.load(FULL_PAYLOAD) == FULL_PAYLOAD

        assert field_names(public) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(internal) == set(ALL_CHILD_FIELDS)

    def test_instances_do_not_share_their_field_dictionaries(self):
        first = ChildSchema(only=PUBLIC_CHILD_FIELDS)
        second = ChildSchema()

        assert first.fields is not second.fields
        assert first.load_fields is not second.load_fields
        assert first.dump_fields is not second.dump_fields
        assert first.declared_fields is not second.declared_fields


class TestInheritance:
    """Subclass configuration must not reach back into the parent schema."""

    def test_subclass_exclude_and_extra_field_leave_parent_intact(self):
        class StrictChildSchema(ChildSchema):
            extra = fields.Str()

            class Meta:
                unknown = EXCLUDE
                exclude = ("secret",)

        parent = ChildSchema()
        child = StrictChildSchema()

        assert field_names(parent) == set(ALL_CHILD_FIELDS)
        assert field_names(child) == {"id", "public", "extra"}
        assert set(ChildSchema._declared_fields) == set(ALL_CHILD_FIELDS)
        assert set(StrictChildSchema._declared_fields) == {
            *ALL_CHILD_FIELDS,
            "extra",
        }

        assert parent.dump(FULL_PAYLOAD) == FULL_PAYLOAD
        assert child.dump({**FULL_PAYLOAD, "extra": "e"}) == {
            **PUBLIC_PAYLOAD,
            "extra": "e",
        }

    def test_inherited_instances_remain_independent_after_repeated_use(self):
        class PublicChildSchema(ChildSchema):
            class Meta:
                unknown = EXCLUDE
                fields = PUBLIC_CHILD_FIELDS

        internal = ChildSchema()
        public = PublicChildSchema()

        for _ in range(5):
            assert internal.dump(FULL_PAYLOAD) == FULL_PAYLOAD
            assert public.dump(FULL_PAYLOAD) == PUBLIC_PAYLOAD
            assert internal.load(FULL_PAYLOAD) == FULL_PAYLOAD
            assert public.load(FULL_PAYLOAD) == PUBLIC_PAYLOAD

        assert field_names(internal) == set(ALL_CHILD_FIELDS)
        assert field_names(public) == set(PUBLIC_CHILD_FIELDS)
        assert set(ChildSchema._declared_fields) == set(ALL_CHILD_FIELDS)


class TestExternalAlias:
    """The same class bound to two local names with divergent options."""

    def test_aliased_constructors_keep_independent_visibility(self):
        PublicChild = ChildSchema  # noqa: N806 - external alias
        InternalChild = ChildSchema  # noqa: N806 - external alias

        public = PublicChild(only=("id",))
        internal = InternalChild()

        assert public.dump(FULL_PAYLOAD) == {"id": 1}
        assert internal.dump(FULL_PAYLOAD) == FULL_PAYLOAD
        assert public.load(FULL_PAYLOAD) == {"id": 1}
        assert internal.load(FULL_PAYLOAD) == FULL_PAYLOAD

        assert field_names(public) == {"id"}
        assert field_names(internal) == set(ALL_CHILD_FIELDS)

    def test_aliased_nested_schemas_do_not_pollute_each_other(self):
        PublicChild = ChildSchema  # noqa: N806 - external alias
        InternalChild = ChildSchema  # noqa: N806 - external alias

        class PublicContainer(Schema):
            child = fields.Nested(PublicChild, only=PUBLIC_CHILD_FIELDS)

        class InternalContainer(Schema):
            child = fields.Nested(InternalChild)

        public_container = PublicContainer()
        internal_container = InternalContainer()
        public_child = public_container.fields["child"].schema
        internal_child = internal_container.fields["child"].schema

        assert field_names(public_child) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(internal_child) == set(ALL_CHILD_FIELDS)
        assert public_container.dump({"child": FULL_PAYLOAD}) == {
            "child": PUBLIC_PAYLOAD
        }
        assert internal_container.dump({"child": FULL_PAYLOAD}) == {
            "child": FULL_PAYLOAD
        }


class TestNestedCaching:
    """Cached nested schemas must keep the visibility decided at first build."""

    def test_nested_schema_is_cached_per_field_and_isolated(self):
        first_field = fields.Nested(ChildSchema, only=("id",))
        second_field = fields.Nested(ChildSchema, only=("public",))

        class Holder(Schema):
            first = first_field
            second = second_field

        holder = Holder()

        assert holder.fields["first"].schema is holder.fields["first"].schema
        assert holder.fields["second"].schema is holder.fields["second"].schema
        assert holder.fields["first"].schema is not holder.fields["second"].schema
        assert field_names(holder.fields["first"].schema) == {"id"}
        assert field_names(holder.fields["second"].schema) == {"public"}

    def test_parent_table_stable_while_cached_children_differ(self):
        class Container(Schema):
            restricted = fields.Nested(ChildSchema, only=("id",))
            full = fields.Nested(ChildSchema)

        container = Container()

        # The parent field table is the same for every instance...
        assert set(container.fields) == {"restricted", "full"}
        # ...but the two cached child schemas must diverge.
        restricted_child = container.fields["restricted"].schema
        full_child = container.fields["full"].schema
        assert field_names(restricted_child) == {"id"}
        assert field_names(full_child) == set(ALL_CHILD_FIELDS)

        assert container.dump(
            {"restricted": FULL_PAYLOAD, "full": FULL_PAYLOAD}
        ) == {"restricted": {"id": 1}, "full": FULL_PAYLOAD}
        assert container.load(
            {"restricted": FULL_PAYLOAD, "full": FULL_PAYLOAD}
        ) == {"restricted": {"id": 1}, "full": FULL_PAYLOAD}

    def test_dot_path_options_do_not_pollute_later_instances(self):
        class Parent(Schema):
            child = fields.Nested(ChildSchema)

        nested_payload = {"child": FULL_PAYLOAD}

        # First instance flattens a dot-path exclude onto its own nested field.
        restricted = Parent(exclude=("child.secret",))
        assert restricted.dump(nested_payload) == {"child": PUBLIC_PAYLOAD}

        # A fresh instance must not inherit the flattened nested option.
        for _ in range(3):
            full = Parent()
            assert full.dump(nested_payload) == nested_payload
            assert full.load(nested_payload) == nested_payload
            assert field_names(full.fields["child"].schema) == set(
                ALL_CHILD_FIELDS
            )

        # The class-level declared nested field must remain unconfigured.
        assert not Parent._declared_fields["child"].exclude
        assert restricted.dump(nested_payload) == {"child": PUBLIC_PAYLOAD}

    def test_repeated_cycles_keep_cached_child_visibility(self):
        class PublicParent(Schema):
            child = fields.Nested(ChildSchema, only=PUBLIC_CHILD_FIELDS)

        class InternalParent(Schema):
            child = fields.Nested(ChildSchema)

        public = PublicParent()
        internal = InternalParent()
        public_child = public.fields["child"].schema
        internal_child = internal.fields["child"].schema

        for _ in range(5):
            assert public.dump({"child": FULL_PAYLOAD}) == {
                "child": PUBLIC_PAYLOAD
            }
            assert internal.dump({"child": FULL_PAYLOAD}) == {
                "child": FULL_PAYLOAD
            }
            assert public.load({"child": FULL_PAYLOAD}) == {
                "child": PUBLIC_PAYLOAD
            }
            assert internal.load({"child": FULL_PAYLOAD}) == {
                "child": FULL_PAYLOAD
            }

        assert field_names(public_child) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(internal_child) == set(ALL_CHILD_FIELDS)


class TestSharedNestedInstance:
    """One preconfigured nested instance reused by several parent schemas."""

    def test_same_instance_under_restricted_and_full_parents(self):
        shared_child = ChildSchema()

        class PublicParent(Schema):
            child = fields.Nested(shared_child, only=PUBLIC_CHILD_FIELDS)

        class InternalParent(Schema):
            child = fields.Nested(shared_child)

        public = PublicParent()
        internal = InternalParent()
        public_child = public.fields["child"].schema
        internal_child = internal.fields["child"].schema

        assert field_names(public_child) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(internal_child) == set(ALL_CHILD_FIELDS)

        for _ in range(5):
            assert public.dump({"child": FULL_PAYLOAD}) == {
                "child": PUBLIC_PAYLOAD
            }
            assert internal.dump({"child": FULL_PAYLOAD}) == {
                "child": FULL_PAYLOAD
            }
            assert public.load({"child": FULL_PAYLOAD}) == {
                "child": PUBLIC_PAYLOAD
            }
            assert internal.load({"child": FULL_PAYLOAD}) == {
                "child": FULL_PAYLOAD
            }

        # The originally configured instance keeps its full visibility.
        assert field_names(shared_child) == set(ALL_CHILD_FIELDS)
        assert shared_child.dump(FULL_PAYLOAD) == FULL_PAYLOAD
        assert set(ChildSchema._declared_fields) == set(ALL_CHILD_FIELDS)

    def test_later_parent_with_exclude_does_not_shrink_cached_schemas(self):
        shared_child = ChildSchema()

        class InternalParent(Schema):
            child = fields.Nested(shared_child)

        internal = InternalParent()
        internal_child = internal.fields["child"].schema

        class LaterRestrictedParent(Schema):
            child = fields.Nested(shared_child, exclude=("secret",))

        later = LaterRestrictedParent()
        later_child = later.fields["child"].schema

        assert field_names(later_child) == set(PUBLIC_CHILD_FIELDS)
        assert field_names(internal_child) == set(ALL_CHILD_FIELDS)
        assert field_names(shared_child) == set(ALL_CHILD_FIELDS)
        assert internal.dump({"child": FULL_PAYLOAD}) == {
            "child": FULL_PAYLOAD
        }

    def test_on_bind_field_mutation_does_not_change_field_visibility(self):
        class BindingChildSchema(Schema):
            id = fields.Int()
            public = fields.Str()
            secret = fields.Str()

            class Meta:
                unknown = EXCLUDE

            def on_bind_field(self, field_name, field_obj):
                field_obj.metadata["bound_by"] = field_obj.root.__class__.__name__

        shared_child = BindingChildSchema()

        class PublicParent(Schema):
            child = fields.Nested(shared_child, only=PUBLIC_CHILD_FIELDS)

        class InternalParent(Schema):
            child = fields.Nested(shared_child)

        public = PublicParent()
        internal = InternalParent()

        assert public.dump({"child": FULL_PAYLOAD}) == {"child": PUBLIC_PAYLOAD}
        assert internal.dump({"child": FULL_PAYLOAD}) == {
            "child": FULL_PAYLOAD
        }
        assert public.load({"child": FULL_PAYLOAD}) == {"child": PUBLIC_PAYLOAD}
        assert internal.load({"child": FULL_PAYLOAD}) == {
            "child": FULL_PAYLOAD
        }
        assert field_names(public.fields["child"].schema) == set(
            PUBLIC_CHILD_FIELDS
        )
        assert field_names(internal.fields["child"].schema) == set(
            ALL_CHILD_FIELDS
        )


class TestLoadOnlyDumpOnlyIsolation:
    """load_only/dump_only configuration stays scoped to each instance."""

    def test_instance_options_do_not_leak_between_siblings(self):
        class VisibilitySchema(Schema):
            id = fields.Int()
            token = fields.Str(load_only=True)
            note = fields.Str(dump_only=True)

            class Meta:
                unknown = EXCLUDE

        default = VisibilitySchema()
        with_extra_load_only = VisibilitySchema(load_only=("note",))
        with_extra_dump_only = VisibilitySchema(dump_only=("token",))

        assert dump_names(default) == {"id", "note"}
        assert load_names(default) == {"id", "token"}
        assert dump_names(with_extra_load_only) == {"id"}
        assert load_names(with_extra_load_only) == {"id", "token"}
        assert dump_names(with_extra_dump_only) == {"id", "note"}
        # token is load_only by default and dump_only here, so it leaves both sets
        assert load_names(with_extra_dump_only) == {"id"}

        # Building the extra instances must not reconfigure the first one.
        assert dump_names(default) == {"id", "note"}
        assert load_names(default) == {"id", "token"}

    def test_load_and_dump_outputs_match_configured_visibility(self):
        class VisibilitySchema(Schema):
            id = fields.Int()
            token = fields.Str(load_only=True)
            note = fields.Str(dump_only=True)

            class Meta:
                unknown = EXCLUDE

        schema = VisibilitySchema()
        payload = {"id": 1, "token": "t", "note": "n"}

        assert schema.dump(payload) == {"id": 1, "note": "n"}
        assert schema.load(payload) == {"id": 1, "token": "t"}

        sibling = VisibilitySchema(load_only=("note",))
        assert sibling.dump(payload) == {"id": 1}
        # And the first instance is still unchanged after another load/dump.
        assert schema.dump(payload) == {"id": 1, "note": "n"}
        assert schema.load(payload) == {"id": 1, "token": "t"}
