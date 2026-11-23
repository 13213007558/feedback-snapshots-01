from unittest import TestCase
import textwrap

import jsonpath_ng

from jsonschema import exceptions
from jsonschema.validators import _LATEST_VERSION


class TestBestMatch(TestCase):
    def best_match_of(self, instance, schema):
        errors = list(_LATEST_VERSION(schema).iter_errors(instance))
        msg = f"No errors found for {instance} under {schema!r}!"
        self.assertTrue(errors, msg=msg)

        best = exceptions.best_match(iter(errors))
        reversed_best = exceptions.best_match(reversed(errors))

        self.assertEqual(
            best._contents(),
            reversed_best._contents(),
            f"No consistent best match!\nGot: {best}\n\nThen: {reversed_best}",
        )
        return best

    def test_shallower_errors_are_better_matches(self):
        schema = {
            "properties": {
                "foo": {
                    "minProperties": 2,
                    "properties": {"bar": {"type": "object"}},
                },
            },
        }
        best = self.best_match_of(instance={"foo": {"bar": []}}, schema=schema)
        self.assertEqual(best.validator, "minProperties")

    def test_earlier_sibling_errors_are_better_matches(self):
        """
        Among equally relevant errors, the one earliest in the instance wins,
        regardless of the order in which the errors are provided.
        """

        schema = {"items": {"const": 37}}
        best = self.best_match_of(instance=[12, 12, 12], schema=schema)
        self.assertEqual(list(best.path), [0])

    def test_earlier_sibling_errors_within_a_subschema_are_better_matches(
        self,
    ):
        """
        The same holds within an anyOf subschema, even though its errors are
        always provided in the order they were produced in.
        """

        schema = {"anyOf": [{"items": {"const": 37}}]}
        error = next(_LATEST_VERSION(schema).iter_errors([12, 12, 12]))
        error.context.reverse()
        best = exceptions.best_match([error])
        self.assertEqual(list(best.path), [0])

    def test_hand_constructed_errors_with_context(self):
        """
        Errors constructed by hand need not have any schema path at all.
        """

        error = exceptions.ValidationError(
            "parent",
            context=[
                exceptions.ValidationError("child", path=["foo"]),
                exceptions.ValidationError("grandchild", path=["foo", "bar"]),
            ],
        )
        best = exceptions.best_match([error])
        self.assertEqual(best.message, "child")

    def test_oneOf_and_anyOf_are_weak_matches(self):
        """
        A property you *must* match is probably better than one you have to
        match a part of.
        """

        schema = {
            "minProperties": 2,
            "anyOf": [{"type": "string"}, {"type": "number"}],
            "oneOf": [{"type": "string"}, {"type": "number"}],
        }
        best = self.best_match_of(instance={}, schema=schema)
        self.assertEqual(best.validator, "minProperties")

    def test_if_the_most_relevant_error_is_anyOf_it_is_traversed(self):
        """
        If the most relevant error is an anyOf, then we traverse its context
        and select the otherwise *least* relevant error, since in this case
        that means the most specific, deep, error inside the instance.

        I.e. since only one of the schemas must match, we look for the most
        relevant one.
        """

        schema = {
            "properties": {
                "foo": {
                    "anyOf": [
                        {"type": "string"},
                        {"properties": {"bar": {"type": "array"}}},
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": {"bar": 12}}, schema=schema)
        self.assertEqual(best.validator_value, "array")

    def test_anyOf_traversal_for_single_shallower_errors_better_match(self):
        """
        Traverse the context of an anyOf error with the only subschema,
        and select the most relevant error.
        """

        schema = {
            "anyOf": [
                {
                    "properties": {
                        "foo": {
                            "minProperties": 2,
                            "properties": {"bar": {"type": "object"}},
                        },
                    },
                },
            ],
        }
        best = self.best_match_of(instance={"foo": {"bar": []}}, schema=schema)
        self.assertEqual(best.validator, "minProperties")

    def test_anyOf_traversal_least_relevant_among_most_relevant_errors(self):
        """
        Traverse the context of an anyOf error, and select
        the *least* relevant error among the most relevant errors
        in each separate subschema.

        I.e. since only one of the schemas must match, we look for the most
        specific one, and choose the most relevant error produced by it.
        """

        schema = {
            "anyOf": [
                {"type": "string"},
                {
                    "properties": {
                        "foo": {
                            "minProperties": 2,
                            "properties": {"bar": {"type": "object"}},
                        },
                    },
                },
            ],
        }
        best = self.best_match_of(instance={"foo": {"bar": []}}, schema=schema)
        self.assertEqual(best.validator, "minProperties")

    def test_no_anyOf_traversal_for_equally_relevant_errors(self):
        """
        We don't traverse into an anyOf (as above) if all of its context errors
        seem to be equally "wrong" against the instance.
        """

        schema = {
            "anyOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "object"},
            ],
        }
        best = self.best_match_of(instance=[], schema=schema)
        self.assertEqual(best.validator, "anyOf")

    def test_no_anyOf_traversal_for_two_properties_sibling_errors(self):
        """
        We don't traverse into an anyOf if all of its context errors
        seem to be equally "wrong" against the instance.
        """

        schema = {
            "anyOf": [
                {"properties": {"foo": {"type": "string"}}},
                {"properties": {"bar": {"type": "string"}}},
            ],
        }
        best = self.best_match_of(instance={"foo": 1, "bar": 1}, schema=schema)
        self.assertEqual(best.validator, "anyOf")

    def test_anyOf_traversal_prefers_subschemas_with_fewer_errors(self):
        """
        When subschemas fail at the same depth, we traverse into the one
        which produced fewer errors, since it was closer to being valid.

        Here the first subschema rejects every item, whereas the second
        rejects only the non-integer one.
        """

        schema = {
            "anyOf": [
                {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/int_array",
                    },
                },
                {
                    "$ref": "#/$defs/int_array",
                },
            ],
            "$defs": {
                "int_array": {
                    "type": "array",
                    "items": {
                        "type": "integer",
                    },
                },
            },
        }
        best = self.best_match_of(instance=["not an int", 0], schema=schema)
        self.assertEqual(best.validator, "type")
        self.assertEqual(best.instance, "not an int")
        best = self.best_match_of(instance=[0, "not an int"], schema=schema)
        self.assertEqual(best.validator, "type")
        self.assertEqual(best.instance, "not an int")

    def test_anyOf_traversal_for_partially_matching_subschemas(self):
        """
        When one subschema matches more of the instance than another,
        we traverse into it, and report its remaining error.

        See #1002.
        """

        schema = {
            "anyOf": [
                {
                    "properties": {
                        "version": {"const": 1},
                        "description": {"type": "string"},
                    },
                },
                {
                    "properties": {
                        "version": {"const": 2},
                        "description": {"type": "string"},
                    },
                },
            ],
        }
        instance = {"version": 1, "description": 0}
        best = self.best_match_of(instance=instance, schema=schema)
        self.assertEqual(best.validator, "type")
        self.assertEqual(list(best.path), ["description"])

    def test_anyOf_traversal_for_single_equally_relevant_error(self):
        """
        We *do* traverse anyOf with a single nested error, even though it is
        vacuously equally relevant to itself.
        """

        schema = {
            "anyOf": [
                {"type": "string"},
            ],
        }
        best = self.best_match_of(instance=[], schema=schema)
        self.assertEqual(best.validator, "type")

    def test_anyOf_traversal_for_single_sibling_errors_choose_first(self):
        """
        We *do* traverse anyOf with a single subschema that fails multiple
        times (e.g. on multiple items).
        """

        schema = {
            "anyOf": [
                {"items": {"const": 37}},
            ],
        }
        best = self.best_match_of(instance=[12, 13], schema=schema)
        self.assertEqual(best.validator, "const")
        self.assertEqual(best.instance, 12)

    def test_anyOf_traversal_for_non_type_matching_sibling_errors(self):
        """
        We *do* traverse anyOf with multiple subschemas when one does not type
        match.
        """

        schema = {
            "anyOf": [
                {"type": "object"},
                {"items": {"const": 37}},
            ],
        }
        best = self.best_match_of(instance=[12, 12], schema=schema)
        self.assertEqual(best.validator, "const")

    def test_if_the_most_relevant_error_is_oneOf_it_is_traversed(self):
        """
        If the most relevant error is an oneOf, then we traverse its context
        and select the otherwise *least* relevant error, since in this case
        that means the most specific, deep, error inside the instance.

        I.e. since only one of the schemas must match, we look for the most
        relevant one.
        """

        schema = {
            "properties": {
                "foo": {
                    "oneOf": [
                        {"type": "string"},
                        {"properties": {"bar": {"type": "array"}}},
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": {"bar": 12}}, schema=schema)
        self.assertEqual(best.validator_value, "array")

    def test_oneOf_traversal_for_single_shallower_errors_better_match(self):
        """
        Traverse the context of an oneOf error with the only subschema,
        and select the most relevant error.
        """

        schema = {
            "oneOf": [
                {
                    "properties": {
                        "foo": {
                            "minProperties": 2,
                            "properties": {"bar": {"type": "object"}},
                        },
                    },
                },
            ],
        }
        best = self.best_match_of(instance={"foo": {"bar": []}}, schema=schema)
        self.assertEqual(best.validator, "minProperties")

    def test_oneOf_traversal_least_relevant_among_most_relevant_errors(self):
        """
        Traverse the context of an oneOf error, and select
        the *least* relevant error among the most relevant errors
        in each separate subschema.

        I.e. since only one of the schemas must match, we look for the most
        specific one, and choose the most relevant error produced by it.
        """

        schema = {
            "oneOf": [
                {"type": "string"},
                {
                    "properties": {
                        "foo": {
                            "minProperties": 2,
                            "properties": {"bar": {"type": "object"}},
                        },
                    },
                },
            ],
        }
        best = self.best_match_of(instance={"foo": {"bar": []}}, schema=schema)
        self.assertEqual(best.validator, "minProperties")

    def test_no_oneOf_traversal_for_equally_relevant_errors(self):
        """
        We don't traverse into an oneOf (as above) if all of its context errors
        seem to be equally "wrong" against the instance.
        """

        schema = {
            "oneOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "object"},
            ],
        }
        best = self.best_match_of(instance=[], schema=schema)
        self.assertEqual(best.validator, "oneOf")

    def test_no_oneOf_traversal_for_two_properties_sibling_errors(self):
        """
        We don't traverse into an oneOf if all of its context errors
        seem to be equally "wrong" against the instance.
        """

        schema = {
            "oneOf": [
                {"properties": {"foo": {"type": "string"}}},
                {"properties": {"bar": {"type": "string"}}},
            ],
        }
        best = self.best_match_of(instance={"foo": 1, "bar": 1}, schema=schema)
        self.assertEqual(best.validator, "oneOf")

    def test_oneOf_traversal_prefers_subschemas_with_fewer_errors(self):
        """
        When subschemas fail at the same depth, we traverse into the one
        which produced fewer errors, since it was closer to being valid.

        Here the first subschema rejects every item, whereas the second
        rejects only the non-integer one.
        """

        schema = {
            "oneOf": [
                {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/int_array",
                    },
                },
                {
                    "$ref": "#/$defs/int_array",
                },
            ],
            "$defs": {
                "int_array": {
                    "type": "array",
                    "items": {
                        "type": "integer",
                    },
                },
            },
        }
        best = self.best_match_of(instance=["not an int", 0], schema=schema)
        self.assertEqual(best.validator, "type")
        self.assertEqual(best.instance, "not an int")
        best = self.best_match_of(instance=[0, "not an int"], schema=schema)
        self.assertEqual(best.validator, "type")
        self.assertEqual(best.instance, "not an int")

    def test_oneOf_traversal_for_partially_matching_subschemas(self):
        """
        When one subschema matches more of the instance than another,
        we traverse into it, and report its remaining error.

        See #1002.
        """

        schema = {
            "oneOf": [
                {
                    "properties": {
                        "version": {"const": 1},
                        "description": {"type": "string"},
                    },
                },
                {
                    "properties": {
                        "version": {"const": 2},
                        "description": {"type": "string"},
                    },
                },
            ],
        }
        instance = {"version": 1, "description": 0}
        best = self.best_match_of(instance=instance, schema=schema)
        self.assertEqual(best.validator, "type")
        self.assertEqual(list(best.path), ["description"])

    def test_oneOf_traversal_for_single_equally_relevant_error(self):
        """
        We *do* traverse oneOf with a single nested error, even though it is
        vacuously equally relevant to itself.
        """

        schema = {
            "oneOf": [
                {"type": "string"},
            ],
        }
        best = self.best_match_of(instance=[], schema=schema)
        self.assertEqual(best.validator, "type")

    def test_oneOf_traversal_for_single_sibling_errors_choose_first(self):
        """
        We *do* traverse oneOf with a single subschema that fails multiple
        times (e.g. on multiple items).
        """

        schema = {
            "oneOf": [
                {"items": {"const": 37}},
            ],
        }
        best = self.best_match_of(instance=[12, 13], schema=schema)
        self.assertEqual(best.validator, "const")
        self.assertEqual(best.instance, 12)

    def test_oneOf_traversal_for_non_type_matching_sibling_errors(self):
        """
        We *do* traverse oneOf with multiple subschemas when one does not type
        match.
        """

        schema = {
            "oneOf": [
                {"type": "object"},
                {"items": {"const": 37}},
            ],
        }
        best = self.best_match_of(instance=[12, 12], schema=schema)
        self.assertEqual(best.validator, "const")

    def test_if_the_most_relevant_error_is_allOf_it_is_traversed(self):
        """
        Now, if the error is allOf, we traverse but select the *most* relevant
        error from the context, because all schemas here must match anyways.
        """

        schema = {
            "properties": {
                "foo": {
                    "allOf": [
                        {"type": "string"},
                        {"properties": {"bar": {"type": "array"}}},
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": {"bar": 12}}, schema=schema)
        self.assertEqual(best.validator_value, "string")

    def test_nested_context_for_oneOf(self):
        """
        We traverse into nested contexts (a oneOf containing an error in a
        nested oneOf here).
        """

        schema = {
            "properties": {
                "foo": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "oneOf": [
                                {"type": "string"},
                                {
                                    "properties": {
                                        "bar": {"type": "array"},
                                    },
                                },
                            ],
                        },
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": {"bar": 12}}, schema=schema)
        self.assertEqual(best.validator_value, "array")

    def test_it_prioritizes_matching_types(self):
        schema = {
            "properties": {
                "foo": {
                    "anyOf": [
                        {"type": "array", "minItems": 2},
                        {"type": "string", "minLength": 10},
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": "bar"}, schema=schema)
        self.assertEqual(best.validator, "minLength")

        reordered = {
            "properties": {
                "foo": {
                    "anyOf": [
                        {"type": "string", "minLength": 10},
                        {"type": "array", "minItems": 2},
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": "bar"}, schema=reordered)
        self.assertEqual(best.validator, "minLength")

    def test_it_prioritizes_matching_union_types(self):
        schema = {
            "properties": {
                "foo": {
                    "anyOf": [
                        {"type": ["array", "object"], "minItems": 2},
                        {"type": ["integer", "string"], "minLength": 10},
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": "bar"}, schema=schema)
        self.assertEqual(best.validator, "minLength")

        reordered = {
            "properties": {
                "foo": {
                    "anyOf": [
                        {"type": "string", "minLength": 10},
                        {"type": "array", "minItems": 2},
                    ],
                },
            },
        }
        best = self.best_match_of(instance={"foo": "bar"}, schema=reordered)
        self.assertEqual(best.validator, "minLength")

    def test_boolean_schemas(self):
        schema = {"properties": {"foo": False}}
        best = self.best_match_of(instance={"foo": "bar"}, schema=schema)
        self.assertIsNone(best.validator)

    def test_one_error(self):
        validator = _LATEST_VERSION({"minProperties": 2})
        validator.iter_errors({})
        self.assertEqual(
            exceptions.best_match(validator.iter_errors({})).validator,
            "minProperties",
        )

    def test_no_errors(self):
        validator = _LATEST_VERSION({})
        self.assertIsNone(exceptions.best_match(validator.iter_errors({})))


class TestByRelevance(TestCase):
    def test_short_paths_are_better_matches(self):
        shallow = exceptions.ValidationError("Oh no!", path=["baz"])
        deep = exceptions.ValidationError("Oh yes!", path=["foo", "bar"])
        match = max([shallow, deep], key=exceptions.relevance)
        self.assertIs(match, shallow)

        match = max([deep, shallow], key=exceptions.relevance)
        self.assertIs(match, shallow)

    def test_global_errors_are_even_better_matches(self):
        shallow = exceptions.ValidationError("Oh no!", path=[])
        deep = exceptions.ValidationError("Oh yes!", path=["foo"])

        errors = sorted([shallow, deep], key=exceptions.relevance)
        self.assertEqual(
            [list(error.path) for error in errors],
            [["foo"], []],
        )

        errors = sorted([deep, shallow], key=exceptions.relevance)
        self.assertEqual(
            [list(error.path) for error in errors],
            [["foo"], []],
        )

    def test_weak_keywords_are_lower_priority(self):
        weak = exceptions.ValidationError("Oh no!", path=[], validator="a")
        normal = exceptions.ValidationError("Oh yes!", path=[], validator="b")

        best_match = exceptions.by_relevance(weak="a")

        match = max([weak, normal], key=best_match)
        self.assertIs(match, normal)

        match = max([normal, weak], key=best_match)
        self.assertIs(match, normal)

    def test_strong_keywords_are_higher_priority(self):
        weak = exceptions.ValidationError("Oh no!", path=[], validator="a")
        normal = exceptions.ValidationError("Oh yes!", path=[], validator="b")
        strong = exceptions.ValidationError("Oh fine!", path=[], validator="c")

        best_match = exceptions.by_relevance(weak="a", strong="c")

        match = max([weak, normal, strong], key=best_match)
        self.assertIs(match, strong)

        match = max([strong, normal, weak], key=best_match)
        self.assertIs(match, strong)


class TestErrorTree(TestCase):
    def test_it_knows_how_many_total_errors_it_contains(self):
        # FIXME: #442
        errors = [
            exceptions.ValidationError("Something", validator=i)
            for i in range(8)
        ]
        tree = exceptions.ErrorTree(errors)
        self.assertEqual(tree.total_errors, 8)

    def test_it_contains_an_item_if_the_item_had_an_error(self):
        errors = [exceptions.ValidationError("a message", path=["bar"])]
        tree = exceptions.ErrorTree(errors)
        self.assertIn("bar", tree)

    def test_it_does_not_contain_an_item_if_the_item_had_no_error(self):
        errors = [exceptions.ValidationError("a message", path=["bar"])]
        tree = exceptions.ErrorTree(errors)
        self.assertNotIn("foo", tree)

    def test_keywords_that_failed_appear_in_errors_dict(self):
        error = exceptions.ValidationError("a message", validator="foo")
        tree = exceptions.ErrorTree([error])
        self.assertEqual(tree.errors, {"foo": error})

    def test_it_creates_a_child_tree_for_each_nested_path(self):
        errors = [
            exceptions.ValidationError("a bar message", path=["bar"]),
            exceptions.ValidationError("a bar -> 0 message", path=["bar", 0]),
        ]
        tree = exceptions.ErrorTree(errors)
        self.assertIn(0, tree["bar"])
        self.assertNotIn(1, tree["bar"])

    def test_children_have_their_errors_dicts_built(self):
        e1, e2 = (
            exceptions.ValidationError("1", validator="foo", path=["bar", 0]),
            exceptions.ValidationError("2", validator="quux", path=["bar", 0]),
        )
        tree = exceptions.ErrorTree([e1, e2])
        self.assertEqual(tree["bar"][0].errors, {"foo": e1, "quux": e2})

    def test_multiple_errors_with_instance(self):
        e1, e2 = (
            exceptions.ValidationError(
                "1",
                validator="foo",
                path=["bar", "bar2"],
                instance="i1",
            ),
            exceptions.ValidationError(
                "2",
                validator="quux",
                path=["foobar", 2],
                instance="i2",
            ),
        )
        exceptions.ErrorTree([e1, e2])

    def test_it_does_not_contain_subtrees_that_are_not_in_the_instance(self):
        error = exceptions.ValidationError("123", validator="foo", instance=[])
        tree = exceptions.ErrorTree([error])

        with self.assertRaises(IndexError):
            tree[0]

    def test_if_its_in_the_tree_anyhow_it_does_not_raise_an_error(self):
        """
        If a keyword refers to a path that isn't in the instance, the
        tree still properly returns a subtree for that path.
        """

        error = exceptions.ValidationError(
            "a message",
            validator="foo",
            instance={},
            path=["foo"],
        )
        tree = exceptions.ErrorTree([error])
        self.assertIsInstance(tree["foo"], exceptions.ErrorTree)

    def test_iter(self):
        e1, e2 = (
            exceptions.ValidationError(
                "1",
                validator="foo",
                path=["bar", "bar2"],
                instance="i1",
            ),
            exceptions.ValidationError(
                "2",
                validator="quux",
                path=["foobar", 2],
                instance="i2",
            ),
        )
        tree = exceptions.ErrorTree([e1, e2])
        self.assertEqual(set(tree), {"bar", "foobar"})

    def test_accessing_an_error_free_index_does_not_add_it_to_the_tree(self):
        """
        Retrieving a subtree for an index with no errors returns an
        empty tree but must not change what the tree contains.

        See https://github.com/python-jsonschema/jsonschema/issues/1328
        """
        error = exceptions.ValidationError(
            "a message",
            validator="foo",
            instance=["spam", "eggs"],
            path=[0],
        )
        tree = exceptions.ErrorTree([error])

        subtree = tree[1]

        self.assertEqual(subtree.total_errors, 0)
        self.assertNotIn(1, tree)
        self.assertEqual(list(tree), [0])
        self.assertEqual(tree.total_errors, 1)

    def test_error_free_subtrees_still_know_their_instance(self):
        """
        Subtrees for indices with no errors still propagate lookup
        errors from the instance they correspond to.
        """
        error = exceptions.ValidationError(
            "a message",
            validator="foo",
            instance={"bar": []},
            path=["foo"],
        )
        tree = exceptions.ErrorTree([error])

        subtree = tree["foo"]["bar"]
        self.assertEqual(subtree.total_errors, 0)

        with self.assertRaises(IndexError):
            subtree[0]

    def test_it_can_be_given_the_instance_it_corresponds_to(self):
        tree = exceptions.ErrorTree(instance={"foo": []})

        with self.assertRaises(KeyError):
            tree["bar"]

        with self.assertRaises(IndexError):
            tree["foo"][0]

    def test_repr_single(self):
        error = exceptions.ValidationError(
            "1",
            validator="foo",
            path=["bar", "bar2"],
            instance="i1",
        )
        tree = exceptions.ErrorTree([error])
        self.assertEqual(repr(tree), "<ErrorTree (1 total error)>")

    def test_repr_multiple(self):
        e1, e2 = (
            exceptions.ValidationError(
                "1",
                validator="foo",
                path=["bar", "bar2"],
                instance="i1",
            ),
            exceptions.ValidationError(
                "2",
                validator="quux",
                path=["foobar", 2],
                instance="i2",
            ),
        )
        tree = exceptions.ErrorTree([e1, e2])
        self.assertEqual(repr(tree), "<ErrorTree (2 total errors)>")

    def test_repr_empty(self):
        tree = exceptions.ErrorTree([])
        self.assertEqual(repr(tree), "<ErrorTree (0 total errors)>")


class TestErrorInitReprStr(TestCase):
    def make_error(self, **kwargs):
        defaults = dict(
            message="hello",
            validator="type",
            validator_value="string",
            instance=5,
            schema={"type": "string"},
        )
        defaults.update(kwargs)
        return exceptions.ValidationError(**defaults)

    def assertShows(self, expected, **kwargs):
        expected = textwrap.dedent(expected).rstrip("\n")

        error = self.make_error(**kwargs)
        message_line, _, rest = str(error).partition("\n")
        self.assertEqual(message_line, error.message)
        self.assertEqual(rest, expected)

    def test_it_calls_super_and_sets_args(self):
        error = self.make_error()
        self.assertGreater(len(error.args), 1)

    def test_repr(self):
        self.assertEqual(
            repr(exceptions.ValidationError(message="Hello!")),
            "<ValidationError: 'Hello!'>",
        )

    def test_unset_error(self):
        error = exceptions.ValidationError("message")
        self.assertEqual(str(error), "message")

        kwargs = {
            "validator": "type",
            "validator_value": "string",
            "instance": 5,
            "schema": {"type": "string"},
        }
        # Just the message should show if any of the attributes are unset
        for attr in kwargs:
            k = dict(kwargs)
            del k[attr]
            error = exceptions.ValidationError("message", **k)
            self.assertEqual(str(error), "message")

    def test_empty_paths(self):
        self.assertShows(
            """
            Failed validating 'type' in schema:
                {'type': 'string'}

            On instance:
                5
            """,
            path=[],
            schema_path=[],
        )

    def test_one_item_paths(self):
        self.assertShows(
            """
            Failed validating 'type' in schema:
                {'type': 'string'}

            On instance[0]:
                5
            """,
            path=[0],
            schema_path=["items"],
        )

    def test_multiple_item_paths(self):
        self.assertShows(
            """
            Failed validating 'type' in schema['items'][0]:
                {'type': 'string'}

            On instance[0]['a']:
                5
            """,
            path=[0, "a"],
            schema_path=["items", 0, 1],
        )

    def test_uses_pprint(self):
        self.assertShows(
            """
            Failed validating 'maxLength' in schema:
                {0: 0,
                 1: 1,
                 2: 2,
                 3: 3,
                 4: 4,
                 5: 5,
                 6: 6,
                 7: 7,
                 8: 8,
                 9: 9,
                 10: 10,
                 11: 11,
                 12: 12,
                 13: 13,
                 14: 14,
                 15: 15,
                 16: 16,
                 17: 17,
                 18: 18,
                 19: 19}

            On instance:
                [0,
                 1,
                 2,
                 3,
                 4,
                 5,
                 6,
                 7,
                 8,
                 9,
                 10,
                 11,
                 12,
                 13,
                 14,
                 15,
                 16,
                 17,
                 18,
                 19,
                 20,
                 21,
                 22,
                 23,
                 24]
            """,
            instance=list(range(25)),
            schema=dict(zip(range(20), range(20))),
            validator="maxLength",
        )

    def test_does_not_reorder_dicts(self):
        self.assertShows(
            """
            Failed validating 'type' in schema:
                {'do': 3, 'not': 7, 'sort': 37, 'me': 73}

            On instance:
                {'here': 73, 'too': 37, 'no': 7, 'sorting': 3}
            """,
            schema={
                "do": 3,
                "not": 7,
                "sort": 37,
                "me": 73,
            },
            instance={
                "here": 73,
                "too": 37,
                "no": 7,
                "sorting": 3,
            },
        )

    def test_str_works_with_instances_having_overriden_eq_operator(self):
        """
        Check for #164 which rendered exceptions unusable when a
        `ValidationError` involved instances with an `__eq__` method
        that returned truthy values.
        """

        class DontEQMeBro:
            def __eq__(this, other):  # pragma: no cover
                self.fail("Don't!")

            def __ne__(this, other):  # pragma: no cover
                self.fail("Don't!")

        instance = DontEQMeBro()
        error = exceptions.ValidationError(
            "a message",
            validator="foo",
            instance=instance,
            validator_value="some",
            schema="schema",
        )
        self.assertIn(repr(instance), str(error))


class TestHashable(TestCase):
    def test_hashable(self):
        {exceptions.ValidationError("")}
        {exceptions.SchemaError("")}


class TestJsonPathRendering(TestCase):
    def validate_json_path_rendering(self, property_name, expected_path):
        error = exceptions.ValidationError(
            path=[property_name],
            message="1",
            validator="foo",
            instance="i1",
        )

        rendered_json_path = error.json_path
        self.assertEqual(rendered_json_path, expected_path)

        re_parsed_name = jsonpath_ng.parse(rendered_json_path).right.fields[0]
        self.assertEqual(re_parsed_name, property_name)

    def test_basic(self):
        self.validate_json_path_rendering("x", "$.x")

    def test_empty(self):
        self.validate_json_path_rendering("", "$['']")

    def test_number(self):
        self.validate_json_path_rendering("1", "$['1']")

    def test_period(self):
        self.validate_json_path_rendering(".", "$['.']")

    def test_single_quote(self):
        self.validate_json_path_rendering("'", r"$['\'']")

    def test_space(self):
        self.validate_json_path_rendering(" ", "$[' ']")

    def test_backslash(self):
        self.validate_json_path_rendering("\\", r"$['\\']")

    def test_backslash_single_quote(self):
        self.validate_json_path_rendering(r"\'", r"$['\\\'']")

    def test_underscore(self):
        self.validate_json_path_rendering("_", r"$['_']")

    def test_double_quote(self):
        self.validate_json_path_rendering('"', """$['"']""")

    def test_hyphen(self):
        self.validate_json_path_rendering("-", "$['-']")

    def test_json_path_injection(self):
        self.validate_json_path_rendering("a[0]", "$['a[0]']")

    def test_open_bracket(self):
        self.validate_json_path_rendering("[", "$['[']")


class TestPublicErrors(TestCase):
    secret = "SUPER-SECRET-MARKER-4242"

    schema = {
        "$defs": {
            "phone": {
                "anyOf": [
                    {
                        "type": "object",
                        "properties": {"number": {"type": "string"}},
                        "required": ["number"],
                    },
                    {"type": "string", "pattern": r"^\+?[0-9-]+$"},
                ],
            },
        },
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "contact": {"$ref": "#/$defs/phone"},
                "tags": {"type": "array", "uniqueItems": True},
            },
            "required": ["name", "contact"],
        },
    }

    # The secret only appears inside the failing anyOf branch's instance
    # (and therefore its error messages), never in the rest of the instance.
    @property
    def instance(self):
        return [
            {
                "name": "alice",
                "contact": {"label": self.secret},
                "tags": ["a", "a"],
            },
        ]

    def setUp(self):
        self.errors = list(
            _LATEST_VERSION(self.schema).iter_errors(self.instance),
        )
        self.assertTrue(self.errors)

    def assert_no_secret(self, text):
        self.assertNotIn(self.secret, text)

    def test_direct_iteration_only_exposes_approved_fields(self):
        public = exceptions.public_errors(self.errors)

        self.assertEqual(len(public), len(self.errors))
        for error in public:
            self.assertIsInstance(error, exceptions.PublicError)
            self.assertEqual(
                list(error),
                ["path", "schema_path", "validator", "context"],
            )
            self.assertEqual(
                set(error.keys()),
                {"path", "schema_path", "validator", "context"},
            )
            for attribute in (
                "message",
                "instance",
                "schema",
                "validator_value",
                "cause",
                "parent",
            ):
                self.assertFalse(hasattr(error, attribute))

    def test_best_match_selection_is_unchanged(self):
        best = exceptions.best_match(iter(self.errors))
        reversed_best = exceptions.best_match(reversed(self.errors))
        self.assertEqual(best._contents(), reversed_best._contents())

        public = exceptions.public_errors([best])[0]
        self.assertEqual(public.validator, best.validator)
        self.assertEqual(public.path, tuple(best.absolute_path))
        self.assertEqual(
            public.schema_path,
            tuple(best.absolute_schema_path),
        )

    def test_serialization_contains_only_approved_fields(self):
        import json

        public = exceptions.public_errors(self.errors)
        for serialized in (
            json.dumps(public),
            json.dumps(public[0]),
            json.dumps(public[0].to_dict()),
        ):
            reloaded = json.loads(serialized)
            entries = reloaded if isinstance(reloaded, list) else [reloaded]
            for entry in entries:
                self.assertEqual(
                    set(entry),
                    {"path", "schema_path", "validator", "context"},
                )

    def test_marker_still_present_on_inner_raw_branch(self):
        anyof = next(
            error for error in self.errors if error.validator == "anyOf"
        )
        self.assertTrue(
            any(
                self.secret in str(branch.instance)
                for branch in anyof.context
            ),
            "the marker should be present on the internal raw error",
        )

    def test_public_view_preserves_anyof_branches_without_values(self):
        anyof = next(
            error
            for error in exceptions.public_errors(self.errors)
            if error.validator == "anyOf"
        )
        self.assertEqual(anyof.path, (0, "contact"))
        self.assertEqual(
            sorted(branch.validator for branch in anyof.context),
            ["required", "type"],
        )
        for branch in anyof.context:
            self.assertEqual(branch.path, (0, "contact"))
            self.assertEqual(
                set(branch),
                {"path", "schema_path", "validator", "context"},
            )
            self.assertEqual(branch.context, ())

    def test_public_view_locates_array_level_error(self):
        unique_items = next(
            error
            for error in exceptions.public_errors(self.errors)
            if error.validator == "uniqueItems"
        )
        self.assertEqual(unique_items.path, (0, "tags"))
        self.assertEqual(unique_items.schema_path[-1], "uniqueItems")

    def test_no_marker_in_serialized_output(self):
        import json

        public = exceptions.public_errors(self.errors)
        best = exceptions.public_errors(
            [exceptions.best_match(self.errors)],
        )
        self.assert_no_secret(json.dumps(public))
        self.assert_no_secret(json.dumps(best))
        self.assert_no_secret(json.dumps(public[0].to_dict()))

    def test_no_marker_in_repr_str_or_logged_context(self):
        import io
        import logging

        public = exceptions.public_errors(self.errors)
        self.assert_no_secret(repr(public))
        self.assert_no_secret(str(public))
        self.assert_no_secret(repr(public[0].context))

        stream = io.StringIO()
        logger = logging.getLogger("jsonschema.public-errors-test")
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)
        try:
            logger.warning("public errors: %r", public)
        finally:
            logger.removeHandler(handler)
        self.assert_no_secret(stream.getvalue())

    def test_public_errors_are_read_only(self):
        public = exceptions.public_errors(self.errors)[0]
        with self.assertRaises(TypeError):
            public["message"] = "leaked"
        with self.assertRaises(TypeError):
            del public["validator"]
        with self.assertRaises(AttributeError):
            public.message = "leaked"
        with self.assertRaises(AttributeError):
            del public.validator
        for mutation in (
            lambda: public.update({"message": "leaked"}),
            lambda: public.setdefault("message", "leaked"),
            lambda: public.pop("validator"),
            lambda: public.popitem(),
            lambda: public.clear(),
        ):
            with self.assertRaises(TypeError):
                mutation()
        self.assertEqual(
            set(public),
            {"path", "schema_path", "validator", "context"},
        )

    def test_copy_and_pickle_preserve_the_public_view(self):
        import copy
        import pickle

        public = exceptions.public_errors(self.errors)
        for copied in (
            copy.copy(public),
            copy.deepcopy(public),
            pickle.loads(pickle.dumps(public)),
        ):
            self.assertEqual(copied, public)
            self.assertIsInstance(copied[0], exceptions.PublicError)

    def test_mapping_access_matches_attribute_access(self):
        public = exceptions.public_errors(self.errors)[0]
        self.assertIs(public["path"], public.path)
        self.assertIs(public["context"], public.context)
        self.assertEqual(public.get("instance", "missing"), "missing")
        self.assertEqual(len(public), 4)
        self.assertIn("validator", public)

    def test_empty_input(self):
        self.assertEqual(exceptions.public_errors(()), [])

    def test_hand_constructed_error_without_validator(self):
        error = exceptions.ValidationError(
            "some message containing " + self.secret,
            path=["foo"],
        )
        public = exceptions.PublicError.from_error(error)
        self.assertIsNone(public.validator)
        self.assertEqual(public.path, ("foo",))
        self.assertEqual(public.context, ())
        self.assert_no_secret(repr(public))
