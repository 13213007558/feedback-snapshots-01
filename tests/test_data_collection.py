import sys
import warnings

import pytest

import sentry_sdk
from sentry_sdk.data_collection import _ALL_HTTP_BODY_TYPES
from sentry_sdk.utils import has_data_collection_enabled, serialize_frame


def test_kvcb_invalid_mode(sentry_init):
    with pytest.raises(ValueError, match="Invalid collection mode 'nope'"):
        sentry_init(data_collection={"cookies": {"mode": "nope"}})  # type: ignore Purposely ignoring to test invalid option


def test_stack_frame_variables_invalid_mode(sentry_init):
    with pytest.raises(ValueError, match="Invalid collection mode 'nope'"):
        sentry_init(data_collection={"stack_frame_variables": {"mode": "nope"}})


@pytest.mark.parametrize(
    "value",
    ["3", -1, [1], 2.5],
    ids=[
        "frame_context_lines_string",
        "frame_context_lines_negative",
        "frame_context_lines_list",
        "frame_context_lines_float",
    ],
)
def test_frame_context_lines_invalid_value(sentry_init, value):
    with pytest.raises(ValueError, match="Invalid `frame_context_lines` value"):
        sentry_init(data_collection={"frame_context_lines": value})


def test_kvcb_from_dict_defaults_mode(sentry_init):
    sentry_init(data_collection={"cookies": {"mode": "denylist", "terms": ["x"]}})
    client = sentry_sdk.get_client()
    assert client.options["data_collection"]["cookies"] == {
        "mode": "denylist",
        "terms": ["x"],
    }


def test_http_headers_collection_defaults(sentry_init):
    default_terms = ["forwarded", "-ip", "remote-", "via", "-user"]

    sentry_init(data_collection={"http_headers": {}})  # type: ignore Purposely ignoring to test invalid option
    client = sentry_sdk.get_client()
    assert client.options["data_collection"]["http_headers"]["request"] == {
        "mode": "denylist"
    }

    sentry_init(data_collection={"http_headers": "off"})  # type: ignore Purposely ignoring to test invalid option
    client = sentry_sdk.get_client()
    assert client.options["data_collection"]["http_headers"]["request"] == {
        "mode": "denylist"
    }

    sentry_init()
    client = sentry_sdk.get_client()
    assert client.options["data_collection"]["http_headers"]["request"] == {
        "mode": "denylist",
        "terms": default_terms,
    }


def test_http_headers_use_default_in_setting_with_missing_config(sentry_init):
    sentry_init(
        data_collection={
            "http_headers": {
                "request": {"mode": "allowlist", "terms": ["x-id"]},
            }
        }
    )

    client = sentry_sdk.get_client()

    assert client.options["data_collection"]["http_headers"]["request"] == {
        "mode": "allowlist",
        "terms": ["x-id"],
    }


def _initialize_client_with_config(sentry_init, **options):
    sentry_init(**options)
    return sentry_sdk.get_client().options["data_collection"]


def _get(dc, path):
    obj = dc
    for part in path.split("."):
        obj = obj[part]
    return obj


@pytest.mark.parametrize(
    "options,expected",
    [
        pytest.param(
            {},
            {
                "user_info": False,
                "gen_ai.inputs": False,
                "gen_ai.outputs": False,
                "cookies.mode": "denylist",
                "url_query_params.mode": "denylist",
                "http_headers.request.mode": "denylist",
                "http_bodies": _ALL_HTTP_BODY_TYPES,
                "queues": False,
                "frame_context_lines": 5,
            },
            id="no_options_collects_no_pii",
        ),
        pytest.param(
            {"send_default_pii": True},
            {
                "user_info": True,
                "gen_ai.inputs": True,
                "gen_ai.outputs": True,
                "cookies.mode": "denylist",
                "url_query_params.mode": "denylist",
                "queues": True,
            },
            id="send_default_pii_true_collects_pii",
        ),
        pytest.param(
            {"send_default_pii": False},
            {"user_info": False, "cookies.mode": "denylist", "queues": False},
            id="send_default_pii_false_collects_no_pii",
        ),
        pytest.param(
            {"data_collection": {}},
            {
                "user_info": True,
                "gen_ai.inputs": True,
                "gen_ai.outputs": True,
                "cookies.mode": "denylist",
                "url_query_params.mode": "denylist",
                "http_bodies": _ALL_HTTP_BODY_TYPES,
                "queues": True,
            },
            id="explicit_data_collection_uses_spec_defaults",
        ),
        pytest.param(
            {"data_collection": {"user_info": False, "http_bodies": []}},
            {
                "user_info": False,
                "http_bodies": [],
                "gen_ai.inputs": True,
                "cookies.mode": "denylist",
            },
            id="explicit_partial_fills_omitted_with_spec_defaults",
        ),
        pytest.param(
            {
                "data_collection": {},
                "include_local_variables": False,
                "include_source_context": False,
            },
            {"stack_frame_variables": True, "frame_context_lines": 5},
            id="explicit_data_collection_ignores_legacy_include_local_variables",
        ),
        pytest.param(
            {
                "data_collection": {
                    "cookies": {"mode": "off"},
                    "url_query_params": {"mode": "allowlist", "terms": ["page"]},
                    "http_headers": {"request": {"mode": "off"}},
                    "gen_ai": {"inputs": False, "outputs": True},
                }
            },
            {
                "cookies.mode": "off",
                "url_query_params.mode": "allowlist",
                "url_query_params.terms": ["page"],
                "http_headers.request.mode": "off",
                "gen_ai.inputs": False,
                "gen_ai.outputs": True,
            },
            id="accepts_dict_with_nested_dicts",
        ),
        pytest.param(
            {
                "data_collection": {
                    "cookies": None,
                    "http_headers": None,
                    "url_query_params": None,
                    "graphql": None,
                    "gen_ai": None,
                }
            },
            {
                "cookies.mode": "denylist",
                "http_headers.request.mode": "denylist",
                "url_query_params.mode": "denylist",
                "graphql.document": True,
                "graphql.variables": True,
                "gen_ai.inputs": True,
                "gen_ai.outputs": True,
            },
            id="none_values_fall_back_to_spec_defaults",
        ),
        pytest.param(
            {"data_collection": {}},
            {
                "graphql.document": True,
                "graphql.variables": True,
                "database_query_data": True,
            },
            id="explicit_graphql_database_defaults",
        ),
        pytest.param(
            {"send_default_pii": False},
            {
                "graphql.document": False,
                "graphql.variables": False,
                "database_query_data": False,
                "queues": False,
            },
            id="legacy_pii_off_gates_graphql_database_and_queues",
        ),
        pytest.param(
            {"send_default_pii": True},
            {
                "graphql.document": True,
                "graphql.variables": True,
                "database_query_data": True,
                "queues": True,
            },
            id="legacy_pii_on_collects_graphql_database_and_queues",
        ),
        pytest.param(
            {"data_collection": {"graphql": {"variables": False}}},
            {"graphql.document": True, "graphql.variables": False},
            id="explicit_partial_graphql_fills_omitted",
        ),
        pytest.param(
            {"data_collection": {"frame_context_lines": True}},
            {"frame_context_lines": 5},
            id="frame_context_lines_bool_fallback_true",
        ),
        pytest.param(
            {"data_collection": {"frame_context_lines": False}},
            {"frame_context_lines": 0},
            id="frame_context_lines_bool_fallback_false",
        ),
        pytest.param(
            {"data_collection": {"frame_context_lines": 3}},
            {"frame_context_lines": 3},
            id="frame_context_lines_bool_fallback_3",
        ),
        pytest.param(
            {"data_collection": {"frame_context_lines": 0}},
            {"frame_context_lines": 0},
            id="frame_context_lines_bool_fallback_0",
        ),
        pytest.param(
            {"data_collection": {"stack_frame_variables": True}},
            {"stack_frame_variables": True},
            id="stack_frame_variables_explicit_true",
        ),
        pytest.param(
            {"data_collection": {"stack_frame_variables": False}},
            {"stack_frame_variables": False},
            id="stack_frame_variables_explicit_false",
        ),
        pytest.param(
            {
                "data_collection": {
                    "stack_frame_variables": {
                        "mode": "allowlist",
                        "terms": ["order_id"],
                    }
                }
            },
            {
                "stack_frame_variables": {
                    "mode": "allowlist",
                    "terms": ["order_id"],
                }
            },
            id="stack_frame_variables_allowlist_dict",
        ),
        pytest.param(
            {"data_collection": {"stack_frame_variables": {"terms": ["order_id"]}}},
            {
                "stack_frame_variables": {
                    "mode": "denylist",
                    "terms": ["order_id"],
                }
            },
            id="stack_frame_variables_dict_defaults_mode_to_denylist",
        ),
        pytest.param(
            {"data_collection": {"stack_frame_variables": {"mode": "off"}}},
            {"stack_frame_variables": {"mode": "off"}},
            id="stack_frame_variables_off_dict_omits_terms",
        ),
        pytest.param(
            {"data_collection": {"stack_frame_variables": "yes"}},
            {"stack_frame_variables": True},
            id="stack_frame_variables_non_bool_truthy_coerces_to_true",
        ),
        pytest.param(
            {"data_collection": {"stack_frame_variables": ""}},
            {"stack_frame_variables": False},
            id="stack_frame_variables_non_bool_falsy_coerces_to_false",
        ),
        pytest.param(
            {"data_collection": {"frame_context_lines": None}},
            {"frame_context_lines": 5},
            id="frame_context_lines_none_falls_back_to_spec_default",
        ),
        pytest.param(
            {"include_local_variables": False, "include_source_context": False},
            {"stack_frame_variables": False, "frame_context_lines": 0},
            id="legacy_include_local_variables_off_disables_stack_frame_variables",
        ),
        pytest.param(
            {"include_local_variables": True, "include_source_context": True},
            {"stack_frame_variables": True, "frame_context_lines": 5},
            id="legacy_include_local_variables_on_enables_stack_frame_variables",
        ),
    ],
)
def test_initialize_client_data_collection(sentry_init, options, expected):
    dc = _initialize_client_with_config(sentry_init, **options)
    for path, value in expected.items():
        assert _get(dc, path) == value, f"{path} != {value!r}"


def test_initialize_client_stack_frame_variable_sources(sentry_init):
    dc = _initialize_client_with_config(
        sentry_init,
        data_collection={
            "stack_frame_variables": {
                "sources": [
                    {"module": "myapp", "mode": "allowlist", "terms": ["order"]},
                    {"path": "/srv/internal", "mode": "off"},
                ]
            }
        },
    )

    assert dc["stack_frame_variables"] == {
        "mode": "off",
        "sources": [
            {"module": "myapp", "mode": "allowlist", "terms": ["order"]},
            {"path": "/srv/internal", "mode": "off"},
        ],
    }


def test_initialize_client_stack_frame_variable_sources_with_explicit_fallback(
    sentry_init,
):
    dc = _initialize_client_with_config(
        sentry_init,
        data_collection={
            "stack_frame_variables": {
                "sources": [{"module": "myapp", "mode": "denylist"}],
                "mode": "denylist",
                "terms": ["nickname"],
            }
        },
    )

    assert dc["stack_frame_variables"] == {
        "mode": "denylist",
        "terms": ["nickname"],
        "sources": [{"module": "myapp", "mode": "denylist"}],
    }


def test_initialize_client_stack_frame_variable_sources_default_mode_is_denylist(
    sentry_init,
):
    dc = _initialize_client_with_config(
        sentry_init,
        data_collection={
            "stack_frame_variables": {"sources": [{"module": "myapp"}]}
        },
    )

    assert dc["stack_frame_variables"]["sources"] == [
        {"module": "myapp", "mode": "denylist"}
    ]


def test_initialize_client_data_collection_overrides_send_default_pii_and_warns(
    sentry_init,
):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        dc = _initialize_client_with_config(
            sentry_init,
            send_default_pii=True,
            data_collection={"user_info": False},
        )
    assert dc["user_info"] is False  # data_collection wins
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


@pytest.mark.parametrize(
    "init_kwargs,expected",
    [
        pytest.param(
            {},
            {
                "user_info": False,
                "provided_by_user": False,
                "should_send_default_pii": False,
            },
            id="defaults_to_no_pii",
        ),
        pytest.param(
            {"send_default_pii": True},
            {"user_info": True, "provided_by_user": False},
            id="send_default_pii_enables_user_info",
        ),
        pytest.param(
            {"data_collection": {"user_info": False}},
            {"user_info": False, "provided_by_user": True},
            id="explicit_data_collection_overrides_user_info",
        ),
        pytest.param(
            {"spotlight": True},
            {"provided_by_user": False, "user_info": True},
            id="dsnless_spotlight_rederives_data_collection",
        ),
        pytest.param(
            {
                "spotlight": True,
                "data_collection": {"user_info": False},
            },
            {"provided_by_user": True, "user_info": False},
            id="dsnless_spotlight_respects_explicit_data_collection",
        ),
    ],
)
def test_client_data_collection_settings(sentry_init, init_kwargs, expected):
    sentry_init(**init_kwargs)
    client = sentry_sdk.get_client()
    for key, value in expected.items():
        if key == "should_send_default_pii":
            assert client.should_send_default_pii() is value
        else:
            assert client.options["data_collection"][key] is value


def test_has_data_collection_enabled_gates_on_user_provided_config():
    assert has_data_collection_enabled(None) is False
    assert has_data_collection_enabled({}) is False
    # An unset/None option is "not provided by the user".
    assert has_data_collection_enabled({"data_collection": None}) is False
    # Every SDK call site passes post-resolution client options, where
    # `data_collection` is always a fully-resolved dict carrying
    # `provided_by_user`. That flag -- not the key's presence -- is the gate.
    assert (
        has_data_collection_enabled({"data_collection": {"provided_by_user": False}})
        is False
    )
    assert (
        has_data_collection_enabled({"data_collection": {"provided_by_user": True}})
        is True
    )


@pytest.mark.parametrize(
    "init_kwargs, expected",
    [
        pytest.param({}, False, id="no_config"),
        pytest.param({"send_default_pii": True}, False, id="send_default_pii_true"),
        pytest.param({"send_default_pii": False}, False, id="send_default_pii_false"),
        pytest.param({"data_collection": {}}, True, id="empty_data_collection"),
        pytest.param(
            {"data_collection": {"user_info": False}},
            True,
            id="partial_data_collection",
        ),
    ],
)
def test_has_data_collection_enabled_after_resolution(
    sentry_init, init_kwargs, expected
):
    sentry_init(**init_kwargs)
    assert has_data_collection_enabled(sentry_sdk.get_client().options) is expected


def test_no_data_collection_values_fall_back_to_send_default_pii_configuration(
    sentry_init,
):
    sentry_init(send_default_pii=True)
    client = sentry_sdk.get_client()
    dc = client.options["data_collection"]
    assert dc["provided_by_user"] is False
    assert dc["user_info"] is True
    assert has_data_collection_enabled(client.options) is False


def test_data_collection_via_experiments(sentry_init):
    sentry_init(
        _experiments={"data_collection": {"user_info": True}},
    )

    dc = sentry_sdk.get_client().options["data_collection"]
    assert dc is not None
    assert dc["provided_by_user"] is True
    assert dc["user_info"] is True


def test_top_level_takes_precedence_over_experiments(sentry_init):
    sentry_init(
        data_collection={"user_info": False},
        _experiments={"data_collection": {"user_info": True}},
    )

    dc = sentry_sdk.get_client().options["data_collection"]
    assert dc is not None
    assert dc["provided_by_user"] is True
    assert dc["user_info"] is False


def _import_module_from_source(tmp_path, module_name, source):
    """
    Import a real module from a temp file so frames have genuine source
    files, module names, and line numbers.
    """
    import importlib.util
    import sys
    from textwrap import dedent

    path = tmp_path / f"{module_name}.py"
    path.write_text(dedent(source), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module, path


def test_stack_frame_variable_source_rules_preserve_chain_and_deny_unlisted_frames(
    sentry_init, capture_events, tmp_path
):
    """
    Acceptance test for source-based frame collection:

    * the exception chain and both source locations survive,
    * an approved module keeps bounded local state,
    * an internal module contributes no locals,
    * and the restricted object's serialization/``repr``/attribute access
      never runs.
    """
    import sys

    from sentry_sdk.serializer import MAX_DATABAG_BREADTH

    internal_name = "sentry_test_internal_restricted"
    approved_name = "sentry_test_approved_handler"

    internal_module, internal_path = _import_module_from_source(
        tmp_path,
        internal_name,
        """
        CALLS = []

        class Restricted:
            def __repr__(self):
                CALLS.append("repr")
                return "<restricted>"

            def __getattr__(self, name):
                CALLS.append("getattr:" + name)
                raise AssertionError("restricted attribute access must not run")

        def fail():
            restricted = Restricted()
            transcript = {"note": "must not be serialized"}
            raise ValueError("internal boom")
        """,
    )

    approved_module, approved_path = _import_module_from_source(
        tmp_path,
        approved_name,
        f"""
        import {internal_name}

        def handle():
            order_id = "order-123"
            password = "hunter2"
            safe_state = {{"attempt": 1}}
            try:
                {internal_name}.fail()
            except ValueError as exc:
                raise RuntimeError("approved wrapper") from exc

        def many_locals():
            v00 = 0
            v01 = 1
            v02 = 2
            v03 = 3
            v04 = 4
            v05 = 5
            v06 = 6
            v07 = 7
            v08 = 8
            v09 = 9
            v10 = 10
            v11 = 11
            v12 = 12
            v13 = 13
            v14 = 14
            raise RuntimeError("many locals")
        """,
    )

    custom_repr_seen = []

    def custom_repr(value):
        custom_repr_seen.append(type(value).__name__)
        return None

    sentry_init(
        custom_repr=custom_repr,
        data_collection={
            "stack_frame_variables": {
                "sources": [
                    {"module": approved_name, "mode": "denylist"},
                    {"path": str(internal_path), "mode": "off"},
                ]
            }
        },
    )
    events = capture_events()

    try:
        approved_module.handle()
    except RuntimeError:
        sentry_sdk.capture_exception()

    (event,) = events
    values = event["exception"]["values"]

    assert [value["type"] for value in values] == ["ValueError", "RuntimeError"]

    internal_source = internal_path.read_text(encoding="utf-8").splitlines()

    fail_frame = next(
        frame
        for frame in values[0]["stacktrace"]["frames"]
        if frame["function"] == "fail"
    )
    handle_cause_frame = next(
        frame
        for frame in values[0]["stacktrace"]["frames"]
        if frame["function"] == "handle"
    )
    handle_wrapper_frame = next(
        frame
        for frame in values[1]["stacktrace"]["frames"]
        if frame["function"] == "handle"
    )

    # Source locations are intact for both modules.
    assert fail_frame["module"] == internal_name
    assert fail_frame["abs_path"] == str(internal_path)
    assert fail_frame["filename"] == f"{internal_name}.py"
    assert fail_frame["lineno"] == next(
        lineno
        for lineno, line in enumerate(internal_source, 1)
        if 'raise ValueError("internal boom")' in line
    )
    assert fail_frame["context_line"].strip() == 'raise ValueError("internal boom")'

    assert handle_cause_frame["module"] == approved_name
    assert handle_cause_frame["abs_path"] == str(approved_path)
    assert handle_cause_frame["context_line"].strip() == f"{internal_name}.fail()"
    assert handle_wrapper_frame["context_line"].strip() == (
        'raise RuntimeError("approved wrapper") from exc'
    )

    # The internal frame is denied entirely.
    assert "vars" not in fail_frame
    assert internal_module.CALLS == []
    assert "Restricted" not in custom_repr_seen

    # The approved frame keeps locals, with sensitive keys filtered.
    assert handle_cause_frame["vars"]["order_id"] == "'order-123'"
    assert handle_cause_frame["vars"]["password"] == "'[Filtered]'"
    assert "safe_state" in handle_cause_frame["vars"]

    # Any frame without an explicit source silently falls back to "off".
    for value in values:
        for frame in value["stacktrace"]["frames"]:
            if frame["module"] != approved_name:
                assert "vars" not in frame

    # Approved frames are still bounded.
    del events[:]
    try:
        approved_module.many_locals()
    except RuntimeError:
        sentry_sdk.capture_exception()

    (event,) = events
    many_frame = next(
        frame
        for frame in event["exception"]["values"][0]["stacktrace"]["frames"]
        if frame["function"] == "many_locals"
    )
    assert len(many_frame["vars"]) == MAX_DATABAG_BREADTH

    for module_name in (internal_name, approved_name):
        sys.modules.pop(module_name, None)


def test_stack_frame_variable_source_rules_unmatched_frames_default_to_off(
    sentry_init,
):
    sentry_init(
        data_collection={
            "stack_frame_variables": {
                "sources": [{"module": "some.approved.module", "mode": "denylist"}]
            }
        }
    )

    def frame_with_locals():
        safe_value = "ok"  # noqa: F841
        password = "hunter2"  # noqa: F841
        return sys._getframe()

    result = serialize_frame(frame_with_locals())

    assert "vars" not in result


def test_stack_frame_variable_source_rules_explicit_fallback_for_unmatched_frames(
    sentry_init,
):
    sentry_init(
        data_collection={
            "stack_frame_variables": {
                "sources": [{"module": "some.approved.module", "mode": "denylist"}],
                "mode": "allowlist",
                "terms": ["safe_value"],
            }
        }
    )

    def frame_with_locals():
        safe_value = "ok"  # noqa: F841
        password = "hunter2"  # noqa: F841
        return sys._getframe()

    result = serialize_frame(frame_with_locals())

    assert result["vars"] == {
        "safe_value": "'ok'",
        "password": "'[Filtered]'",
    }


def test_stack_frame_variable_source_rules_frames_without_source_use_fallback(
    sentry_init,
):
    """
    A frame with no ``__name__`` in its globals (and therefore no module) has
    no identifiable source; it must use the fallback behaviour as well.
    """
    sentry_init(
        data_collection={
            "stack_frame_variables": {
                "sources": [{"module": "some.approved.module", "mode": "denylist"}],
                "mode": "allowlist",
                "terms": ["safe_value"],
            }
        }
    )

    namespace = {}
    exec(
        compile(
            "import sys\n"
            "safe_value = 'ok'\n"
            "password = 'hunter2'\n"
            "frame = sys._getframe()\n",
            "<synthetic-no-module>",
            "exec",
        ),
        namespace,
    )

    result = serialize_frame(namespace["frame"], include_local_variables=False)

    assert result["module"] is None
    assert result["vars"]["safe_value"] == "'ok'"
    assert result["vars"]["password"] == "'[Filtered]'"


def test_stack_frame_variable_source_rules_path_prefix(
    sentry_init, capture_events, tmp_path
):
    internal_name = "sentry_test_path_internal"
    approved_name = "sentry_test_path_approved"

    _internal_module, internal_path = _import_module_from_source(
        tmp_path,
        internal_name,
        """
        def fail():
            secret = "internal"
            raise ValueError("internal path boom")
        """,
    )
    approved_module, approved_path = _import_module_from_source(
        tmp_path,
        approved_name,
        f"""
        import {internal_name}

        def handle():
            order_id = "order-456"
            try:
                {internal_name}.fail()
            except ValueError as exc:
                raise RuntimeError("wrapped") from exc
        """,
    )

    sentry_init(
        data_collection={
            "stack_frame_variables": {
                "sources": [
                    {"path": str(approved_path), "mode": "denylist"},
                    {"path": str(internal_path), "mode": "off"},
                ]
            }
        }
    )
    events = capture_events()
    try:
        approved_module.handle()
    except RuntimeError:
        sentry_sdk.capture_exception()

    (event,) = events
    frames = event["exception"]["values"][0]["stacktrace"]["frames"]
    approved_frame = next(frame for frame in frames if frame["function"] == "handle")
    internal_frame = next(frame for frame in frames if frame["function"] == "fail")

    assert approved_frame["vars"]["order_id"] == "'order-456'"
    assert "vars" not in internal_frame


@pytest.mark.parametrize(
    "sources",
    [
        pytest.param("not-a-list", id="sources_not_a_list"),
        pytest.param(["not-a-dict"], id="source_not_a_dict"),
        pytest.param([{}], id="source_missing_selector"),
        pytest.param(
            [{"module": "a", "path": "/tmp/a.py"}],
            id="source_both_selectors",
        ),
        pytest.param([{"module": ""}], id="source_empty_module"),
        pytest.param([{"path": ""}], id="source_empty_path"),
        pytest.param([{"module": 123}], id="source_non_string_module"),
        pytest.param([{"path": 123}], id="source_non_string_path"),
    ],
)
def test_stack_frame_variable_source_rules_invalid_config(sentry_init, sources):
    with pytest.raises(ValueError, match="stack_frame_variables"):
        sentry_init(data_collection={"stack_frame_variables": {"sources": sources}})
