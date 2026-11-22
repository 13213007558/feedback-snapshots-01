import pytest

from sentry_sdk.data_category_policy import (
    DataCategoryPolicy,
    _build_data_category_policy,
)


def test_default_policy_allows_every_category():
    assert _build_data_category_policy(None) is None

    policy = DataCategoryPolicy()
    assert policy.allows("profile")
    assert policy.allows("error")


def test_sequence_policy_keeps_only_listed_categories():
    policy = _build_data_category_policy(["error", "transaction"])

    assert isinstance(policy, DataCategoryPolicy)
    assert policy.allows("error")
    assert policy.allows("transaction")
    assert not policy.allows("profile")
    assert not policy.allows("profile_chunk")


def test_callback_policy_is_evaluated_each_call():
    state = {"allowed": False}
    policy = _build_data_category_policy(
        lambda category: state["allowed"] or category != "profile"
    )

    assert not policy.allows("profile")
    assert policy.allows("transaction")

    state["allowed"] = True
    assert policy.allows("profile")


def test_policy_instance_is_returned_unchanged():
    policy = DataCategoryPolicy(["error"])
    assert _build_data_category_policy(policy) is policy


def test_invalid_policy_values_raise_type_error():
    with pytest.raises(TypeError, match="not a single string"):
        _build_data_category_policy("profile")

    with pytest.raises(TypeError, match="must be a sequence"):
        _build_data_category_policy(42)
