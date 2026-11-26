import pytest

try:
    from tests.django_helper import RequestClient
except ImportError:  # Django is an optional dependency for this test tree.
    RequestClient = None


@pytest.fixture
def factory():
    if RequestClient is None:
        pytest.skip("Django is not installed")
    return RequestClient()
