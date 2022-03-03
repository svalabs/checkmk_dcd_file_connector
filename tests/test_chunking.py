from collections import defaultdict

import pytest

from fileconnector import Chunker


def test_chunking(chunk_size=3):
    for chunk in Chunker.chunks(range(10), chunk_size):
        assert len(chunk) == chunk_size


def test_chunking_fills_with_none():
    chunk_size = 3
    original_iter = list(range(10))
    assert len(original_iter) % 3 != 0

<<<<<<< HEAD
    for index, chunk in enumerate(fileconnector.chunks(original_iter, chunk_size)):
=======
    for index, chunk in enumerate(Chunker.chunks(original_iter, chunk_size)):
>>>>>>> Move chunking our calls into a separate class
        print(chunk)
        if index != chunk_size:
            assert len([x for x in chunk if x is not None]) == chunk_size
            continue  # No further checks

        chunk_length = len(chunk)
        empty_elements = [x for x in chunk if x is None]
        assert empty_elements

        filled_elements = [x for x in chunk if x is not None]
        assert chunk_size == len(filled_elements + empty_elements)


class DummyApiClient:
    def __init__(self):
        self._calls = defaultdict(int)

    def add_hosts(self, hosts):
        self._calls["add_hosts"] += 1
        return hosts

    def modify_hosts(self, hosts):
        self._calls["modify_hosts"] += 1
        return hosts

    def delete_hosts(self, hosts):
        self._calls["delete_hosts"] += 1

    def activate_changes(self):
        print("Activating changes")
        self._calls["activate_changes"] += 1
        return True

    def dummy(self):
        return 123.45


@pytest.fixture
def chunk_size():
    return 10


@pytest.fixture
def api_client():
    return DummyApiClient()


def test_chunker_does_not_require_activation(api_client):
    chunker = Chunker(api_client, 1)
    assert chunker.requires_activation is False


@pytest.mark.parametrize("method", ["delete_hosts"])
def test_chunker_chunking_methods(method, api_client, chunk_size):
    chunker = Chunker(api_client, chunk_size)

    hosts = list(range(chunk_size * 2))

    method_obj = getattr(chunker, method)
    returned_hosts = method_obj(hosts)

    assert api_client._calls[method] == 2
    assert api_client._calls["activate_changes"] == 2


@pytest.mark.parametrize("function", ["add_hosts", "modify_hosts"])
def test_chunker_chunking_function(function, api_client, chunk_size):
    chunker = Chunker(api_client, chunk_size)

    hosts = list(range(1, chunk_size * 2 + 1))

    method_obj = getattr(chunker, function)
    returned_hosts = method_obj(hosts)

    assert api_client._calls[function] == 2
    assert api_client._calls["activate_changes"] == 2
    assert returned_hosts == hosts


def test_chunker_does_only_proxy_known_methods(api_client):
    chunker = Chunker(api_client, 1)

    assert chunker.dummy() == 123.45
