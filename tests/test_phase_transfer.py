from fileconnector import FileConnectorHosts
import pytest


@pytest.fixture
def hosts():
    return list(range(10))


@pytest.fixture
def fieldnames():
    return ["counter"]


@pytest.fixture
def hostname_field():
    return "counter"


def test_serialization(hosts, hostname_field, fieldnames):
    conhosts = FileConnectorHosts(hosts, hostname_field, fieldnames)

    serialized = conhosts._serialize_attributes()

    assert isinstance(serialized, dict)
    assert serialized["hosts"] == hosts
    assert serialized["hostname_field"] == hostname_field
    assert serialized["fieldnames"] == fieldnames


def test_deserialization(hosts, hostname_field, fieldnames):
    serialized = {
        "hosts": hosts,
        "hostname_field": hostname_field,
        "fieldnames": fieldnames
    }
    conhosts = FileConnectorHosts.from_serialized_attributes(serialized)

    assert isinstance(conhosts, FileConnectorHosts)
    assert conhosts.hosts == hosts
    assert conhosts.hostname_field == hostname_field
    assert conhosts.fieldnames == fieldnames


def test_repr(hosts, hostname_field, fieldnames):
    conhosts = FileConnectorHosts(hosts, hostname_field, fieldnames)

    representation = repr(conhosts)

    assert representation.startswith("FileConnectorHosts(")
    assert representation.endswith(")")
    assert repr(hosts) in representation
    assert repr(hostname_field) in representation
    assert repr(fieldnames) in representation
