from csvconnector import CSVConnectorHosts
import pytest


@pytest.fixture
def hosts():
    return list(range(10))


@pytest.fixture
def fieldnames():
    return ["counter"]


def test_serialization(hosts, fieldnames):
    conhosts = CSVConnectorHosts(hosts, fieldnames)

    serialized = conhosts._serialize_attributes()

    assert isinstance(serialized, dict)
    assert serialized["cmdb_hosts"] == hosts
    assert serialized["fieldnames"] == fieldnames


def test_deserialization(hosts, fieldnames):
    serialized = {"cmdb_hosts": hosts, "fieldnames": fieldnames}
    conhosts = CSVConnectorHosts.from_serialized_attributes(serialized)

    assert isinstance(conhosts, CSVConnectorHosts)
    assert conhosts.cmdb_hosts == hosts
    assert conhosts.fieldnames == fieldnames


def test_repr(hosts, fieldnames):
    conhosts = CSVConnectorHosts(hosts, fieldnames)

    representation = repr(conhosts)

    assert representation.startswith("CSVConnectorHosts(")
    assert representation.endswith(")")
    assert repr(hosts) in representation
    assert repr(fieldnames) in representation
