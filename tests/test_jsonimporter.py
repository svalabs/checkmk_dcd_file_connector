import os.path

from csvconnector import JSONImporter

import pytest


@pytest.fixture
def example_file():
    current_dir = os.path.dirname(__file__)
    return os.path.join(current_dir, "json_example.json")


@pytest.fixture
def importer(example_file):
    return JSONImporter(example_file)


def test_getting_hosts(importer):
    importer.import_hosts()

    assert len(importer.hosts) == 5


def test_getting_hostname_field(importer):
    assert importer.hostname_field is None

    importer.import_hosts()

    assert importer.hostname_field == "name"


def test_getting_host_attribute_fields(importer):
    importer.import_hosts()

    assert importer.fields == {"system_type", "name", "ipv4", "ipv6"}
