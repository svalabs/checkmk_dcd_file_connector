import os.path

from fileconnector import BVQImporter

import pytest


@pytest.fixture
def example_file():
    current_dir = os.path.dirname(__file__)
    return os.path.join(current_dir, "bvq_example")


@pytest.fixture
def importer(example_file):
    return BVQImporter(example_file)


def test_getting_hosts(importer):
    importer.import_hosts()

    assert len(importer.hosts) == 2


def test_getting_hostname_field(importer):
    # The value is hardcoded
    assert importer.hostname_field == "name"


def test_getting_host_attribute_fields(importer):
    importer.import_hosts()

    assert importer.fields == {"label_bvq_type", "name", "ipv4", "ipv6"}
