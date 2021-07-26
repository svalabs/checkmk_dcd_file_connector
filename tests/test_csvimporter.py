import os.path

from csvconnector import CSVImporter
import pytest


@pytest.fixture
def example_file():
    current_dir = os.path.dirname(__file__)
    return os.path.join(current_dir, "example_data.csv")


@pytest.fixture
def importer(example_file):
    return CSVImporter(example_file)


def test_getting_hosts(importer):
    importer.import_hosts()

    assert len(importer.hosts) == 6


def test_getting_hostname_field(importer):
    importer.import_hosts()

    assert importer.hostname_field == "HOSTNAME"


def test_getting_host_attribute_fields(importer):
    importer.import_hosts()

    assert importer.fields == ["HOSTNAME", "STANDORT", "STADT", "IDENT"]
