import os.path

from csvconnector import FileImporter, LowercaseImporter

import pytest


class FakeImporter(FileImporter):

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.hosts = None
        self.fields = None
        self.hostname_field = None

    def import_hosts(self):
        "This function will be called for importing the hosts."
        self.fields = ["HostName", "IpAddress", "Server_LOC"]
        self.hostname_field = "HostName"
        # TODO: Add hosts


@pytest.fixture
def import_path():
    return "some_PATH"


@pytest.fixture
def importer(import_path):
    return FakeImporter(import_path)


def test_path_is_not_changed(importer, import_path):
    lowercaseImporter = LowercaseImporter(importer)

    assert import_path == lowercaseImporter.filepath


def test_lowercasing_hostname_field(importer):
    lowercaseImporter = LowercaseImporter(importer)
    lowercaseImporter.import_hosts()

    assert lowercaseImporter.hostname_field.islower()


def test_lowercasing_hostname_field_only_if_filled(importer):
    lowercaseImporter = LowercaseImporter(importer)

    # No import happens
    assert lowercaseImporter.hostname_field is None


def test_lowercasing_fields(importer):
    lowercaseImporter = LowercaseImporter(importer)
    lowercaseImporter.import_hosts()

    assert lowercaseImporter.fields

    for fieldname in lowercaseImporter.fields:
        assert fieldname.islower()


def test_lowercasing_fields_only_if_filled(importer):
    lowercaseImporter = LowercaseImporter(importer)

    # No import happens
    assert lowercaseImporter.fields is None


def test_lowercasing_hosts_only_if_filled(importer):
    lowercaseImporter = LowercaseImporter(importer)

    assert not lowercaseImporter.hosts
