import os.path

from fileconnector import FileImporter, LowercaseImporter

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

        self.hosts = [
            {
                "HostName": "hubert",
                "Server_LOC": "iShelter",
                "funny": False
            },
            {
                "HostName": "heinz",
                "IpAddress": "HIDDEN",
                "size": 10,
                "pi": 3.14,

            }
        ]


@pytest.fixture
def import_path():
    return "some_PATH"


@pytest.fixture
def fakeImporter(import_path):
    return FakeImporter(import_path)


@pytest.fixture
def importer(fakeImporter):
    return LowercaseImporter(fakeImporter)


def test_path_is_not_changed(importer, import_path):
    assert import_path == importer.filepath


def test_lowercasing_hostname_field(importer):
    importer.import_hosts()

    assert importer.hostname_field.islower()


def test_lowercasing_hostname_field_only_if_filled(importer):
    # No import happens
    assert importer.hostname_field is None


def test_lowercasing_fields(importer):
    importer.import_hosts()

    assert importer.fields

    for fieldname in importer.fields:
        assert fieldname.islower()


def test_lowercasing_fields_only_if_filled(importer):
    # No import happens
    assert importer.fields is None


def test_lowercasing_hosts_only_if_filled(importer):
    assert not importer.hosts


def test_import_hosts(importer):
    importer.import_hosts()

    for host in importer.hosts:
        for key, value in host.items():
            assert key.islower()

            if isinstance(value, str):
                assert value.islower()
