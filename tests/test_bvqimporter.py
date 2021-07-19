import os.path

from csvconnector import BVQImporter

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



# class BVQJSONImporter(FileImporter):
#     FIELD_MAPPING = (
#         # Mapping data from CMK to JSON.
#         # (CMK, JSON)
#         ("label_bvq_type", "tag"),
#         ("ipv4", "ipv4"),
#         ("ipv6", "ipv6"),
#     )

#     def __init__(self, filepath):
#         super().__init__(filepath)

#         # We know that this is our field
#         self.hostname_field = "name"

#     def import_hosts(self):
#         with open(self.filepath) as export_file:
#             hosts = json.load(export_file)

#         self.hosts = [
#             self.format_host(element["hostAddress"])
#             for element in hosts
#             if "hostAddress" in element
#         ]

#         try:
#             self.fields = list(hosts[0].keys())
#         except IndexError:
#             # Handling the error will be done in the calling method
#             pass

#     def format_host(self, host):
#         # TODO: figure out how to handle these:
#         #     "masterGroupingObjectIpv4": "10.10.101.43",  -> tag "parent" in host_properties -> fragen wir bei BVQ an
#         #     "masterGroupingObjectIpv6": ""

#         new_host = {"name": host["name"]}

#         for host_key, json_key in self.FIELD_MAPPING:
#             try:
#                 new_host[host_key] = host[json_key]
#             except KeyError:
#                 continue

#         return new_host
