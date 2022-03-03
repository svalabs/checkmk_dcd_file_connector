# -*- encoding: utf-8; py-indent-offset: 4 -*-

# +------------------------------------------------------------+
# |                                                            |
# |             | |             | |            | |             |
# |          ___| |__   ___  ___| | ___ __ ___ | | __          |
# |         / __| '_ \ / _ \/ __| |/ / '_ ` _ \| |/ /          |
# |        | (__| | | |  __/ (__|   <| | | | | |   <           |
# |         \___|_| |_|\___|\___|_|\_\_| |_| |_|_|\_\          |
# |                                   custom code by SVA       |
# |                                                            |
# +------------------------------------------------------------+
#
# File Connector is a no-code DCD connector for checkmk.
#
# Copyright (C) 2021-2022 SVA System Vertrieb Alexander GmbH
#                         Niko Wenselowski <niko.wenselowski@sva.de>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""
File Connector import logic.
"""

import csv
import json
import re
import time
from abc import ABC, abstractmethod
from functools import partial, wraps
from itertools import zip_longest

from typing import (  # pylint: disable=unused-import
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
)

from cmk.utils.i18n import _  # pylint: disable=import-error

from cmk.cee.dcd.web_api import MKAPIError  # pylint: disable=import-error

from cmk.cee.dcd.plugins.connectors.connectors_api.v1 import (  # noqa: F401 # pylint: disable=unused-import,import-error
    connector_config_registry,
    ConnectorConfig,
    connector_registry,
    Connector,
    Phase1Result,
    NullObject,
)

BUILTIN_ATTRIBUTES = {"locked_by", "labels", "meta_data"}
IP_ATTRIBUTES = {"ipv4", "ip", "ipaddress"}
FOLDER_PLACEHOLDER = "undefined"
PATH_SEPERATOR = "/"


def normalize_hostname(hostname: str) -> str:
    "Generate a normalized hostname form"
    return hostname.lower().replace(" ", "_")


def get_host_label(host: Dict[str, str], hostname_field: str) -> Dict[str, str]:
    """
    Get the labels from a host.

    Labels are either prefixed with "label_" or are not any of the
    known values for IPs.
    """

    def unlabelify(value: str) -> str:
        if value.startswith("label_"):
            return value[6:]

        return value

    tmp = {key.lower(): value for key, value in host.items() if key != hostname_field}

    return {
        unlabelify(key): value
        for key, value in tmp.items()
        if not (
            is_tag(key)
            or key in IP_ATTRIBUTES  # noqa: W503
            or is_attribute(key)  # noqa: W503
            or key in BUILTIN_ATTRIBUTES  # noqa: W503
        )
    }


def get_host_attributes(host: Dict[str, str]) -> Dict[str, str]:
    "Get unprefixed host attributes from the given dict."

    def unprefix(value: str) -> str:
        # Because we use is_attribute we can be sure that every value
        # we receive is prefixed with `attr_`
        return value[5:]

    return {
        unprefix(key): value
        for key, value in host.items()
        if is_attribute(key) and unprefix(key) not in BUILTIN_ATTRIBUTES
    }


def is_attribute(string: str) -> str:
    "Checks if a field is marked as attribute."
    return string.lower().startswith("attr_")


def get_ip_address(host: Dict[str, str]) -> Optional[str]:
    """
    Tries to get an IP address for a host. If not found returns `None`.

    If multiple IPs are given and separated through a comma only the
    first IP address will be used.
    """

    for field in IP_ATTRIBUTES:
        try:
            ip_address = host[field].split(",")[0]  # use only first IP
        except KeyError:
            continue

        return ip_address.strip()


def get_host_tags(attributes: Dict[str, str]) -> Dict[str, str]:
    "Get attributes of the host from the given dict"
    return {attr: value for attr, value in attributes.items() if is_tag(attr)}


def is_tag(name: str) -> str:
    """
    Is the name a 'tag'?

    Checks for attributes that begin 'tag_' as this is how the
    CMK API handles this cases.
    """
    return name.lower().startswith("tag_")


def create_hostlike_tags(tags_from_cmk: dict) -> Dict[str, List[str]]:
    """
    Create tags in a format that is similar to the ones
    present at hosts.

    Tags at a host are prefixed with 'tag_'
    """
    return {
        "tag_" + tag["id"]: [choice["id"] for choice in tag["tags"]]
        for tag in tags_from_cmk
    }


@connector_config_registry.register
class FileConnectorConfig(ConnectorConfig):  # pylint: disable=too-few-public-methods
    """Loading the persisted connection config"""

    @classmethod
    def name(cls) -> str:  # pylint: disable=missing-function-docstring
        return "fileconnector"

    def _connector_attributes_to_config(self) -> dict:
        return {
            "interval": self.interval,
            "path": self.path,
            "file_format": self.file_format,
            "folder": self.folder,
            "lowercase_everything": self.lowercase_everything,
            "host_filters": self.host_filters,
            "host_overtake_filters": self.host_overtake_filters,
            "chunk_size": self.chunk_size,
            "use_service_discovery": self.use_service_discovery,
            "label_path_template": self.label_path_template,
            "csv_delimiter": self.csv_delimiter,
            "label_prefix": self.label_prefix,
        }

    def _connector_attributes_from_config(self, connector_cfg: dict):
        self.interval: int = connector_cfg["interval"]  # pylint: disable=attribute-defined-outside-init
        self.path: str = connector_cfg["path"]  # pylint: disable=attribute-defined-outside-init
        self.file_format: str = connector_cfg.get("file_format", "csv")  # pylint: disable=attribute-defined-outside-init
        self.folder: str = connector_cfg["folder"]  # pylint: disable=attribute-defined-outside-init
        self.lowercase_everything: bool = connector_cfg.get("lowercase_everything", False)  # pylint: disable=attribute-defined-outside-init
        self.host_filters: List[str] = connector_cfg.get("host_filters", [])  # pylint: disable=attribute-defined-outside-init
        self.host_overtake_filters: List[str] = connector_cfg.get(  # pylint: disable=attribute-defined-outside-init
            "host_overtake_filters", []
        )
        self.chunk_size: int = connector_cfg.get("chunk_size", 0)  # pylint: disable=attribute-defined-outside-init
        self.use_service_discovery: bool = connector_cfg.get(  # pylint: disable=attribute-defined-outside-init
            "use_service_discovery", True
        )
        self.label_path_template: str = connector_cfg.get("label_path_template", "")  # pylint: disable=attribute-defined-outside-init
        self.csv_delimiter: Optional[str] = connector_cfg.get("csv_delimiter")  # pylint: disable=attribute-defined-outside-init
        self.label_prefix: Optional[str] = connector_cfg.get("label_prefix")  # pylint: disable=attribute-defined-outside-init


class FileImporter(ABC):  # pylint: disable=too-few-public-methods
    "Basic file importer"

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.hosts: Optional[dict] = None
        self.fields: Optional[List[str]] = None
        self.hostname_field: Optional[str] = None

    @abstractmethod
    def import_hosts(self):
        "This function will be called for importing the hosts."


class CSVImporter(FileImporter):  # pylint: disable=too-few-public-methods
    "Import hosts from a CSV file"

    def __init__(self, filepath: str, delimiter: str = None):
        super().__init__(filepath)

        self.delimiter = delimiter

    def import_hosts(self):
        with open(self.filepath) as cmdb_export:  # pylint: disable=unspecified-encoding
            if self.delimiter:
                reader = csv.DictReader(cmdb_export, delimiter=self.delimiter)
            else:
                reader = csv.DictReader(cmdb_export)

            self.hosts = list(reader)
            self.fields = reader.fieldnames

        try:
            # We always assume that the first column in our CSV is the hostname
            self.hostname_field = self.fields[0]
        except IndexError:
            # Handling the error will be done in the calling method
            pass


class JSONImporter(FileImporter):  # pylint: disable=too-few-public-methods
    "Import hosts from a file with JSON"

    EXPECTED_HOST_NAMES = [
        "name",
        "hostname",
    ]

    def import_hosts(self):
        with open(self.filepath) as export_file:  # pylint: disable=unspecified-encoding
            self.hosts = json.load(export_file)

        fields = set()
        for host in self.hosts:
            fields.update(host.keys())

        self.fields = fields

        possible_hostname_fields = self.EXPECTED_HOST_NAMES + list(IP_ATTRIBUTES)
        for field in possible_hostname_fields:
            if field in self.fields:
                self.hostname_field = field
                break


class BVQImporter(FileImporter):
    "Import hosts from a BVQ file"

    FIELD_MAPPING = (
        # Mapping data from CMK to JSON.
        # (CMK, JSON)
        ("label_bvq_type", "tag"),
        ("ipv4", "ipv4"),
        ("ipv6", "ipv6"),
    )

    def __init__(self, filepath: str):
        super().__init__(filepath)

        # We know that this is our field
        self.hostname_field = "name"

    def import_hosts(self):
        with open(self.filepath) as export_file:  # pylint: disable=unspecified-encoding
            hosts = json.load(export_file)

        self.hosts = [
            self.format_host(element["hostAddress"])
            for element in hosts
            if "hostAddress" in element
        ]

        fields = set()
        for host in self.hosts:
            fields.update(host.keys())

        self.fields = fields

    @classmethod
    def format_host(cls, host: dict):
        "Get a host object formatted as required for further processing"
        # BVQ sends more fields than we handle.
        # We currently exclude:
        #  - masterGroupingObjectIpv4
        #  - masterGroupingObjectIpv6

        new_host = {"name": host["name"]}

        for host_key, json_key in cls.FIELD_MAPPING:
            try:
                new_host[host_key] = host[json_key]
            except KeyError:
                continue

        return new_host


class LowercaseImporter:
    "This modifies an importer to only return lowercased values"

    def __init__(self, importer):
        self._importer = importer

    @property
    def filepath(self):  # pylint: disable=missing-function-docstring
        return self._importer.filepath

    @property
    def hosts(self):  # pylint: disable=missing-function-docstring
        hosts = self._importer.hosts
        if hosts is None:
            return None

        lowercase = self.lowercase

        def lowercase_host(host):
            return {key.lower(): lowercase(value) for key, value in host.items()}

        return [lowercase_host(host) for host in hosts]

    @property
    def fields(self):  # pylint: disable=missing-function-docstring
        fields = self._importer.fields
        if fields is None:
            return None

        return [self.lowercase(fieldname) for fieldname in fields]

    @property
    def hostname_field(self):  # pylint: disable=missing-function-docstring
        hostname_field = self._importer.hostname_field
        if hostname_field is None:
            return None

        return hostname_field.lower()

    def import_hosts(self):
        "Import hosts through the importer"
        return self._importer.import_hosts()

    @staticmethod
    def lowercase(value):
        "Convert the given value to lowercase if possible"
        if isinstance(value, (int, float, bool)):
            return value

        return value.lower()


class BaseApiClient(ABC):

    def __init__(self, api_client):
        self._api_client = api_client

    @abstractmethod
    def get_hosts(self) -> List[dict]:
        pass

    @abstractmethod
    def add_hosts(self, hosts: List[dict]) -> Dict:
        pass

    @abstractmethod
    def modify_hosts(self, hosts: List[dict]):
        pass

    @abstractmethod
    def delete_hosts(self, hosts: List[dict]):
        pass

    @abstractmethod
    def get_host_tags(self):
        # TODO: what format do we want to be returned?
        pass

    @abstractmethod
    def discover_services(self, hosts: List[str]) -> bool:
        # TODO: discovery status check necessary to be exposed as a single function?
        pass

    @abstractmethod
    def is_discovery_running(self) -> bool:
        pass

    @abstractmethod
    def activate_changes(self) -> bool:
        pass

    @property
    def requires_activation(self) -> bool:
        """
        This function indicates if the class requires an explicit
        activation after making changes.
        """
        return True

    @abstractmethod
    def get_folders(self) -> Set[str]:
        pass

    @abstractmethod
    def add_folder(self, folder: str):
        pass


class HttpApiClient(BaseApiClient):
    # The following lines can be used to debug _api_client.
    # self._logger.info("Dir: {}".format(dir(self._api_client)))
    # import inspect
    # self._logger.info("Sig: {}".format(inspect.getargspec(self._api_client._api_request)))

    def get_hosts(self) -> List[dict]:
        return self._api_client.get_all_hosts()

    def add_hosts(self, hosts: List[dict]) -> Dict:
        return self._api_client.add_hosts(hosts)

    def modify_hosts(self, hosts: List[dict]):
        self._api_client.edit_hosts(hosts)

    def delete_hosts(self, hosts: List[dict]):
        self._api_client.delete_hosts(hosts)

    def get_host_tags(self):
        # Working around limitations of the builtin client to get the
        # required results from the API.
        # The second parameter has to be a dict.
        return self._api_client._api_request("webapi.py?action=get_hosttags", {})

    def discover_services(self, hostnames: List[str]):
        self._api_client.bulk_discovery_start(hostnames)

    def is_discovery_running(self) -> bool:
        return self._api_client.bulk_discovery_status()["is_active"]

    def activate_changes(self) -> bool:
        try:
            self._api_client.activate_changes()
        except MKAPIError as error:
            if "no changes to activate" in str(error):
                return False

            raise

        return True

    def get_folders(self) -> Set[str]:
        all_folders = self._api_client._api_request("webapi.py?action=get_all_folders", {})
        return set(all_folders)

    def add_folder(self, folder: str):
        # Follow the required format for the request.
        folder_data = {"folder": folder, "attributes": {}}
        data = {"request": json.dumps(folder_data)}

        self._api_client._api_request("webapi.py?action=add_folder", data)


class Chunker:

    _CHUNKABLE_METHODS = {"delete_hosts"}
    _CHUNKABLE_FUNCTIONS = {"add_hosts", "modify_hosts"}

    def __init__(self, api_client: BaseApiClient, chunk_size: int):
        self._api_client = api_client
        self._chunk_size = chunk_size

        self._CHUNKABLE = set.union(self._CHUNKABLE_METHODS, self._CHUNKABLE_FUNCTIONS)

    def __getattr__(self, attr):
        if attr in self._CHUNKABLE:
            api_method = getattr(self._api_client, attr)

            if attr in self._CHUNKABLE_METHODS:
                return self._chunk_call(api_method)
            else:
                return self._chunk_returning_call(api_method)
        else:
            return getattr(self._api_client, attr)

    @property
    def requires_activation(self) -> bool:
        # The wrapped methods activate the changes.
        return False

    @staticmethod
    def chunks(iterable: Iterable, count: int) -> Iterable:
        "Collect data into fixed-length chunks or blocks"
        # chunks('ABCDEFG', 3) --> ABC DEF Gxx"
        args = [iter(iterable)] * count
        return zip_longest(*args)

    def _chunk_returning_call(self, function):

        @wraps(function)
        def wrap_function(parameter):
            returned_values = []
            for chunk in self.chunks(parameter, self._chunk_size):
                single_call_return = function([c for c in chunk if c])

                if single_call_return:
                    returned_values.extend(single_call_return)
                    self._api_client.activate_changes()

            return returned_values

        return wrap_function

    def _chunk_call(self, function):

        @wraps(function)
        def wrap_method(parameter):
            for chunk in self.chunks(parameter, self._chunk_size):
                function([c for c in chunk if c])
                self._api_client.activate_changes()

        return wrap_method


@connector_registry.register
class FileConnector(Connector):  # pylint: disable=too-few-public-methods
    "The connector that manages the importing"

    @classmethod
    def name(cls) -> str:  # pylint: disable=missing-function-docstring
        return "fileconnector"

    def _execution_interval(self) -> int:
        """Number of seconds to sleep after each phase execution"""
        return self._connection_config.interval

    def _execute_phase1(self) -> Phase1Result:
        """Execute the first synchronization phase"""
        self._logger.info("Execute phase 1")

        importer = self._get_importer()
        importer.import_hosts()
        self._logger.info("Found %i hosts in file", len(importer.hosts))

        if not importer.fields:
            self._logger.error(
                "Unable to read fields from %r. Is the file empty?",
                self._connection_config.path,
            )
            raise RuntimeError("Unable to detect available fields")

        if not importer.hostname_field:
            self._logger.error(
                "Unable to detect hostname field from %r!",
                self._connection_config.path,
            )
            raise RuntimeError("Unable to detect hostname field")

        return Phase1Result(
            FileConnectorHosts(
                importer.hosts, importer.hostname_field, importer.fields
            ),
            self._status,
        )

    def _get_importer(self) -> FileImporter:
        "Get the correct importer based on the current config."
        file_format = self._connection_config.file_format
        if file_format == "csv":
            importer = CSVImporter(
                self._connection_config.path, self._connection_config.csv_delimiter
            )
        elif file_format == "bvq":
            importer = BVQImporter(self._connection_config.path)
        elif file_format == "json":
            importer = JSONImporter(self._connection_config.path)
        else:
            raise RuntimeError(f"Invalid file format {file_format!r}")

        if self._connection_config.lowercase_everything:
            self._logger.info("All imported values will be lowercased")
            importer = LowercaseImporter(importer)

        return importer

    def _execute_phase2(self, phase1_result: Phase1Result):
        """Execute the second synchronization phase

        It is executed based on the information provided by the first phase. This
        phase is intended to talk to the local WATO Web API for updating the
        Check_MK configuration based on the information provided by the connection.
        """
        with self.status.next_step(
            "phase2_extract_result", _("Phase 2.1: Extracting result")
        ):
            if isinstance(phase1_result.connector_object, NullObject):
                raise ValueError("Remote site has not completed phase 1 yet")

            if not isinstance(phase1_result.connector_object, FileConnectorHosts):
                raise ValueError(
                    "Got invalid connector object as phase 1 result: "
                    f"{phase1_result.connector_object!r}"
                )

            cmdb_hosts = phase1_result.connector_object.hosts
            fieldnames = phase1_result.connector_object.fieldnames
            hostname_field = phase1_result.connector_object.hostname_field

        with self.status.next_step(
            "phase2_fetch_hosts", _("Phase 2.2: Fetching existing hosts")
        ):
            self._api_client = HttpApiClient(self._web_api)

            cmk_hosts = self._api_client.get_hosts()

            cmk_tags = {}
            fields_contain_tags = any(is_tag(name) for name in fieldnames)
            if fields_contain_tags:
                tag_response = self._api_client.get_host_tags()

                cmk_tags = create_hostlike_tags(tag_response["tag_groups"])
                cmk_tags.update(
                    create_hostlike_tags(tag_response["builtin"]["tag_groups"])
                )

        with self.status.next_step(
            "phase2_update", _("Phase 2.3: Updating config")
        ) as step:
            hosts_to_create, hosts_to_modify, hosts_to_delete = self._partition_hosts(
                cmdb_hosts, cmk_hosts, hostname_field, cmk_tags
            )

            if self._connection_config.label_path_template:
                # Creating possibly missing folders if we rely on
                # labels for the path creation.
                self._process_folders(hosts_to_create)

            chunk_size = self._connection_config.chunk_size
            if chunk_size:
                self._logger.info("Processing in chunks of %i", chunk_size)
                self._api_client = Chunker(self._api_client, chunk_size)

            created_host_names = self._create_new_hosts(hosts_to_create)
            modified_host_names = self._modify_existing_hosts(hosts_to_modify)
            deleted_host_names = self._delete_hosts(hosts_to_delete)

            changes_to_hosts = bool(
                created_host_names or modified_host_names or deleted_host_names
            )
            if changes_to_hosts:
                if created_host_names and modified_host_names and deleted_host_names:
                    change_message = _("Hosts: %i created, %i modified, %i deleted") % (
                        len(created_host_names),
                        len(modified_host_names),
                        len(deleted_host_names),
                    )
                elif created_host_names and modified_host_names:
                    change_message = _("Hosts: %i created, %i modified") % (
                        len(created_host_names),
                        len(modified_host_names),
                    )
                elif created_host_names and deleted_host_names:
                    change_message = _("Hosts: %i created, %i deleted") % (
                        len(created_host_names),
                        len(deleted_host_names),
                    )
                elif modified_host_names and deleted_host_names:
                    change_message = _("Hosts: %i modified, %i deleted") % (
                        len(modified_host_names),
                        len(deleted_host_names),
                    )
                elif created_host_names:
                    change_message = _("Hosts: %i created") % len(created_host_names)
                elif deleted_host_names:
                    change_message = _("Hosts: %i deleted") % len(deleted_host_names)
                else:
                    change_message = _("Hosts: %i modified") % len(modified_host_names)
            else:
                change_message = _("Nothing changed")

            self._logger.info(change_message)
            step.finish(change_message)

        with self.status.next_step(
            "phase2_activate", _("Phase 2.4: Activating changes")
        ) as step:
            if changes_to_hosts and self._api_client.requires_activation:
                if self._activate_changes():
                    step.finish(_("Activated the changes"))
                else:
                    step.finish(_("Not activated"))
            else:
                step.finish(_("No activation needed"))

    def _partition_hosts(
        self,
        cmdb_hosts: List[dict],
        cmk_hosts: Dict[str, dict],
        hostname_field: str,
        cmk_tags: Dict[str, List[str]],
    ) -> Tuple[list, list, list]:
        """
        Partition the hosts into three groups:

        1) New hosts which have to be added.
        2) Existing hosts which which have to be modified.
        3) Existing hosts that have been removed from the import.

        Unrelated hosts that are not handled by this connection should never be
        modified. If a host is handled by a connection is determined by the the
        locked attribute. Locked attributes are exclusively set by the connection
        and cannot be modified in the GUI, but other attributes can still be
        modified.
        """
        host_overtake_filters = [
            re.compile(f) for f in self._connection_config.host_overtake_filters
        ]

        def overtake_host(hostname: str) -> bool:
            if not host_overtake_filters:
                return False

            return any(f.match(hostname) for f in host_overtake_filters)

        global_ident = self.global_ident()
        hosts_managed_by_plugin = {}
        hosts_to_overtake = set()
        unrelated_hosts = set()
        for host_name, host in cmk_hosts.items():
            locked_by = host["attributes"].get("locked_by")
            if locked_by == global_ident:
                hosts_managed_by_plugin[host_name] = host
            elif overtake_host(host_name) and not locked_by:
                # A user might want the plugin to overtake already
                # existing hosts. These hosts usually have been added
                # before and their labels shall now be managed by this
                # plugin.
                # To avoid a hostile takeover this only is done for
                # hosts that are not locked by another plugin.
                self._logger.debug("Marking host %r for takeover", host_name)
                hosts_to_overtake.add(host_name)
            else:
                self._logger.debug(
                    "Host %r already exists as an unrelated host", host_name
                )
                unrelated_hosts.add(host_name)

        self._logger.info(
            "Existing hosts: %i managed by this connection, %i unrelated",
            len(hosts_managed_by_plugin),
            len(unrelated_hosts),
        )

        host_filters = [re.compile(f) for f in self._connection_config.host_filters]

        def host_matches_filters(host: str) -> bool:
            if not host_filters:
                return True

            return any(f.match(host) for f in host_filters)

        def add_prefix_to_labels(
            labels: Dict[str, str], prefix: Optional[str] = None
        ) -> Dict[str, str]:
            prefix = self._connection_config.label_prefix
            if not prefix:
                return labels

            return {f"{prefix}{key}": value for key, value in labels.items()}

        def needs_modification(old: dict, new: dict) -> bool:
            for label, value in new.items():
                try:
                    if old[label] != value:
                        self._logger.debug(
                            "Difference detected at %r: %r vs. %r",
                            label,
                            old[label],
                            value,
                        )
                        return True
                except KeyError:
                    self._logger.debug("Missing %s (%r vs. %r)", label, old, new)
                    return True

            return False

        def create_host_tags(host_tags: dict) -> dict:
            tags = {tag_matcher.get_tag(key): value for key, value in host_tags.items()}

            for tag, choice in tags.items():
                try:
                    tag_matcher.is_possible_value(tag, choice, True)
                except ValueError as verr:
                    self._logger.error(verr)

            return tags

        def ip_needs_modification(old_ip: Optional[str], new_ip: Optional[str]) -> bool:
            return old_ip != new_ip

        def clean_cmk_attributes(host: dict) -> dict:
            """
            Creates a cleaned up version of the host attributes dict.

            The aim of this to have a dict comparable with the data
            retrieved from the CMDB import.
            """
            return {
                key: value
                for key, value
                in host.items()
                if not (key in BUILTIN_ATTRIBUTES or is_tag(key))
            }

        if self._connection_config.label_path_template:
            path_labels = self._connection_config.label_path_template.split(
                PATH_SEPERATOR
            )

            def get_dynamic_folder_path(
                labels: dict, keys: List[str], depth: int
            ) -> str:
                def replace_special_chars(string: str) -> str:
                    return string.replace(" ", "_")

                path = generate_path_from_labels(labels, keys, depth)
                if self._connection_config.folder:
                    # In case the hosts should be added to the main
                    # folder we have '' as value. We do not want to
                    # add it because it disturbs CMKs path processing.
                    path.insert(0, self._connection_config.folder)
                path = (replace_special_chars(p) for p in path)
                return PATH_SEPERATOR.join(path)

            get_folder_path = partial(
                get_dynamic_folder_path, keys=path_labels, depth=len(path_labels)
            )
        else:
            # Keeping the signature of the more complex function
            def get_folder_path(_) -> str:
                return self._connection_config.folder

        def get_host_creation_tuple(
            host: dict,
            hostname_field: str,
            global_ident: str,
            label_prefix: Optional[str] = None,
        ) -> Tuple[str, str, dict]:
            labels = get_host_label(host, hostname_field)
            folder_path = get_folder_path(labels)
            prefixed_labels = add_prefix_to_labels(labels, label_prefix)

            attributes = {
                "labels": prefixed_labels,
                # Lock the host in order to be able to detect hosts
                # that have been created through this plugin.
                "locked_by": global_ident,
            }

            ip_address = get_ip_address(host)
            if ip_address is not None:
                attributes["ipaddress"] = ip_address

            tags = create_host_tags(get_host_tags(host))
            attributes.update(tags)

            attributes_from_cmdb = get_host_attributes(host)
            attributes.update(attributes_from_cmdb)

            return (hostname, folder_path, attributes)

        def get_host_modification_tuple(
            existing_host: dict,
            cmdb_host: dict,
            hostname_field: str,
            overtake_host: bool,
            label_prefix: Optional[str] = None,
        ) -> Tuple[str, dict, list]:
            hostname = normalize_hostname(cmdb_host[hostname_field])
            attributes = existing_host["attributes"]

            future_attributes = get_host_attributes(cmdb_host)
            comparable_attributes = clean_cmk_attributes(attributes)

            api_label = attributes.get("labels", {})

            future_label = get_host_label(cmdb_host, hostname_field)
            future_label = add_prefix_to_labels(future_label, label_prefix)
            if label_prefix:
                # We only manage labels that match our prefix
                unmodified_api_label = api_label.copy()
                api_label = {
                    key: value
                    for key, value
                    in api_label.items()
                    if key.startswith(label_prefix)
                }

            api_tags = get_host_tags(attributes)
            host_tags = get_host_tags(cmdb_host)
            future_tags = create_host_tags(host_tags)

            existing_ip = attributes.get("ipaddress")
            future_ip = get_ip_address(cmdb_host)

            overtake_host = hostname in hosts_to_overtake

            def update_needed() -> bool:
                if overtake_host:
                    self._logger.debug("Host marked for overtake")
                    return True

                if needs_modification(comparable_attributes, future_attributes):
                    self._logger.debug("Attributes require update")
                    return True

                if needs_modification(api_label, future_label):
                    self._logger.debug("Labels require update")
                    return True

                if needs_modification(api_tags, future_tags):
                    self._logger.debug("Tags require update")
                    return True

                if ip_needs_modification(existing_ip, future_ip):
                    self._logger.debug("IP requires update")
                    return True

                return False  # Nothing changed

            if update_needed():
                if label_prefix:
                    unmodified_api_label.update(api_label)
                    api_label = unmodified_api_label

                api_label.update(future_label)
                attributes["labels"] = api_label

                attributes_to_unset = []
                if future_ip is None:
                    attributes_to_unset.append("ipaddress")
                else:
                    attributes["ipaddress"] = future_ip

                attributes.update(future_tags)
                attributes.update(future_attributes)

                if overtake_host:
                    self._logger.info("Overtaking host %r", hostname)
                    attributes["locked_by"] = global_ident

                try:
                    del attributes["hostname"]
                    self._logger.debug(
                        "Host %r contained attribute 'hostname'. Original data: %r",
                        hostname,
                        cmdb_host,
                    )
                except KeyError:
                    pass  # Nothing to do

                return (hostname, attributes, attributes_to_unset)

            return tuple()  # For consistent return type

        tag_matcher = TagMatcher(cmk_tags)
        hosts_to_create = []
        hosts_to_modify = []
        for host in cmdb_hosts:
            hostname = normalize_hostname(host[hostname_field])
            if not host_matches_filters(hostname):
                continue

            try:
                existing_host = cmk_hosts[hostname]
                if hostname in unrelated_hosts:
                    continue  # not managed by this plugin
            except KeyError:  # Host is missing and has to be created
                self._logger.debug("Creating new host %s", hostname)
                creation_tuple = get_host_creation_tuple(
                    host,
                    hostname_field,
                    global_ident,
                    label_prefix=self._connection_config.label_prefix,
                )
                hosts_to_create.append(creation_tuple)
                continue

            self._logger.debug("Checking managed host %s", hostname)
            host_modifications = get_host_modification_tuple(
                existing_host,
                host,
                hostname_field,
                overtake_host=bool(hostname in hosts_to_overtake),
                label_prefix=self._connection_config.label_prefix,
            )
            if not host_modifications:
                continue  # No changes
            hosts_to_modify.append(host_modifications)

        cmdb_hostnames = set(
            normalize_hostname(host[hostname_field]) for host in cmdb_hosts
        )
        # API requires this to be a list
        hosts_to_delete = list(set(hosts_managed_by_plugin) - cmdb_hostnames)

        self._logger.info(
            "Planned host actions: %i to create, %i to modify, %i to delete",
            len(hosts_to_create),
            len(hosts_to_modify),
            len(hosts_to_delete),
        )

        return hosts_to_create, hosts_to_modify, hosts_to_delete

    def _process_folders(self, hosts: List[dict]):
        # Folders are represented as a string.
        # Paths are written Unix style: 'folder/subfolder'
        host_folders = self._get_folders(hosts)
        existing_folders = self._api_client.get_folders()

        folders_to_create = host_folders - existing_folders
        self._logger.debug("Creating the following folders: %s", folders_to_create)
        self._create_folders(sorted(folders_to_create))

    def _get_folders(self, hosts: List[dict]) -> Set[str]:
        "Get the folders from the hosts to create."
        folders = {folder_path for (_, folder_path, _) in hosts}
        self._logger.debug("Found the following folders: %s", folders)

        return folders

    def _create_folders(self, folders: List[str]) -> List[str]:
        if not folders:
            self._logger.debug("No folders to create.")
            return []

        self._logger.debug("Creating the following folders: %s", folders)

        created_folders = []
        for folder in folders:
            self._logger.info("Creating folder: %s", folder)
            self._api_client.add_folder(folder)
            created_folders.append(folder)

        # We want our folders to exist before processing the hosts
        self._activate_changes()
        self._wait_for_folders(folders)

        return created_folders

    def _wait_for_folders(self, folders: List[str]):
        self._logger.debug("Waiting for folders to be created")
        timeout = 60  # seconds
        interval = 2  # seconds
        start = time.time()

        def are_folders_missing() -> bool:
            existing_folders = self._get_existing_folders()
            missing_folders = set(folders) - existing_folders
            self._logger.debug("Missing the following folders: %s", ", ".join(missing_folders))
            return bool(missing_folders)

        def get_duration() -> int:
            return time.time() - start

        while are_folders_missing() and get_duration() < timeout:
            time.sleep(interval)

        if get_duration() > timeout:
            self._logger.debug("Timed out after waiting %is for folders to be created.", timeout)

    def _create_new_hosts(self, hosts_to_create: List[tuple]) -> List[str]:
        if not hosts_to_create:
            self._logger.debug("Nothing to create")
            return []

        created_host_names = self._create_hosts(hosts_to_create)

        self._logger.debug("Created %i hosts", len(created_host_names))
        if not created_host_names:
            return []

        if self._connection_config.use_service_discovery:
            self._discover_hosts(created_host_names)

        return created_host_names

    def _create_hosts(self, hosts_to_create: List[tuple]) -> List[str]:
        self._logger.debug(
            "Creating %i hosts (%s)",
            len(hosts_to_create),
            ", ".join(h[0] for h in hosts_to_create),
        )
        result = self._api_client.add_hosts(hosts_to_create)

        for hostname, message in sorted(result["failed_hosts"].items()):
            self._logger.error('Creation of "%s" failed: %s', hostname, message)

        return result["succeeded_hosts"]

    def _discover_hosts(self, host_names_to_discover: List[str]):
        self._logger.debug(
            "Discovering services on %i hosts (%s)",
            len(host_names_to_discover),
            host_names_to_discover,
        )
        self._api_client.discover_services(host_names_to_discover)
        self._wait_for_bulk_discovery()

    def _wait_for_bulk_discovery(self):
        self._logger.debug("Waiting for bulk discovery to complete")
        timeout = 60  # seconds
        interval = 0.5  # seconds
        start = time.time()

        def discovery_stopped() -> bool:
            return self._api_client.is_discovery_running() is False

        def get_duration() -> int:
            return time.time() - start

        while not discovery_stopped() and get_duration() < timeout:
            time.sleep(interval)

        if not discovery_stopped():
            self._logger.error(
                "Timeout out waiting for the bulk discovery to finish (Timeout: %d sec)",
                timeout,
            )
        else:
            self._logger.debug(
                "Bulk discovery finished after %0.2f seconds", get_duration()
            )

    def _modify_existing_hosts(self, hosts_to_modify: List[tuple]) -> List[str]:
        """
        Modify the given hosts. Returns the IDs of modified hosts.

        Will chunk the given hosts if necessary.
        """
        if not hosts_to_modify:
            self._logger.debug("Nothing to modify")
            return []

        modified_host_names = self._modify_hosts(hosts_to_modify)

        self._logger.debug("Modified %i hosts", len(modified_host_names))
        return modified_host_names

    def _modify_hosts(self, hosts_to_modify: List[tuple]) -> List[str]:
        "Modify the given hosts. Returns the IDs of modified hosts."
        self._logger.debug(
            "Modifying %i hosts (%s)",
            len(hosts_to_modify),
            ", ".join(h[0] for h in hosts_to_modify),
        )
        result = self._api_client.edit_hosts(hosts_to_modify)

        for hostname, message in sorted(result["failed_hosts"].items()):
            self._logger.error('Modification of "%s" failed: %s', hostname, message)

        return result["succeeded_hosts"]

    def _delete_hosts(self, hosts_to_delete: List[str]) -> List[str]:
        """Delete hosts that have been created by this connection and are not existing anymore"""
        if not hosts_to_delete:
            self._logger.debug("Nothing to delete")
            return []

        self._api_client.delete_hosts(hosts_to_delete)

        self._logger.debug(
            "Deleted %i hosts (%s)", len(hosts_to_delete), ", ".join(hosts_to_delete)
        )

        return hosts_to_delete

    def _activate_changes(self) -> bool:
        "Activate changes. Returns a boolean representation of the success."
        self._logger.debug("Activating changes")
        changes_activated = self._api_client.activate_changes()
        if not changes_activated:
            self._logger.info(_("There was no change to activate"))

        return changes_activated


class TagMatcher:
    """
    Tag matching with some additonal logic.

    It is unclear if the casing of the received data will match the
    casing in CMK. Therefore we can search for matching tags in a
    case-insensitive way.

    Looking for a matching tag is always done as following:
    * If there is a tag matching our casing we use this.
    * If there is a tag with a different casing we use this.
    * If no matching tag is found throw an error.
    """

    def __init__(self, tags: dict):
        self._original = tags
        self._normalized_names = {key.lower(): key for key in tags}

    def get_tag(self, name: str) -> str:
        """
        Get the matching tag independent of used casing.

        Throw a `ValueError` if no tag matches.
        """
        if name in self._original:
            return name

        try:
            return self._normalized_names[name.lower()]
        except KeyError as kerr:
            raise ValueError(f"No matching tag for {name!r} found!") from kerr

    def is_possible_value(
        self, tag: str, value: str, raise_error: bool = False
    ) -> bool:
        "Check if the value is possible for the given tag"

        tag = self.get_tag(tag)
        values = self._original[tag]
        match_found = value in values

        if raise_error and not match_found:
            raise ValueError(
                f"{value!r} is no possible choice for tag {tag}. "
                "Valid tags are: {}".format(", ".join(values))
            )

        return match_found


def generate_path_from_labels(
    labels: dict, keys: List[str], depth: int = 0
) -> List[str]:
    "Generate a path from the given labels"
    if not labels:
        if not depth:
            depth = 0

        return [FOLDER_PLACEHOLDER] * depth

    # A host might have the label set without a value.
    # In this case we want to use the placeholder.
    path = [labels.get(key) or FOLDER_PLACEHOLDER for key in keys]

    return path


class FileConnectorHosts:
    "Class used for exchanging data between different stages"

    def __init__(self, hosts: List[dict], hostname_field: str, fieldnames: List[str]):
        self.hosts = hosts
        self.hostname_field = hostname_field
        self.fieldnames = fieldnames

    @classmethod
    def from_serialized_attributes(cls, serialized: dict):
        "Generate an instance from serialized attributes"
        return cls(
            serialized["hosts"], serialized["hostname_field"], serialized["fieldnames"]
        )

    def _serialize_attributes(self) -> dict:
        "Serialize class attributes"
        return {
            "hosts": self.hosts,
            "hostname_field": self.hostname_field,
            "fieldnames": self.fieldnames,
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.hosts!r}, "
            f"{self.hostname_field!r}, {self.fieldnames!r})"
        )
