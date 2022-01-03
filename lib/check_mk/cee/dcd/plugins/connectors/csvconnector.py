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
# Copyright (C) 2021  Niko Wenselowski <niko.wenselowski@sva.de>
#                     for SVA System Vertrieb Alexander GmbH
"""
CSVConnector import logic.
"""

import csv
import json
import re
import time
from abc import abstractmethod
from functools import partial
from itertools import zip_longest

from typing import (  # pylint: disable=unused-import
    Dict,
    List,
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

IP_ATTRIBUTES = {"ipv4", "ip", "ipaddress"}
FOLDER_PLACEHOLDER = "undefined"
PATH_SEPERATOR = "/"


def normalize_hostname(hostname: str) -> str:
    "Generate a normalized hostname form"
    return hostname.lower().replace(" ", "_")


def get_host_label(host: dict, hostname_field: str) -> dict:
    """
    Get the labels from a host.

    Labels are either prefixed with "_label" or are not any of the
    known values for IPs.
    """

    def unlabelify(value):
        if value.startswith("label_"):
            return value[6:]

        return value

    tmp = {key.lower(): value for key, value in host.items() if key != hostname_field}

    return {
        unlabelify(key): value
        for key, value in tmp.items()
        if not (is_tag(key) or key in IP_ATTRIBUTES)
    }


def get_ip_address(host: dict):
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


def get_host_tags(attributes: dict) -> dict:
    return {attr: value for attr, value in attributes.items() if is_tag(attr)}


def is_tag(name):
    """
    Is the name a 'tag'?

    Checks for attributes that begin 'tag_' as this is how the
    CMK API handles this cases.
    """
    return name.lower().startswith("tag_")


def create_hostlike_tags(tags_from_cmk):
    """
    Create tags in a format that is similar to the ones
    present at hosts.

    Tags at a host are prefixed with 'tag_'
    """
    return {
        "tag_" + tag["id"]: [choice["id"] for choice in tag["tags"]]
        for tag in tags_from_cmk
    }


def chunks(iterable, count):
    "Collect data into fixed-length chunks or blocks"
    # chunks('ABCDEFG', 3) --> ABC DEF Gxx"
    args = [iter(iterable)] * count
    return zip_longest(*args)


@connector_config_registry.register
class CSVConnectorConfig(ConnectorConfig):
    """Loading the persisted connection config"""

    @classmethod
    def name(cls):
        # type: () -> str
        return "csvconnector"

    def _connector_attributes_to_config(self) -> dict:
        return {
            "interval": self.interval,
            "path": self.path,
            "file_format": self.file_format,
            "folder": self.folder,
            "host_filters": self.host_filters,
            "host_overtake_filters": self.host_overtake_filters,
            "chunk_size": self.chunk_size,
            "use_service_discovery": self.use_service_discovery,
            "label_path_template": self.label_path_template,
            "csv_delimiter": self.csv_delimiter,
        }

    def _connector_attributes_from_config(self, connector_cfg: dict):
        self.interval = connector_cfg["interval"]  # type: int
        self.path = connector_cfg["path"]  # type: str
        self.file_format = connector_cfg.get("file_format", "csv")  # type: str
        self.folder = connector_cfg["folder"]  # type: str
        self.host_filters = connector_cfg.get("host_filters", [])  # type: list
        self.host_overtake_filters = connector_cfg.get(
            "host_overtake_filters", []
        )  # type: list
        self.chunk_size = connector_cfg.get("chunk_size", 0)  # type: int
        self.use_service_discovery = connector_cfg.get(
            "use_service_discovery", True
        )  # type: bool
        self.label_path_template = connector_cfg.get("label_path_template", "")
        self.csv_delimiter = connector_cfg.get("csv_delimiter")


class FileImporter:
    "Basic file importer"

    def __init__(self, filepath):
        self.filepath = filepath
        self.hosts = None
        self.fields = None
        self.hostname_field = None

    @abstractmethod
    def import_hosts(self):
        "This function will be called for importing the hosts."


class CSVImporter(FileImporter):
    "Import hosts from a CSV file"

    def __init__(self, filepath, delimiter=None):
        super().__init__(filepath)

        self.delimiter = delimiter

    def import_hosts(self):
        with open(self.filepath) as cmdb_export:
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


class JSONImporter(FileImporter):
    "Import hosts from a file with JSON"

    EXPECTED_HOST_NAMES = [
        "name",
        "hostname",
    ]

    def import_hosts(self):
        with open(self.filepath) as export_file:
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

    def __init__(self, filepath):
        super().__init__(filepath)

        # We know that this is our field
        self.hostname_field = "name"

    def import_hosts(self):
        with open(self.filepath) as export_file:
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

    def format_host(self, host):
        # BVQ sends more fields than we handle.
        # We currently exclude:
        #  - masterGroupingObjectIpv4
        #  - masterGroupingObjectIpv6

        new_host = {"name": host["name"]}

        for host_key, json_key in self.FIELD_MAPPING:
            try:
                new_host[host_key] = host[json_key]
            except KeyError:
                continue

        return new_host


@connector_registry.register
class CSVConnector(Connector):
    @classmethod
    def name(cls):
        # type: () -> str
        return "csvconnector"

    def _execution_interval(self):
        # type: () -> int
        """Number of seconds to sleep after each phase execution"""
        return self._connection_config.interval

    def _execute_phase1(self):
        # type: () -> Phase1Result
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

    def _get_importer(self):
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
            raise RuntimeError("Invalid file format {!r}".format(file_format))

        return importer

    def _execute_phase2(self, phase1_result):
        # type: (Phase1Result) -> None
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
                    "Got invalid connector object as phase 1 result: %r"
                    % phase1_result.connector_object
                )

            cmdb_hosts = phase1_result.connector_object.hosts
            fieldnames = phase1_result.connector_object.fieldnames
            hostname_field = phase1_result.connector_object.hostname_field

        with self.status.next_step(
            "phase2_fetch_hosts", _("Phase 2.2: Fetching existing hosts")
        ):
            cmk_hosts = self._web_api.get_all_hosts()

            cmk_tags = {}
            fields_contain_tags = any(is_tag(name) for name in fieldnames)
            if fields_contain_tags:
                # The builtin _web_api only has methods for very few
                # API commands. In an ideal world we could directly
                # call the API like this:
                # cmk_tags = self._web_api.get_hosttags()

                # The following lines can be used to debug _web_api.
                # self._logger.info("Dir: {}".format(dir(self._web_api)))
                # import inspect
                # self._logger.info("Sig: {}".format(inspect.getargspec(self._web_api._api_request)))

                # Working around to get the required results from
                # the API.
                # The second parameter has to be a dict.
                tag_response = self._web_api._api_request(
                    "webapi.py?action=get_hosttags", {}
                )

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

            self._chunk_size = self._connection_config.chunk_size
            if self._chunk_size:
                self._logger.info("Processing in chunks of %i", self._chunk_size)

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
            if changes_to_hosts and not self._chunk_size:
                # When used with chunks each step activates the host
                # changes they did. Therefore no further activation
                # is needed.
                if self._activate_changes():
                    step.finish(_("Activated the changes"))
                else:
                    step.finish(_("Not activated"))
            else:
                step.finish(_("No activation needed"))

    def _partition_hosts(self, cmdb_hosts, cmk_hosts, hostname_field, cmk_tags):
        # type: (List[Dict], Dict, str, Dict) -> Tuple[List, List, List]
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

        def overtake_host(hostname):
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

        def host_matches_filters(host):
            if not host_filters:
                return True

            return any(f.match(host) for f in host_filters)

        def needs_modification(old, new):
            for label, value in new.items():
                try:
                    if old[label] != value:
                        return True
                except KeyError:
                    return True

            return False

        def create_host_tags(host_tags):
            tags = {tag_matcher.get_tag(key): value for key, value in host_tags.items()}

            for tag, choice in tags.items():
                try:
                    tag_matcher.is_possible_value(tag, choice, True)
                except ValueError as verr:
                    self._logger.error(verr)

            return tags

        def ip_needs_modification(old_ip, new_ip):
            return old_ip != new_ip

        if self._connection_config.label_path_template:
            path_labels = self._connection_config.label_path_template.split(
                PATH_SEPERATOR
            )

            def get_dynamic_folder_path(
                labels: dict, keys: List[str], depth: int
            ) -> str:
                def replace_special_chars(string):
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
            def get_folder_path(_):
                return self._connection_config.folder

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
            except KeyError:
                labels = get_host_label(host, hostname_field)
                attributes = {
                    "labels": labels,
                    # Lock the host in order to be able to detect hosts
                    # that have been created through this plugin.
                    "locked_by": global_ident,
                }

                ip_address = get_ip_address(host)
                if ip_address is not None:
                    attributes["ipaddress"] = ip_address

                tags = create_host_tags(get_host_tags(host))
                attributes.update(tags)

                folder_path = get_folder_path(labels)

                hosts_to_create.append((hostname, folder_path, attributes))
                continue

            attributes = existing_host["attributes"]
            api_label = attributes.get("labels", {})
            future_label = get_host_label(host, hostname_field)

            api_tags = get_host_tags(attributes)
            host_tags = get_host_tags(host)
            future_tags = create_host_tags(host_tags)

            existing_ip = attributes.get("ipaddress")
            future_ip = get_ip_address(host)

            overtake_host = hostname in hosts_to_overtake
            update_needed = (
                overtake_host
                or needs_modification(api_label, future_label)  # noqa: W503
                or needs_modification(api_tags, future_tags)  # noqa: W503
                or ip_needs_modification(existing_ip, future_ip)
            )  # noqa: W503

            if update_needed:
                api_label.update(future_label)
                attributes["labels"] = api_label
                attributes["ipaddress"] = future_ip

                attributes.update(future_tags)

                if overtake_host:
                    self._logger.info("Overtaking host %r", hostname)
                    attributes["locked_by"] = global_ident

                try:
                    del attributes["hostname"]
                    self._logger.debug(
                        "Host %r contained attribute 'hostname'. Original data: %r",
                        hostname,
                        host,
                    )
                except KeyError:
                    pass  # Nothing to do

                hosts_to_modify.append((hostname, attributes, []))

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

    def _process_folders(self, hosts: List):
        # Folders are represented as a string.
        # Paths are written Unix style: 'folder/subfolder'
        host_folders = self._get_folders(hosts)
        existing_folders = self._get_existing_folders()

        folders_to_create = host_folders - existing_folders
        self._logger.debug("Creating the following folders: %s", folders_to_create)
        self._create_folders(sorted(folders_to_create))

    def _get_existing_folders(self) -> Set:
        all_folders = self._web_api._api_request("webapi.py?action=get_all_folders", {})

        return set(all_folders)

    def _get_folders(self, hosts: List) -> Set:
        "Get the folders from the hosts to create."
        folders = {folder_path for (_, folder_path, _) in hosts}
        self._logger.debug("Found the following folders: %s", folders)

        return folders

    def _create_folders(self, folders: List) -> List:
        if not folders:
            self._logger.debug("No folders to create.")
            return []

        self._logger.debug("Creating the following folders: %s", folders)

        created_folders = []
        for folder in folders:
            self._logger.info("Creating folder: %s", folder)

            # Follow the required format for the request.
            folder_data = {"folder": folder, "attributes": {}}
            data = {"request": json.dumps(folder_data)}

            self._web_api._api_request("webapi.py?action=add_folder", data)
            created_folders.append(folder)

        # We want our folders to exist before processing the hosts
        self._activate_changes()

        return created_folders

    def _create_new_hosts(self, hosts_to_create):
        # type: (List) -> List[str]
        if not hosts_to_create:
            self._logger.debug("Nothing to create")
            return []

        if self._chunk_size:
            created_host_names = []
            for chunk in chunks(hosts_to_create, self._chunk_size):
                created_hosts = self._create_hosts([h for h in chunk if h])

                if created_hosts:
                    created_host_names.extend(created_hosts)
                    self._logger.debug("Activating changes...")
                    self._activate_changes()
        else:
            created_host_names = self._create_hosts(hosts_to_create)

        self._logger.debug("Created %i hosts", len(created_host_names))
        if not created_host_names:
            return []

        if self._connection_config.use_service_discovery:
            self._discover_hosts(created_host_names)

        return created_host_names

    def _create_hosts(self, hosts_to_create):
        # type: (List) -> List[str]
        self._logger.debug(
            "Creating %i hosts (%s)",
            len(hosts_to_create),
            ", ".join(h[0] for h in hosts_to_create),
        )
        result = self._web_api.add_hosts(hosts_to_create)

        for hostname, message in sorted(result["failed_hosts"].items()):
            self._logger.error('Creation of "%s" failed: %s', hostname, message)

        return result["succeeded_hosts"]

    def _discover_hosts(self, host_names_to_discover):
        # type: (List[str]) -> None
        self._logger.debug(
            "Discovering services on %i hosts (%s)",
            len(host_names_to_discover),
            host_names_to_discover,
        )
        self._web_api.bulk_discovery_start(host_names_to_discover)
        self._wait_for_bulk_discovery()

    def _wait_for_bulk_discovery(self):
        # type: () -> None
        self._logger.debug("Waiting for bulk discovery to complete")
        timeout = 60  # seconds
        interval = 0.5  # seconds
        start = time.time()

        def discovery_stopped():
            return self._web_api.bulk_discovery_status()["is_active"] is False

        def get_duration():
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

    def _modify_existing_hosts(self, hosts_to_modify):
        # type: (List) -> List[str]
        if not hosts_to_modify:
            self._logger.debug("Nothing to modify")
            return []

        if self._chunk_size:
            modified_host_names = []
            for chunk in chunks(hosts_to_modify, self._chunk_size):
                modified_hosts = self._modify_hosts([h for h in chunk if h])

                if modified_hosts:
                    modified_host_names.extend(modified_hosts)
                    self._logger.debug("Activating changes...")
                    self._activate_changes()
        else:
            modified_host_names = self._modify_hosts(hosts_to_modify)

        self._logger.debug("Modified %i hosts", len(modified_host_names))
        return modified_host_names

    def _modify_hosts(self, hosts_to_modify):
        # type: (List) -> List[str]
        self._logger.debug(
            "Modifying %i hosts (%s)",
            len(hosts_to_modify),
            ", ".join(h[0] for h in hosts_to_modify),
        )
        result = self._web_api.edit_hosts(hosts_to_modify)

        for hostname, message in sorted(result["failed_hosts"].items()):
            self._logger.error('Modification of "%s" failed: %s', hostname, message)

        return result["succeeded_hosts"]

    def _delete_hosts(self, hosts_to_delete):
        # type: (List[str]) -> List[str]
        """Delete hosts that have been created by this connection and are not existing anymore"""
        if not hosts_to_delete:
            self._logger.debug("Nothing to delete")
            return []

        if self._chunk_size:
            for chunk in chunks(hosts_to_delete, self._chunk_size):
                self._web_api.delete_hosts([h for h in chunk if h])
                self._logger.debug("Activating changes...")
                self._activate_changes()
        else:
            self._web_api.delete_hosts(hosts_to_delete)

        self._logger.debug(
            "Deleted %i hosts (%s)", len(hosts_to_delete), ", ".join(hosts_to_delete)
        )

        return hosts_to_delete

    def _activate_changes(self):
        # type: () -> bool
        self._logger.debug("Activating changes")
        try:
            self._web_api.activate_changes()
        except MKAPIError as error:
            if "no changes to activate" in "%s" % error:
                self._logger.info(_("There was no change to activate"))
                return False
            raise
        return True


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

    def __init__(self, d):
        self._original = d
        self._normalized_names = {key.lower(): key for key in d}

    def get_tag(self, name):
        # type: (str) -> str
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

    def is_possible_value(self, tag, value, raise_error=False):
        tag = self.get_tag(tag)
        values = self._original[tag]
        match_found = value in values

        if raise_error and not match_found:
            raise ValueError(
                "{!r} is no possible choice for tag {}. "
                "Valid tags are: {}".format(value, tag, ", ".join(values))
            )

        return match_found


def generate_path_from_labels(labels: dict, keys: List[str], depth: int = 0) -> List:
    if not labels:
        if not depth:
            depth = 0

        return [FOLDER_PLACEHOLDER] * depth

    # A host might have the label set without a value.
    # In this case we want to use the placeholder.
    path = [labels.get(key) or FOLDER_PLACEHOLDER for key in keys]

    return path


class FileConnectorHosts:
    def __init__(self, hosts, hostname_field, fieldnames):
        self.hosts = hosts
        self.hostname_field = hostname_field
        self.fieldnames = fieldnames

    @classmethod
    def from_serialized_attributes(cls, serialized):
        return cls(
            serialized["hosts"], serialized["hostname_field"], serialized["fieldnames"]
        )

    def _serialize_attributes(self) -> dict:
        return {
            "hosts": self.hosts,
            "hostname_field": self.hostname_field,
            "fieldnames": self.fieldnames,
        }

    def __repr__(self) -> str:
        return "%s(%r, %r, %r)" % (
            self.__class__.__name__,
            self.hosts,
            self.hostname_field,
            self.fieldnames,
        )
