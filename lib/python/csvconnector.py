# -*- encoding: utf-8; py-indent-offset: 4 -*-

# Copyright (C) 2020  Niko Wenselowski <niko.wenselowski@sva.de>
#                     for SVA System Vertrieb Alexander GmbH

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

from __future__ import absolute_import

import csv
import os.path
import re
import time

from typing import (  # pylint: disable=unused-import
    Dict, List, Tuple,
)

from cmk.utils.i18n import _

from cmk.cee.dcd.connectors.utils import (
    Phase1Result,
    NullObject,
    ConnectorType,
    ConnectorObject,
    connector_object_registry,
    Connector,
    connector_type_registry,
    connector_registry,
    MKAPIError,
)

from cmk.cee.dcd.config import (
    connector_config_registry,
    ConnectorConfig,
)

from cmk.gui.cee.plugins.wato.dcd import (
    connector_parameters_registry,
    ConnectorParameters,
)

from cmk.gui.exceptions import MKUserError

from cmk.gui.plugins.wato import FullPathFolderChoice

from cmk.gui.valuespec import (
    Age,
    Filename,
    Dictionary,
    ListOfStrings,
    RegExpUnicode,
)


def normalize_hostname(hostname):
    # type: (str) -> str
    return hostname.lower().replace(' ', '_')


def get_host_label(host, hostname_field):
    # type: (Dict, str) -> Dict
    return {key.lower(): value for key, value in host.items() if key != hostname_field}


@connector_type_registry.register
class CSVConnectorType(ConnectorType):
    def name(self):
        return "csvconnector"

    def title(self):
        return _("CSV import")

    def description(self):
        return _("Connector for importing data from a CSV file.")


@connector_config_registry.register
class CSVConnectorConfig(ConnectorConfig):
    def name(self):
        return "csvconnector"

    def _connector_attributes_to_config(self):
        # type: () -> Dict
        return {
            "interval": self.interval,
            "path": self.path,
            "folder": self.folder,
            "host_filters": self.host_filters,
            "host_overtake_filters": self.host_overtake_filters,
        }

    def _connector_attributes_from_config(self, connector_cfg):
        # type: (Dict) -> None
        self.interval = connector_cfg["interval"]
        self.path = connector_cfg["path"]
        self.folder = connector_cfg["folder"]
        self.host_filters = connector_cfg.get("host_filters", [])
        self.host_overtake_filters = connector_cfg.get("host_overtake_filters", [])


@connector_registry.register
class CSVConnector(Connector):
    connector_type = CSVConnectorType

    def __init__(self, logger, config, web_api, connection_id, omd_site):
        self._connection_config = CSVConnectorConfig()
        super(CSVConnector, self).__init__(logger, config, web_api, connection_id, omd_site)
        self._type = self.connector_type()

    def _execution_interval(self):
        return self._connection_config.interval

    def _execute_phase1(self):
        # type: () -> Phase1Result
        with open(self._connection_config.path) as cmdb_export:
            reader = csv.DictReader(cmdb_export)
            cmdb_hosts = list(reader)
            fields = reader.fieldnames

        self._logger.info("Found %i CMDB hosts", len(cmdb_hosts))
        return Phase1Result(CSVConnectorHosts(cmdb_hosts, fields), self._status)

    def _execute_phase2(self, phase1_result):
        # type: (Phase1Result) -> None
        with self.status.next_step("phase2_extract_result", _("Phase 2.1: Extracting result")):
            if isinstance(phase1_result.connector_object, NullObject):
                raise ValueError("Remote site has not completed phase 1 yet")

            if not isinstance(phase1_result.connector_object, CSVConnectorHosts):
                raise ValueError("Got invalid connector object as phase 1 result: %r" %
                                 phase1_result.connector_object)

            cmdb_hosts = phase1_result.connector_object.cmdb_hosts
            # We always assume that the first column in our CSV is the hostname
            hostname_field = phase1_result.connector_object.fieldnames[0]

        with self.status.next_step("phase2_fetch_hosts", _("Phase 2.2: Fetching existing hosts")):
            cmk_hosts = self._web_api.get_all_hosts()

        with self.status.next_step("phase2_update", _("Phase 2.3: Updating config")) as step:
            hosts_to_create, hosts_to_modify, hosts_to_delete = self._partition_hosts(cmdb_hosts, cmk_hosts, hostname_field)

            created_host_names = self._create_new_hosts(hosts_to_create)
            modified_host_names = self._modify_existing_hosts(hosts_to_modify)
            deleted_host_names = self._delete_hosts(hosts_to_delete)

            changes_to_hosts = bool(created_host_names or modified_host_names or deleted_host_names)
            if changes_to_hosts:
                if created_host_names and modified_host_names and deleted_host_names:
                    change_message = _("Hosts: %i created, %i modified, %i deleted") % (len(created_host_names), len(modified_host_names), len(deleted_host_names))
                elif created_host_names and modified_host_names:
                    change_message = _("Hosts: %i created, %i modified") % (len(created_host_names), len(modified_host_names))
                elif created_host_names and deleted_host_names:
                    change_message = _("Hosts: %i created, %i deleted") % (len(created_host_names), len(deleted_host_names))
                elif modified_host_names and deleted_host_names:
                    change_message = _("Hosts: %i modified, %i deleted") % (len(modified_host_names), len(deleted_host_names))
                elif created_host_names:
                    change_message = _("Hosts: %i created") % len(created_host_names)
                elif deleted_host_names:
                    change_message = _("Hosts: %i deleted") % len(deleted_host_names)
                else:
                    change_message = _("Hosts: %i modified") % len(modified_host_names)
            else:
                change_message = _("Nothing changed")

            self._logger.verbose(change_message)
            step.finish(change_message)

        with self.status.next_step("phase2_activate", _("Phase 2.4: Activating changes")) as step:
            if changes_to_hosts:
                if self._activate_changes():
                    step.finish(_("Activated the changes"))
                else:
                    step.finish(_("Not activated"))
            else:
                step.finish(_("No activation needed"))

    def _partition_hosts(self, cmdb_hosts, cmk_hosts, hostname_field):
        # type: (List[Dict], Dict, str) -> Tuple[List, List, List]
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
        host_overtake_filters = [re.compile(f) for f in self._connection_config.host_overtake_filters]

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
                self._logger.info("Overtaking host %r", host_name)
                hosts_to_overtake.add(host_name)
            else:
                self._logger.debug("Host %r already exists as an unrelated host", host_name)
                unrelated_hosts.add(host_name)

        self._logger.verbose(
            "Hosts: %i existing, %i existing but unrelated",
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

        folder_path = self._connection_config.folder
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
                hosts_to_create.append((
                    hostname,
                    folder_path,
                    {
                        "labels": get_host_label(host, hostname_field),
                        # Lock the host in order to be able to detect hosts
                        # that have been created through this plugin.
                        "locked_by": global_ident,
                    },
                ))
                continue

            attributes = existing_host["attributes"]
            api_label = attributes.get("labels", {})
            future_label = get_host_label(host, hostname_field)

            overtake_host = hostname in hosts_to_overtake
            if overtake_host or needs_modification(api_label, future_label):
                api_label.update(future_label)
                attributes["labels"] = api_label

                if overtake_host:
                    attributes["locked_by"] = global_ident

                hosts_to_modify.append((hostname, attributes, []))

        cmdb_hostnames = set(
            normalize_hostname(host[hostname_field])
            for host in cmdb_hosts
        )
        # API requires this to be a list
        hosts_to_delete = list(set(hosts_managed_by_plugin) - cmdb_hostnames)

        self._logger.verbose(
            "Hosts: %i to create, %i to modify, %i to delete",
            len(hosts_to_create),
            len(hosts_to_modify),
            len(hosts_to_delete),
        )

        return hosts_to_create, hosts_to_modify, hosts_to_delete

    def _create_new_hosts(self, hosts_to_create):
        # type: (List) -> List[str]
        if not hosts_to_create:
            self._logger.debug("Nothing to create")
            return []

        created_host_names = self._create_hosts(hosts_to_create)
        self._logger.debug("Created %i hosts", len(created_host_names))
        if not created_host_names:
            return []

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
            self._logger.error("Creation of \"%s\" failed: %s" % (hostname, message))

        return result["succeeded_hosts"]

    def _discover_hosts(self, host_names_to_discover):
        # type: (List[str]) -> None
        self._logger.debug("Discovering services on %i hosts (%s)", len(host_names_to_discover),
                           host_names_to_discover)
        self._web_api.bulk_discovery_start(host_names_to_discover)
        self._wait_for_bulk_discovery()

    def _wait_for_bulk_discovery(self):
        # type: () -> None
        self._logger.debug("Waiting for bulk discovery to complete")
        timeout, interval = 60, 0.5

        def condition():
            return self._web_api.bulk_discovery_status()["is_active"] is False

        start = time.time()
        while not condition() and time.time() - start < timeout:
            time.sleep(interval)
        if not condition():
            self._logger.error(
                "Timeout out waiting for the bulk discovery to finish (Timeout: %d sec)", condition,
                timeout)
        else:
            self._logger.debug("Bulk discovery finished after %0.2f seconds", time.time() - start)

    def _modify_existing_hosts(self, hosts_to_modify):
        # type: (List) -> List[str]
        if not hosts_to_modify:
            self._logger.debug("Nothing to modify")
            return []

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
            self._logger.error("Modification of \"%s\" failed: %s" % (hostname, message))

        return result["succeeded_hosts"]

    def _delete_hosts(self, hosts_to_delete):
        # type: (List[str]) -> List[str]
        """Delete hosts that have been created by this connection and are not existing anymore"""
        if not hosts_to_delete:
            self._logger.debug("Nothing to delete")
            return []

        self._web_api.delete_hosts(hosts_to_delete)
        self._logger.debug("Deleted %i hosts (%s)", len(hosts_to_delete),
                           ", ".join(hosts_to_delete))

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


@connector_object_registry.register
class CSVConnectorHosts(ConnectorObject):
    def __init__(self, cmdb_hosts, fieldnames):
        self.cmdb_hosts = cmdb_hosts
        self.fieldnames = fieldnames

    @classmethod
    def from_serialized_attributes(cls, serialized):
        return cls(serialized["cmdb_hosts"], serialized["fieldnames"])

    def _serialize_attributes(self):
        # type: () -> Dict
        return {"cmdb_hosts": self.cmdb_hosts, "fieldnames": self.fieldnames}

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.cmdb_hosts, self.fieldnames)


@connector_parameters_registry.register
class CSVConnectorParameters(ConnectorParameters):
    def connector_type(self):
        return connector_type_registry["csvconnector"]

    def valuespec(self):
        return Dictionary(
            elements=[
                ("interval", Age(
                    title=_("Sync interval"),
                    minvalue=1,
                    default_value=60,
                )),
                ("path", Filename(
                    title=_("Path of to the CSV file to import."),
                    help=_("This is the path to the CSV file. "
                           "The first column of the file is assumed to contain the hostname."),
                    allow_empty=False,
                    validate=self.validate_csv,
                )),
                ("folder", FullPathFolderChoice(
                    title=_("Create hosts in"),
                    help=_("All hosts created by this connection will be "
                           "placed in this folder. You are free to move the "
                           "host to another folder after creation."),
                )),
                ("host_filters", ListOfStrings(
                    title=_("Only add matching hosts"),
                    help=_(
                        "Only care about hosts with names that match one of these "
                        "regular expressions."),
                    orientation="horizontal",
                    valuespec=RegExpUnicode(mode=RegExpUnicode.prefix,),
                )),
                ("host_overtake_filters", ListOfStrings(
                    title=_("Take over existing hosts"),
                    help=_(
                        "Take over already existing hosts with names that "
                        "match one of these regular expressions. This will not"
                        "take over hosts handled by foreign connections or "
                        "plugins. Hosts that have been took over will be "
                        "deleted once they vanish from the import file."),
                    orientation="horizontal",
                    valuespec=RegExpUnicode(mode=RegExpUnicode.prefix,),
                )),
            ],
            optional_keys=["host_filters", "host_overtake_filters"],
        )

    @staticmethod
    def validate_csv(filename, varprefix):
        if not os.path.isfile(filename):
            raise MKUserError(varprefix, "No file %r" % filename)