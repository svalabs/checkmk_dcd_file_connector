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

from cmk.gui.valuespec import (
    AbsoluteDirname,
    Age,
    Dictionary,
)


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
        }

    def _connector_attributes_from_config(self, connector_cfg):
        # type: (Dict) -> None
        self.interval = connector_cfg["interval"]
        self.path = connector_cfg["path"]


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
        with open(self._connection_config.path) as fd:
            reader = csv.DictReader(fd)
            cmdb_hosts = [row for row in reader]

        self._logger.info("Found %d CMDB hosts", len(cmdb_hosts))
        return Phase1Result(CSVConnectorHosts(cmdb_hosts), self._status)

    def _execute_phase2(self, phase1_result):
        # type: (Phase1Result) -> None
        with self.status.next_step("phase2_extract_result", _("Phase 2.1: Extracting result")):
            if isinstance(phase1_result.connector_object, NullObject):
                raise ValueError("Remote site has not completed phase 1 yet")

            if not isinstance(phase1_result.connector_object, CSVConnectorHosts):
                raise ValueError("Got invalid connector object as phase 1 result: %r" %
                                 phase1_result.connector_object)

            cmdb_hosts = phase1_result.connector_object.cmdb_hosts

        with self.status.next_step("phase2_fetch_hosts", _("Phase 2.2: Fetching existing hosts")):
            cmk_hosts = self._web_api.get_all_hosts()

        with self.status.next_step("phase2_update", _("Phase 2.3: Updating config")) as step:
            new_hosts = self._transform_hosts_for_web_api(
                [h for h in cmdb_hosts if self._normalize_hostname(h['HOSTNAME']) not in cmk_hosts])
            created_host_names = self._create_new_hosts(new_hosts)
            change_message = _("Hosts: %d created") % len(
                created_host_names) if created_host_names else _("Nothing changed")
            self._logger.verbose(change_message)
            step.finish(change_message)

        with self.status.next_step("phase2_activate", _("Phase 2.4: Activating changes")) as step:
            if new_hosts:
                if self._activate_changes():
                    step.finish(_("Activated the changes"))
                else:
                    step.finish(_("Not activated"))
            else:
                step.finish(_("No activation needed"))

    @staticmethod
    def _normalize_hostname(hostname):
        # type: (str) -> str
        return hostname.lower().replace(' ', '_')

    def _transform_hosts_for_web_api(self, hosts):
        # type: (List[Dict]) -> List[Tuple[str, str, Dict]]
        folder = 'cmdb'
        label_mapping = {
            "location": "STANDORT",
            "city": "STADT",
            "monitoring": "MONITORING",
            "alarm": "ALARMIERUNG",
            "slarelevant": "SLARELEVANT",
            "identifier": "IDENTIFIER",
        }

        transformed_hosts = []
        for host in hosts:
            # NOTE: The test data for host_name is empty so we use the readable name here for simplicity.
            #       We use a fixed folder here.
            #       It would be possible to use attributes from the CMDB here.
            transformed_hosts.append((
                self._normalize_hostname(host['HOSTNAME']),
                folder,
                {
                    'ipaddress': '127.0.0.1',
                    "labels": {key: host[value] for key, value in label_mapping.items()}
                },
            ))
        return transformed_hosts

    def _create_new_hosts(self, hosts_to_create):
        # type: (List) -> List[str]
        if not hosts_to_create:
            self._logger.debug("Nothing to create")
            return []

        created_host_names = self._create_hosts(hosts_to_create)
        self._logger.debug("Created %d hosts", len(created_host_names))
        if not created_host_names:
            return []

        self._discover_hosts(created_host_names)

        return created_host_names

    def _create_hosts(self, hosts_to_create):
        # type: (List) -> List[str]
        self._logger.debug(
            "Creating %d hosts (%s)",
            len(hosts_to_create),
            ", ".join(h[0] for h in hosts_to_create),
        )
        result = self._web_api.add_hosts(hosts_to_create)

        for hostname, message in sorted(result["failed_hosts"].iteritems()):
            self._logger.error("Creation of \"%s\" failed: %s" % (hostname, message))

        return result["succeeded_hosts"]

    def _discover_hosts(self, host_names_to_discover):
        # type: (List[str]) -> None
        self._logger.debug("Discovering services on %d hosts (%s)", len(host_names_to_discover),
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

    def _activate_changes(self):
        # type: () -> bool
        self._logger.debug("Activating changes")
        try:
            self._web_api.activate_changes()
        except MKAPIError as e:
            if "no changes to activate" in "%s" % e:
                self._logger.info(_("There was no change to activate"))
                return False
            raise
        return True


@connector_object_registry.register
class CSVConnectorHosts(ConnectorObject):
    def __init__(self, cmdb_hosts):
        self.cmdb_hosts = cmdb_hosts

    @classmethod
    def from_serialized_attributes(cls, serialized):
        return cls(serialized["cmdb_hosts"])

    def _serialize_attributes(self):
        # type: () -> Dict
        return {"cmdb_hosts": self.cmdb_hosts}

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.cmdb_hosts)


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
                ("path", AbsoluteDirname(
                    title=_("Path of to the CSV file to import."),
                    help=_("This is the path to the CSV file."),
                    allow_empty=False,
                    validate=self.validate_csv,
                )),
            ],
            optional_keys=[],
        )

    @staticmethod
    def validate_csv(filename, varprefix):
        if not os.path.isfile(filename):
            raise MKUserError(varprefix, "No file %r" % filename)
