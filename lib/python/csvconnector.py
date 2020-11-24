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

import csv
import re
import time

from typing import (  # pylint: disable=unused-import
    Dict, List, Tuple,
)

from cmk.utils.i18n import _

from cmk.cee.dcd.connectors.utils import MKAPIError

from cmk.cee.dcd.plugins.connectors.connectors_api.v0 import (  # noqa: F401 # pylint: disable=unused-import
    connector_config_registry,
    ConnectorConfig,
    connector_registry,
    Connector,
    Phase1Result,
    NullObject,
)


def normalize_hostname(hostname):
    # type: (str) -> str
    return hostname.lower().replace(' ', '_')


def get_host_label(host, hostname_field):
    # type: (Dict, str) -> Dict
    def unlabelify(value):
        if value.startswith('label_'):
            return value[6:]

        return value

    tmp = {key.lower(): value for key, value in host.items()
           if key != hostname_field}

    return {unlabelify(key): value for key, value in tmp.items()
            if not is_tag(key)}


def get_host_tags(attributes):
    # type: (Dict) -> Dict
    return {attr: value for attr, value in attributes.items()
            if is_tag(attr)}


def is_tag(name):
    """
    Is the name a 'tag'?

    Checks for attributes that begin 'tag_' as this is how the
    CMK API handles this cases.
    """
    return name.lower().startswith('tag_')


def create_hostlike_tags(tags_from_cmk):
    """
    Create tags in a format that is similar to the ones
    present at hosts.

    Tags at a host are prefixed with 'tag_'
    """
    return {
        'tag_' + tag['id']: [choice['id'] for choice in tag['tags']]
        for tag in tags_from_cmk
    }


@connector_config_registry.register
class CSVConnectorConfig(ConnectorConfig):
    """Loading the persisted connection config"""

    @classmethod
    def name(cls):
        # type: () -> str
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
        self.interval = connector_cfg["interval"]  # type: int
        self.path = connector_cfg["path"]  # type: str
        self.folder = connector_cfg["folder"]  # type: str
        self.host_filters = connector_cfg.get("host_filters", [])  # type: list
        self.host_overtake_filters = connector_cfg.get("host_overtake_filters", [])  # type: list


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
        with open(self._connection_config.path) as cmdb_export:
            reader = csv.DictReader(cmdb_export)
            cmdb_hosts = list(reader)
            fields = reader.fieldnames

        self._logger.info("Found %i hosts in CSV file", len(cmdb_hosts))
        return Phase1Result(CSVConnectorHosts(cmdb_hosts, fields), self._status)

    def _execute_phase2(self, phase1_result):
        # type: (Phase1Result) -> None
        """Execute the second synchronization phase

        It is executed based on the information provided by the first phase. This
        phase is intended to talk to the local WATO Web API for updating the
        Check_MK configuration based on the information provided by the connection.
        """
        with self.status.next_step("phase2_extract_result", _("Phase 2.1: Extracting result")):
            if isinstance(phase1_result.connector_object, NullObject):
                raise ValueError("Remote site has not completed phase 1 yet")

            if not isinstance(phase1_result.connector_object, CSVConnectorHosts):
                raise ValueError("Got invalid connector object as phase 1 result: %r" %
                                 phase1_result.connector_object)

            cmdb_hosts = phase1_result.connector_object.cmdb_hosts

            fieldnames = phase1_result.connector_object.fieldnames
            # We always assume that the first column in our CSV is the hostname
            hostname_field = fieldnames[0]

        with self.status.next_step("phase2_fetch_hosts", _("Phase 2.2: Fetching existing hosts")):
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
                tag_response = self._web_api._api_request('webapi.py?action=get_hosttags', {})

                cmk_tags = create_hostlike_tags(tag_response["tag_groups"])
                cmk_tags.update(create_hostlike_tags(tag_response['builtin']['tag_groups']))

        with self.status.next_step("phase2_update", _("Phase 2.3: Updating config")) as step:
            hosts_to_create, hosts_to_modify, hosts_to_delete = self._partition_hosts(cmdb_hosts,
                                                                                      cmk_hosts,
                                                                                      hostname_field,
                                                                                      cmk_tags)

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

            self._logger.info(change_message)
            step.finish(change_message)

        with self.status.next_step("phase2_activate", _("Phase 2.4: Activating changes")) as step:
            if changes_to_hosts:
                if self._activate_changes():
                    step.finish(_("Activated the changes"))
                else:
                    step.finish(_("Not activated"))
            else:
                step.finish(_("No activation needed"))

    def _partition_hosts(self, cmdb_hosts, cmk_hosts, hostname_field, cmk_tags):
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

        self._logger.info(
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

        def create_host_tags(host_tags):
            tags = {tag_matcher.get_tag(key): value
                    for key, value in host_tags.items()}

            for tag, choice in tags.items():
                try:
                    tag_matcher.is_possible_value(tag, choice, True)
                except ValueError as verr:
                    self._logger.error(verr)

            return tags

        tag_matcher = TagMatcher(cmk_tags)
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
                attributes = {
                    "labels": get_host_label(host, hostname_field),
                    # Lock the host in order to be able to detect hosts
                    # that have been created through this plugin.
                    "locked_by": global_ident,
                }

                tags = create_host_tags(get_host_tags(host))
                attributes.update(tags)

                hosts_to_create.append((hostname, folder_path, attributes))
                continue

            attributes = existing_host["attributes"]
            api_label = attributes.get("labels", {})
            future_label = get_host_label(host, hostname_field)

            api_tags = get_host_tags(attributes)
            host_tags = get_host_tags(host)
            future_tags = create_host_tags(host_tags)

            overtake_host = hostname in hosts_to_overtake
            update_needed = (overtake_host
                             or needs_modification(api_label, future_label)
                             or needs_modification(api_tags, future_tags))

            if update_needed:
                api_label.update(future_label)
                attributes["labels"] = api_label

                attributes.update(future_tags)

                if overtake_host:
                    attributes["locked_by"] = global_ident

                hosts_to_modify.append((hostname, attributes, []))

        cmdb_hostnames = set(
            normalize_hostname(host[hostname_field])
            for host in cmdb_hosts
        )
        # API requires this to be a list
        hosts_to_delete = list(set(hosts_managed_by_plugin) - cmdb_hostnames)

        self._logger.info(
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

    def __contains__(self, k):
        if k in self._original:
            return True

        return k.lower() in self._normalized_names

    def __len__(self):
        return len(self._original)

    def __iter__(self):
        return iter(self._original)

    def __getitem__(self, k):
        try:
            return self._original[k]
        except KeyError:
            key = self._normalized_names[k.lower()]
            return self._original[key]

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
        except KeyError:
            raise ValueError("No matching tag for {!r} found!".format(name))

    def is_possible_value(self, tag, value, raise_error=False):
        tag = self.get_tag(tag)
        values = self._original[tag]
        match_found = value in values

        if raise_error and not match_found:
            raise ValueError("{!r} is no possible choice for tag {}. "
                             "Valid tags are: {}".format(value, tag, ', '.join(values)))

        return match_found


class CSVConnectorHosts:
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
