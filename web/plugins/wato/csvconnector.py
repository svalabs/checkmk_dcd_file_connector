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

import os.path

from cmk.gui.cee.plugins.wato.dcd import (  # noqa: F401 # pylint: disable=unused-import
    connector_parameters_registry, ConnectorParameters,
)

from cmk.gui.exceptions import MKUserError

from cmk.gui.i18n import _

from cmk.gui.plugins.wato import FullPathFolderChoice

from cmk.gui.valuespec import (
    Age,
    Checkbox,
    Dictionary,
    Filename,
    Integer,
    ListOfStrings,
    RegExpUnicode,
)


@connector_parameters_registry.register
class CSVConnectorParameters(ConnectorParameters):

    @classmethod
    def name(cls):
        # type: () -> str
        return "csvconnector"

    def title(self):
        # type: () -> str
        return _("CSV import")

    def description(self):
        # type: () -> str
        return _("Connector for importing data from a CSV file.")

    def valuespec(self):
        return Dictionary(
            elements=[
                ("interval", Age(
                    title=_("Sync interval"),
                    minvalue=1,
                    default_value=300,
                )),
                ("path", Filename(
                    title=_("Path of the CSV file to import."),
                    help=_("This is the absolute path to the CSV file. "
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
                ("chunk_size", Integer(
                    default_value=0,
                    minvalue=0,
                    title=_("Chunk size"),
                    help=_(
                        "Split processing of hosts into smaller parts of the "
                        "given size. "
                        "After each part is processed an activation of the "
                        "changes is triggered. "
                        "This setting can reduce performance impacts "
                        "when working with large change sets. "
                        "Setting it to 0 disables splitting."),
                )),
                ("use_service_discovery", Checkbox(
                    default_value=True,
                    title=_("Use service discovery"),
                    help=_(
                        "Controls if service discovery is triggered for new hosts."
                    ),
                )),
            ],
            optional_keys=["host_filters", "host_overtake_filters", "chunk_size"],
        )

    @staticmethod
    def validate_csv(filename, varprefix):
        if not os.path.isfile(filename):
            raise MKUserError(varprefix, "No file %r" % filename)
