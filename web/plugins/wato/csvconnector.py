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
    Alternative,
    Checkbox,
    Dictionary,
    Filename,
    FixedValue,
    Integer,
    ListOfStrings,
    RegExpUnicode,
    TextInput,
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
        csv_value = FixedValue(value="csv", title="CSV", totext="Comma-separated values.")
        bvq_value = FixedValue(value="bvq", title="BVQ", totext="Export from a BVQ system.")
        json_value = FixedValue(value="json", title="JSON", totext="File with JSON format.")

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
                ("file_format", Alternative(
                    title=_("Data Format"),
                    elements=[csv_value, json_value, bvq_value],
                    default_value=csv_value,
                    help=_(
                        "Select the data format for the file."
                    ),
                )),
                ("label_path_template", TextInput(
                    title=_("Use labels to organize hosts"),
                    label=_("Path template"),
                    default_value="location/org",
                    help=_(
                        "Controls if the placement of a host in the "
                        "folder structure is based on the labels of "
                        "the host. "
                        "If this is activated the folder selected "
                        "under 'create hosts in' will act as a prefix "
                        "for the path. "
                        "Separate folders through a single forward "
                        "slash (/). "
                    ),
                    validate=self.validate_label_path_template,
                )),
            ],
            optional_keys=[
                "host_filters",
                "host_overtake_filters",
                "chunk_size",
                "label_path_template"
            ],
        )

    @staticmethod
    def validate_csv(filename, varprefix):
        if not os.path.isfile(filename):
            raise MKUserError(varprefix, "No file %r" % filename)

    @staticmethod
    def validate_label_path_template(template, varprefix):
        if not template.islower():
            raise MKUserError(varprefix, "Please supply only lowercase variables!")

        if template.strip() != template:
            raise MKUserError(varprefix, "Path template can not start or end with whitespace!")

        if template.startswith('/'):
            raise MKUserError(varprefix, "Do not start with a slash!")

        if template.endswith('/'):
            raise MKUserError(varprefix, "Do not specify a slash as last element!")

        if '' in [folder.strip() for folder in template.split('/')]:
            raise MKUserError(varprefix, "Do not use empty values!")

        if '' in template.split('/'):
            raise MKUserError(varprefix, "Do not use double slashes!")
