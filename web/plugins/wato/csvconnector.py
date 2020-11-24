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

import os

from cmk.gui.cee.plugins.wato.dcd import (  # noqa: F401 # pylint: disable=unused-import
    connector_parameters_registry, ConnectorParameters,
)

from cmk.gui.exceptions import MKUserError

from cmk.gui.i18n import _

from cmk.gui.plugins.wato import FullPathFolderChoice

from cmk.gui.valuespec import (
    Age,
    Filename,
    Dictionary,
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
