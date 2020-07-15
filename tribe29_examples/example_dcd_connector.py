#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: Check_MK Enterprise License
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.gui.i18n import _
from cmk.gui.valuespec import Dictionary
from cmk.gui.valuespec import Age

from cmk.gui.cee.plugins.wato.dcd import (  # noqa: F401 # pylint: disable=unused-import
    connector_parameters_registry, ConnectorParameters,
)


# TODO: To register the plugin with the GUI you have to uncomment the line below
#@connector_parameters_registry.register
class MyConnectorParameters(ConnectorParameters):
    @classmethod
    def name(cls):
        # type: () -> str
        return "my-connector"

    def title(self):
        # type: () -> str
        return _("My connector")

    def description(self):
        # type: () -> str
        return _("This connector can be used to automatically create hosts " "based on my data.")

    def valuespec(self):
        return Dictionary(
            elements=[
                ("interval",
                 Age(
                     title=_("Sync interval"),
                     help=_("The interval the connection will be executed to poll the data source "
                            "and update the configuration."),
                     minvalue=1,
                     default_value=60,
                 )),
            ],
            optional_keys=[],
        )
