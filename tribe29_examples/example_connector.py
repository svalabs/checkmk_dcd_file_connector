#!/usr/bin/env python3
"""Minimal Dynamic Configuration Connector plugin

The plugin is registered with the local DCD. Once configured as connection in the DCD
it will be executed every 60 seconds (hard coded, see below) and write some log entries
to the var/log/dcd.log. That's it.
"""

from typing import Dict

from cmk.cee.dcd.plugins.connectors.connectors_api.v0 import (  # noqa: F401 # pylint: disable=unused-import
    connector_config_registry, ConnectorConfig, connector_registry, Connector, Phase1Result,
    NullObject,
)


# TODO: To register the plugin with the DCD you have to uncomment the line below
#@connector_config_registry.register
class MyConnectorConfig(ConnectorConfig):
    """Loading the persisted connection config"""
    @classmethod
    def name(cls):
        # type: () -> str
        return "my-connector"

    def _connector_attributes_to_config(self):
        # type: () -> Dict
        cfg = {
            "interval": self.interval,
        }  # type: Dict
        return cfg

    def _connector_attributes_from_config(self, connector_cfg):
        # type: (Dict) -> None
        self.interval = connector_cfg["interval"]  # type: int


# TODO: To register the plugin with the DCD you have to uncomment the line below
#@connector_registry.register
class MyConnector(Connector):
    """Implementation of the connector"""
    @classmethod
    def name(cls):
        # type: () -> str
        return "my-connector"

    def _execution_interval(self):
        # type: () -> int
        """Number of seconds to sleep after each phase execution"""
        return self._connection_config.interval

    def _execute_phase1(self):
        # type: () -> Phase1Result
        """Execute the first synchronization phase"""
        self._logger.info("Execute phase 1")
        return Phase1Result(NullObject(), self._status)

    def _execute_phase2(self, phase1_result):
        # type: (Phase1Result) -> None
        """Execute the second synchronization phase

        It is executed based on the information provided by the first phase. This
        phase is intended to talk to the local WATO Web API for updating the
        Check_MK configuration based on the information provided by the connection.
        """
        self._logger.info("Execute phase 2")
