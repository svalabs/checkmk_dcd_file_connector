import os
import sys
from unittest.mock import Mock

test_dir = os.path.dirname(__file__)
module_dir = os.path.join(test_dir, '..', 'lib', 'check_mk', 'cee', 'dcd', 'plugins', 'connectors')

sys.path.append(module_dir)

# Make sure the required CheckMK modules are available for importing
modules_to_mock = {
	'cmk.cee.dcd.web_api',
	'cmk.cee.dcd.plugins.connectors.connectors_api.v1',
	'cmk.utils.i18n',
}
for module in modules_to_mock:
	sys.modules[module] = Mock()
