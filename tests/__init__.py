import os
import sys
from unittest.mock import Mock

test_dir = os.path.dirname(__file__)
module_dir = os.path.join(test_dir, '..', 'lib', 'python')

sys.path.append(module_dir)

# Make sure the required CheckMK modules are available for importing
modules_to_mock = {
	'cmk.cee.dcd.connectors.utils',
	'cmk.cee.dcd.plugins.connectors.connectors_api.v0',
	'cmk.utils.i18n',
}
for module in modules_to_mock:
	sys.modules[module] = Mock()
