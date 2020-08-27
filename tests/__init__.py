import os
import sys
from unittest.mock import Mock

test_dir = os.path.dirname(__file__)
module_dir = os.path.join(test_dir, '..', 'lib', 'python')

sys.path.append(module_dir)

# Make sure the required CheckMK modules are available for importing
modules_to_mock = {
	'cmk',
	'cmk.cee.dcd.config',
	'cmk.cee.dcd.connectors',
	'cmk.cee.dcd.connectors.utils',
	'cmk.gui',
	'cmk.gui.cee',
	'cmk.gui.cee.plugins.wato.dcd',
	'cmk.gui.exceptions',
	'cmk.gui.plugins',
	'cmk.gui.plugins.wato',
	'cmk.gui.valuespec',
	'cmk.utils',
	'cmk.utils.i18n',
}
for module in modules_to_mock:
	sys.modules[module] = Mock()
