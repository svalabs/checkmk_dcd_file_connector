import os
import sys

test_dir = os.path.dirname(__file__)
module_dir = os.path.join(test_dir, '..', 'lib', 'python')

sys.path.append(module_dir)