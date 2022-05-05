#! /usr/bin/env python
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# Utility to render our template and fill with the desired values.
#
# Copyright (C) 2021-2022 SVA System Vertrieb Alexander GmbH
#                         Niko Wenselowski <niko.wenselowski@sva.de>

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
from markdown import markdown

TEMPLATE_FILE = "info_template"
VERSION = os.environ["VERSION"]

if not VERSION:
    raise RuntimeError("Missing VERSION env var!")


with open("README.md") as readme_file:
    readme = readme_file.read()

with open(TEMPLATE_FILE) as f:
    template = f.read()


def render_readme():
    rendered_readme = markdown(readme)

    for line in rendered_readme.split("\n"):
        line = line.replace("'", '"')
        yield f"'{line}\\n'"


rendered_info = template.replace("'${DESCRIPTION}'", "\n".join(render_readme()))
rendered_info = rendered_info.replace("${VERSION}", VERSION)

with open("info", "w") as output_file:
    output_file.write(rendered_info)
