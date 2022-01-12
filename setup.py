#!/usr/bin/env python3
#
# Copyright 2013 Sean Alexandre
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from distutils.core import setup
from netstat import __version__

setup(
    name='netstat-monitor', 
    version=__version__,
    py_modules=['netstat'],
    scripts=['netstat-monitor'],
    data_files=[('', ['sample-filters'])],
    url='https://github.com/stalexan/netstat-monitor',
    author='Sean Alexandre',
    author_email='sean@alexan.org',
    license='AGPL',
    description='CLI based network connection monitoring tool',
    keywords="cli monitoring",
    long_description=
        "netstat-monitor is a command line tool for monitoring network connections.\n" +
        'Output is similar to the output from the command "netstat --inet -alp". One difference\n' + 
        "is netstat-monitor can be left running and will display new connections as they are\n" +
        "made. Also, filters can be applied to limit what's displayed to only unexpected or\n" +
        "interesting connections.",
    platforms=['Linux'])

