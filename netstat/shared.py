"""Shared code for the netstat module."""

#!/usr/bin/env python3
#
# Copyright 2022 Sean Alexandre
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

from typing import Union

OptionType = Union[bool, str]

class MonitorException(Exception):
    """Exception type for netstat-monitor.

    Attributes
    ----------
    message : str
        Exception message.
    return_code : int
        Return code to exit with.

    """
    message: str
    return_code: int

    def __init__(self, message: str, return_code: int = -1) -> None:
        super().__init__()
        self.message = message
        self.return_code = return_code

    def __str__(self) -> str:
        return self.message
