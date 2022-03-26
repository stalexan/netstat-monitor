"""This file contains the GenericFilter class."""

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

# Standard library imports
import configparser
import re
from typing import ClassVar, Dict, Optional, Pattern, TextIO, Tuple

# Third-party imports
import netaddr # pylint: disable=import-error

# Local imports
from .shared import MonitorException, OptionType
from .sockets import SocketInfo

# pylint: disable=too-few-public-methods
class FilterParam:
    """Base class for filter parameters"""

    # pylint: disable=no-self-use
    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out."""
        raise MonitorException("ERROR: Not implemented")

class PidFilterParam(FilterParam):
    """Filter parameter to filter on pid

    Attributes
    ----------
    pid : str
        The pid to filter out.

    """
    pid: str

    def __init__(self, pid: str):
        self.pid = pid

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on pid."""
        socket_pid: Optional[str] = socket_info.lookup_pid()
        return socket_pid == self.pid

class ExeFilterParam(FilterParam):
    """Filter parameter to filter on exe

    Attributes
    ----------
    exe : str
        The exe to filter out.

    """
    exe: str

    def __init__(self, exe: str):
        self.exe = exe

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on exe."""
        socket_exe: Optional[str] = socket_info.lookup_exe()
        return socket_exe == self.exe

class CmdLineFilterParam(FilterParam):
    """Filter parameter to filter on exe

    Attributes
    ----------
    cmdline : str
        The command line to filter out.
    is_re : bool
        Whether cmdline is a regular expression.
    cmdline_re : Pattern[str]
        Regular expression compiled from cmdline.

    """
    cmdline: str
    is_re: bool
    cmdline_re: Pattern[str]

    def __init__(self, cmdline: str, is_re: bool):
        self.cmdline = cmdline
        self.is_re = is_re

        # Compile regular expression
        if is_re and not cmdline is None:
            self.cmdline_re = re.compile(cmdline)

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on cmdline."""
        socket_cmdline: Optional[str] = socket_info.lookup_cmdline()
        if not socket_cmdline is None:
            if self.cmdline_re is None:
                return socket_cmdline == self.cmdline
            return not self.cmdline_re.match(socket_cmdline) is None
        return False

class UserFilterParam(FilterParam):
    """Filter parameter to filter on user

    Attributes
    ----------
    user : str
        The user to filter out.

    """
    user: str

    def __init__(self, user: str):
        self.user = user

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on user."""
        socket_user: str = socket_info.lookup_user()
        return socket_user == self.user

class LocalHostsFilterParam(FilterParam):
    """Filter parameter to filter on local hosts

    Attributes
    ----------
    local_hosts : list[str]
        Local hostnames to filter out.

    """
    local_hosts: list[str]

    def __init__(self, local_hosts: list[str]):
        self.local_hosts = local_hosts

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on local_host."""
        host_name: str = socket_info.local_host
        for host in self.local_hosts:
            if host_name.endswith(host):
                return True
        return False

class LocalPortsFilterParam(FilterParam):
    """Filter parameter to filter on local ports

    Attributes
    ----------
    local_ports: list[str]
        Local ports to filter out.

    """
    local_ports: list[str]

    def __init__(self, local_ports: list[str]):
        self.local_ports = local_ports

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on local_port."""
        return socket_info.local_port in self.local_ports

class RemoteHostsFilterParam(FilterParam):
    """Filter parameter to filter on remote hosts

    Attributes
    ----------
    reporte_hosts : list[str]
        Remote hostnames to filter out.

    """
    remote_hosts: list[str]

    def __init__(self, remote_hosts: list[str]):
        self.remote_hosts = remote_hosts

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on remote_host_name."""
        host_name: Optional[str] = socket_info.lookup_remote_host_name()
        if not host_name is None:
            for host in self.remote_hosts:
                if host_name.endswith(host):
                    return True
        return False

class RemoteIpsFilterParam(FilterParam):
    """Filter parameter to filter on remote IP addresses.

    Attributes
    ----------
    remote_ips: list[str]
        Remote IP addresses to filter out.

    """
    remote_ips: list[str]

    def __init__(self, remote_ips: list[str]):
        # Parse CIDR address ranges
        if not remote_ips is None:
            self.remote_ips = [netaddr.IPNetwork(cidr_str) for cidr_str in remote_ips]

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on remote_host IP address."""
        return self._ip_in_a_network(socket_info.remote_host, self.remote_ips)

    @staticmethod
    def _ip_in_a_network(ip_str: str, networks: list[str]) -> bool:
        """Return True if ip is in at least one network."""
        in_range: bool = False
        ip_addr: netaddr.IPAddress = netaddr.IPAddress(ip_str)
        network: str
        for network in networks:
            if ip_addr in network:
                in_range = True
                break
        return in_range

class RemotePortsFilterParam(FilterParam):
    """Filter parameter to filter on remote ports

    Attributes
    ----------
    remote_ports: list[str]
        Remote ports to filter out.

    """
    remote_ports: list[str]

    def __init__(self, remote_ports: list[str]):
        self.remote_ports = remote_ports

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on remote port."""
        return socket_info.remote_port in self.remote_ports

class StatesFilterParam(FilterParam):
    """Filter parameter to filter on states

    Attributes
    ----------
    states: list[str]
        Connection states to filter out.

    """
    states: list[str]

    def __init__(self, states: list[str]):
        self.states = states

    def filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on state."""
        return socket_info.state in self.states

class GenericFilter():
    """Filter to limit what connections are displayed to a user.

    A filter takes effect if all filter attributes match. Attributes are AND'ed
    together and values within any attribute lists are OR'ed together. For
    example if a filter has these settings:

        exe: ``/usr/lib/firefox/firefox``
        user: alice
        remote_ports: 53, 80, 443, 8080

    Connections with exe set to ``/usr/lib/firefox/firefox`` AND user set to
    alice AND a remote port of either 53 OR 80 OR 443 OR 8080 are filtered out.

    Attributes
    ----------
    name : str
        Filter name.
    params : list[FilterParam]
        Filter parameters.

    """

    name: str
    params: list[FilterParam]

    valid_parameter_names: ClassVar[list[str]] = ["pid", "exe", "cmdline", "cmdline_is_re", "user",
        "local_hosts", "local_ports", "remote_hosts", "remote_ips", "remote_ports", "states"]

    # pylint: disable=too-many-arguments
    def __init__(self, name: str, pid: Optional[OptionType] = None,
        exe: Optional[OptionType] = None, cmdline: Optional[OptionType] = None,
        cmdline_is_re: Optional[OptionType] = None, user: Optional[OptionType] = None,
        local_hosts: Optional[OptionType] = None, local_ports: Optional[OptionType] = None,
        remote_hosts: Optional[OptionType] = None, remote_ips: Optional[OptionType] = None,
        remote_ports: Optional[OptionType] = None, states: Optional[OptionType] = None) -> None:
        """Create the specified filter."""

        self.name = name

        # Create filter parameters
        self.params = []
        if not pid is None:
            self.params.append(PidFilterParam(str(pid)))
        if not exe is None:
            self.params.append(ExeFilterParam(str(exe)))
        if not cmdline is None:
            self.params.append(CmdLineFilterParam(str(cmdline), bool(cmdline_is_re)))
        if not user is None:
            self.params.append(UserFilterParam(str(user)))
        if not local_hosts is None:
            self.params.append(LocalHostsFilterParam(
                GenericFilter._parse_list_string(local_hosts)))
        if not local_ports is None:
            self.params.append(LocalPortsFilterParam(
                GenericFilter._parse_list_string(local_ports)))
        if not remote_hosts is None:
            self.params.append(RemoteHostsFilterParam(
                GenericFilter._parse_list_string(remote_hosts)))
        if not remote_ips is None:
            self.params.append(RemoteIpsFilterParam(
                GenericFilter._parse_list_string(remote_ips)))
        if not remote_ports is None:
            self.params.append(RemotePortsFilterParam(
                GenericFilter._parse_list_string(remote_ports)))
        if not states is None:
            self.params.append(StatesFilterParam(
                GenericFilter._parse_list_string(states)))

    @staticmethod
    def _parse_list_string(string_option: Optional[OptionType]) -> list[str]:
        """Cast an option known to be a list of strings from OptionType to list[str]"""
        result: list[str] = []
        if not string_option is None:
            string = str(string_option).strip()
            if len(string) > 0:
                result = [entry.strip() for entry in string.split(',')]
        return result

    def _add_str_part(self, parts: list[str], name: str) -> None:
        """Add to the list of strings used to generate a debug string that describes this filter.

        This will add to the "parts" list if the attribute "name" is set.
        Otherwise, "parts" remains unchanged.

        Parameters
        ----------
        parts : list[str]
            The list to add to.
        name : str
            The name of the attribute to add. The attribute's value will be looked up and a
            string the attribute name and value value will be added to parts.
        """
        attr: Optional[str] = getattr(self, name)
        if not attr is None:
            if len(parts) > 0:
                parts.append(", ")
            parts.append(f"{name}: {attr}")


    def is_socket_filtered_out(self, socket_info: SocketInfo) -> bool:
        """Determine if this filter should filter out the given socket.

        Filter parameters are AND'ed together. Each filter parameter that is set
        is checked.  The first that isn't a match causes the filter not to
        match, checks stop, and False is returned. If all match, True is
        returned, and the socket is filtered out.

        Attributes
        ----------
        socket_info : SocketInfo
            The socket to check.

        Returns
        -------
        bool
            Whether the socket should be filtered out and not displayed because
            of this filter.

        """
        for param in self.params:
            if not param.filters_out(socket_info):
                return False
        return True

    @staticmethod
    def load_filters(filter_files: Optional[list[str]]) -> "list[GenericFilter]":
        """Create filters from specified files.

        Parameters
        ----------
        filter_files : list[str], optional
            Paths to files that define filters.

        Returns
        -------
        list[GenericFilter]:
            The newly created filters.

        Raises
        ------
        MonitorException:
            If any of the filter files cannot be opened, or if there's an error
            parsing the filters.

        """
        filters: list[GenericFilter] = []
        if filter_files is None:
            return filters

        file_name: str
        for file_name in filter_files:
            try:
                filter_file: TextIO
                with open(file_name, encoding="utf-8") as filter_file:
                    parser = configparser.ConfigParser()
                    parser.read_file(filter_file)
                    section: str
                    for section in parser.sections():
                        try:
                            # Reader parameters for this filter
                            filter_params = GenericFilter._read_filter_parameters(
                                parser, section, file_name)

                            # Create filter
                            generic_filter = GenericFilter(section, **filter_params)
                            filters.append(generic_filter)
                            # LOG
                            #print("filter: {0}".format(generic_filter))
                            #sys.stdout.flush()
                        except configparser.Error as ex:
                            message = f"ERROR: Parsing error creating {section} filter from " \
                                "file {file_name}: {str(ex)}."
                            raise MonitorException(message) from ex
                        except netaddr.core.AddrFormatError as ex:
                            message = f"ERROR: Parsing error creating {section} filter from " \
                                "file {file_name}: {str(ex)}."
                            raise MonitorException(message) from ex
            except IOError as ex:
                raise MonitorException(
                    f"ERROR: Unable to open file {file_name}: ({str(ex)})") from ex
            except configparser.Error as ex:
                raise MonitorException(
                    f"ERROR: Parsing error creating filters from file {file_name}: " \
                    f"{str(ex)}.") from ex

        return filters

    @staticmethod
    def _read_filter_parameters(parser: configparser.ConfigParser, section: str,
        file_name: str) -> Dict[str, OptionType]:
        """Read the parameters for a given filter

        Filter definitions are stored in config files. Each config file section
        defines a filter. For example, the section for a filter named "firefox"
        might be:

            [firefox]
            exe: /usr/lib/firefox/firefox
            user: alice
            remote_ports: 53, 80, 443, 8080

        Attributes
        ----------
        parser : configparser.ConfigParser
            The configuration file parser that was used to load the current filter file.
        section : str
            The name of the configuration section to read.
        file_name: str
            The name of the file that's being read.

        Returns
        -------
        Dict[str, OptionType]:
            The filter parameters, stored as a dictionary with filter parameter
            name as the index and filter parameter value as the value.

        """
        # Reader parameters for this filter
        filter_params: Dict[str, OptionType] = {}
        items: list[Tuple[str, str]] = parser.items(section)
        pair: Tuple[str, str]
        for pair in items:
            # Check parameter name
            param_name: str = pair[0].strip()
            if not param_name in GenericFilter.valid_parameter_names:
                raise MonitorException(
                    f"ERROR: Unexpected filter parameter {param_name} for "
                    f"filter {section} in {file_name}.")

            # Determine parameter value
            param_value: OptionType = False
            if param_name == "cmdline_is_re":
                try:
                    param_value = parser[section].getboolean("cmdline_is_re")
                except ValueError as value_error:
                    raise MonitorException(
                        "ERROR: Expecting true or false for cmdline_is_re for" +
                        f" {section} in {file_name}") from value_error
            else:
                param_value = pair[1].strip()

            # Record parameter
            filter_params[param_name] = param_value
        return filter_params
