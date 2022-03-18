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
from typing import ClassVar, Dict, Optional, TextIO, Tuple

# Third-party imports
import netaddr # pylint: disable=import-error

# Local imports
from .shared import MonitorException, OptionType
from .sockets import SocketInfo

# pylint: disable=too-many-instance-attributes
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
    pid : str, optional
        The pid to filter out.
    exe : str, optional
        The exe to filter out.
    cmdline : str, optional
        The command line to filter out.
    cmdline_is_re: bool
        Whether cmdline is a regular expression.
    user : str, optional
        The user to filter out.
    local_hosts: list[str], optional
        Local hostnames to filter out.
    local_ports: list[str], optional
        Local ports to filter out.
    remote_hosts: list[str], optional
        Remote hostnames to filter out.
    remote_ips: list[str], optional
        Remote IP addresses to filter out.
    remote_ports: list[str], optional
        Remote ports to filter out.
    states: list[str], optional
        Connection states to filter out.

    """

    name: str
    pid: Optional[str]
    exe: Optional[str]
    cmdline: Optional[str]
    cmdline_is_re: bool
    user: Optional[str]
    local_hosts: Optional[list[str]]
    local_ports: Optional[list[str]]
    remote_hosts: Optional[list[str]]
    remote_ips: Optional[list[str]]
    remote_ports: Optional[list[str]]
    states: Optional[list[str]]

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

        # Cast OptionTypes to their expected types.
        self.name = name
        self.pid = GenericFilter._cast_option_value_to_str(pid)
        self.exe = GenericFilter._cast_option_value_to_str(exe)
        self.cmdline = GenericFilter._cast_option_value_to_str(cmdline)
        self.cmdline_is_re = GenericFilter._cast_option_value_to_bool(cmdline_is_re)
        self.user = GenericFilter._cast_option_value_to_str(user)
        self.local_hosts = GenericFilter._parse_list_string(local_hosts)
        self.local_ports = GenericFilter._parse_list_string(local_ports)
        self.remote_hosts = GenericFilter._parse_list_string(remote_hosts)
        self.remote_ips = GenericFilter._parse_list_string(remote_ips)
        self.remote_ports = GenericFilter._parse_list_string(remote_ports)
        self.states = GenericFilter._parse_list_string(states)

        # Create regular expression for cmdline
        self.cmdline_re = None
        if self.cmdline_is_re and not self.cmdline is None:
            self.cmdline_re = re.compile(self.cmdline)

        # Parse CIDR address ranges
        if not self.remote_ips is None:
            self.remote_ips = [netaddr.IPNetwork(cidr_str) for cidr_str in self.remote_ips]

    @staticmethod
    def _cast_option_value_to_str(option_value: Optional[OptionType]) -> Optional[str]:
        """Cast an option know to be a string from OptionType to str"""
        if option_value is None:
            return None
        return str(option_value)

    @staticmethod
    def _cast_option_value_to_bool(option_value: Optional[OptionType]) -> bool:
        """Cast an option know to be a bool from OptionType to bool"""
        if option_value is None:
            return False
        return bool(option_value)

    @staticmethod
    def _parse_list_string(string_option: Optional[OptionType]) -> Optional[list[str]]:
        """Cast an option known to be a list of strings from OptionType to list[str]"""
        result: Optional[list[str]] = None
        if not string_option is None:
            string = str(string_option).strip()
            if len(string) > 0:
                result = [entry.strip() for entry in string.split(',')]
        return result

    def __str__(self) -> str:
        """Return a debug string that describes this filter."""
        parts: list[str] = []
        self._add_str_part(parts, 'name')
        self._add_str_part(parts, 'pid')
        self._add_str_part(parts, 'exe')
        self._add_str_part(parts, 'cmdline')
        self._add_str_part(parts, 'cmdline_is_re')
        self._add_str_part(parts, 'user')
        self._add_str_part(parts, 'local_hosts')
        self._add_str_part(parts, 'local_ports')
        self._add_str_part(parts, 'remote_hosts')
        self._add_str_part(parts, 'remote_ips')
        self._add_str_part(parts, 'remote_ports')
        self._add_str_part(parts, 'states')
        string = ''.join(parts)
        return string

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

    def _pid_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on pid."""
        assert not self.pid is None
        socket_pid: Optional[str] = socket_info.lookup_pid()
        return socket_pid == self.pid

    def _exe_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on exe."""
        assert not self.exe is None
        socket_exe: Optional[str] = socket_info.lookup_exe()
        return socket_exe == self.exe

    def _cmdline_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on cmdline."""
        assert not self.cmdline is None
        socket_cmdline: Optional[str] = socket_info.lookup_cmdline()
        if not socket_cmdline is None:
            if self.cmdline_re is None:
                return socket_cmdline == self.cmdline
            else:
                return not self.cmdline_re.match(socket_cmdline) is None
        return False

    def _user_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on user."""
        assert not self.user is None
        socket_user: str = socket_info.lookup_user()
        return socket_user == self.user

    def _local_host_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on local_host."""
        assert not self.local_hosts is None
        host_name: str = socket_info.local_host
        for host in self.local_hosts:
            if host_name.endswith(host):
                return True
        return False
  
    def _local_port_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on local_port."""
        assert not self.local_ports is None
        return socket_info.local_port in self.local_ports

    def _remote_host_name_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on remote_host_name."""
        assert not self.remote_hosts is None
        host_name: Optional[str] = socket_info.lookup_remote_host_name()
        if not host_name is None:
            for host in self.remote_hosts:
                if host_name.endswith(host):
                    return True
        return False

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

    def _remote_ip_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on remote_host IP address."""
        assert not self.remote_ips is None
        return self._ip_in_a_network(socket_info.remote_host, self.remote_ips)

    def _remote_port_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on remote_port."""
        assert not self.remote_ports is None
        return socket_info.remote_port in self.remote_ports

    def _state_filters_out(self, socket_info: SocketInfo) -> bool:
        """Return True if socket_info should be filtered out based on state."""
        assert not self.states is None
        return socket_info.state in self.states

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

        Notes
        -----
        A future improvement on this would be to create a FilterParam class that
        represents a filter parameter, and then subclasses of FilterParam for
        each of the possible filter parameter types. A GenericFilter would then
        have a list of FilterParams, one for each of the filter parameters that
        has been set on the filter. The code below would loop over this list of
        parameters instead of checking each potential parameter.

        For now, though, this is probably good as is. The code is less generic
        but probably clearer. Definitely look at doing this if the number of
        possible filter parameters grows.

        Also, a loop would probably be more efficient than checking each
        parameter. Performance profiling could say for sure.
        
        """
        # Check pid.
        if not self.pid is None:
            if not self._pid_filters_out(socket_info):
                return False

        # Check exe.
        if not self.exe is None:
            if not self._exe_filters_out(socket_info):
                return False

        # Check cmdline.
        if not self.cmdline is None:
            if not self._cmdline_filters_out(socket_info):
                return False

        # Check user.
        if not self.user is None:
            if not self._user_filters_out(socket_info):
                return False

        # Check local host.
        if not self.local_hosts is None:
            if not self._local_host_filters_out(socket_info):
                return False

        # Check local port.
        if not self.local_ports is None:
            if not self._local_port_filters_out(socket_info):
                return False

        # Checkout remote host.
        if not self.remote_hosts is None:
            if not self._remote_host_name_filters_out(socket_info):
                return False

        # Check remote IP.
        if not self.remote_ips is None:
            if not self._remote_ip_filters_out(socket_info):
                return False

        # Check remote port.
        if not self.remote_ports is None:
            if not self._remote_port_filters_out(socket_info):
                return False

        # Check state.
        if not self.states is None:
            if not self._state_filters_out(socket_info):
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
