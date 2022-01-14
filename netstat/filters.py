"""TODO: docstring"""

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
import re

# Third-party imports
import netaddr # pylint: disable=import-error

# pylint: disable=too-many-instance-attributes
class GenericFilter():
    """GenericFilter is a SocketFilter that filters on properties of SocketInfo."""
    valid_parameter_names = ["pid", "exe", "cmdline", "cmdline_is_re", "user",
        "local_hosts", "local_ports", "remote_hosts", "remote_ips", "remote_ports", "states"]

    # pylint: disable=too-many-arguments
    def __init__(self, name, pid=None, exe=None, cmdline=None, cmdline_is_re=None,
        user=None, local_hosts=None, local_ports=None, remote_hosts=None,
        remote_ips=None, remote_ports=None, states=None):
        """Create a GenericFilter that filters out SocketInfos that match all
        the specified properties.

        All arguments are optional. Arguments that aren't set default to None, for "don't care."
        Arguments that are set cause a SocketInfo to be filtered out if all attributes of the
        SocketInfo match the attributes of the arguments set.

        Keyword arguments:

        pid -- If set, pid that a SocketInfo must match to be filtered out.
        exe -- If set, exe that a SocketInfo must match to be filtered out.
        cmdline -- If set, cmdline that a SocketInfo must match to be filtered out.
        cmdline_is_re -- If true, cmdline is treated as a regular expression.
        user -- If set, user that a SocketInfo must match to be filtered out.
        local_hosts -- If set, an array of IP addresses to filter on. A SocketInfo is filtered
          out if its local_host matches any of the addresses.
        local_ports -- If set, an array of ports to filter on. A SocketInfo is filtered
          out if its local_port matches any of the ports.
        remote_hosts -- If set, an array of domain names to filter on. A SocketInfo is filtered
          out if its remote_host_name matches any of the addresses.
        remote_ips -- If set, an array of IP address ranges to filter on, in CIDR notation. A
          SocketInfo is filtered out if its remote_host falls within any of the ranges.
        remote_ports -- If set, an array of ports to filter on. A SocketInfo is filtered
          out if its local_port matches any of the ports.
        states -- If set, an array of states to filter on. A SocketInfo is filtered
          out if its state matches any of the states.
        """

        self.name = name
        self.pid = pid
        self.exe = exe
        self.cmdline = cmdline
        self.cmdline_is_re = cmdline_is_re
        self.user = user
        self.local_hosts = GenericFilter._parse_list_string(local_hosts)
        self.local_ports = GenericFilter._parse_list_string(local_ports)
        self.remote_hosts = GenericFilter._parse_list_string(remote_hosts)
        self.remote_ips = GenericFilter._parse_list_string(remote_ips)
        self.remote_ports = GenericFilter._parse_list_string(remote_ports)
        self.states = GenericFilter._parse_list_string(states)

        # Create regular expression for cmdline
        self.cmdline_re = None
        if self.cmdline_is_re:
            self.cmdline_re = re.compile(self.cmdline)

        # Parse CIDR address ranges
        if not self.remote_ips is None:
            self.remote_ips = [netaddr.IPNetwork(cidr_str) for cidr_str in self.remote_ips]

    @staticmethod
    def _parse_list_string(string):
        result = None
        if not string is None:
            string = string.strip()
            if len(string) > 0:
                result = [entry.strip() for entry in string.split(',')]
        return result

    def __str__(self):
        parts = []
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

    def _add_str_part(self, parts, name):
        attr = getattr(self, name)
        if not attr is None:
            if len(parts) > 0:
                parts.append(", ")
            parts.append("{0}: {1}".format(name, attr))

    def _pid_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on pid."""
        filter_out = True
        if not self.pid is None:
            socket_pid = socket_info.lookup_pid()
            filter_out = socket_pid == self.pid
        return filter_out

    def _exe_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on exe."""
        filter_out = True
        if not self.exe is None:
            socket_exe = socket_info.lookup_exe()
            filter_out = socket_exe == self.exe
        return filter_out

    def _cmdline_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on cmdline."""
        filter_out = True
        if not self.cmdline is None:
            socket_cmdline = socket_info.lookup_cmdline()
            if self.cmdline_re is None:
                filter_out = socket_cmdline == self.cmdline
            else:
                filter_out = not self.cmdline_re.match(socket_cmdline) is None
        return filter_out

    def _user_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on user."""
        filter_out = True
        if not self.user is None:
            socket_user = socket_info.lookup_user()
            filter_out = socket_user == self.user
        return filter_out

    def _local_host_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on local_host."""
        filter_out = True
        if not self.local_hosts is None:
            filter_out = False
            host_name = socket_info.local_host
            for host in self.local_hosts:
                if host_name.endswith(host):
                    filter_out = True
                    break
        return filter_out

    def _local_port_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on local_port."""
        filter_out = True
        if not self.local_ports is None:
            filter_out = socket_info.local_port in self.local_ports
        return filter_out

    def _remote_host_name_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on remote_host_name."""
        filter_out = True
        if not self.remote_hosts is None:
            filter_out = False
            host_name = socket_info.lookup_remote_host_name()
            for host in self.remote_hosts:
                if host_name.endswith(host):
                    filter_out = True
                    break
        return filter_out

    @staticmethod
    def _ip_in_a_network(ip_str, networks):
        """Return True if ip is in at least one network."""
        in_range = False
        ip_addr = netaddr.IPAddress(ip_str)
        for network in networks:
            if ip_addr in network:
                in_range = True
                break
        return in_range

    def _remote_ip_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on remote_host IP address."""
        filter_out = True
        if not self.remote_ips is None:
            filter_out = self._ip_in_a_network(socket_info.remote_host, self.remote_ips)
        return filter_out

    def _remote_port_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on remote_port."""
        filter_out = True
        if not self.remote_ports is None:
            filter_out = socket_info.remote_port in self.remote_ports
        return filter_out

    def _state_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on state."""
        filter_out = True
        if not self.states is None:
            filter_out = socket_info.state in self.states
        return filter_out

    def filter_out(self, socket_info):
        """Return True if socket_info should be filtered out."""

        # Consider each parameter for this filter. All parameters have to match
        # a socket for the socket to be filtered out. The below "filters_out()"
        # calls stop as soon as a particular filter parameter doesn't match
        # (i.e. the filter can't apply).
        #
        # Methods for all parameters are called. If a given parameter is not
        # set, the "filters_out()" method for that parameter will always return
        # true.  This can be thought of as the parameter being set for the
        # filter, but set in such a way that a socket always matches.
        filter_out = (
            self._pid_filters_out(socket_info) and
            self._exe_filters_out(socket_info) and
            self._cmdline_filters_out(socket_info) and
            self._user_filters_out(socket_info) and
            self._local_host_filters_out(socket_info) and
            self._local_port_filters_out(socket_info) and
            self._remote_host_name_filters_out(socket_info) and
            self._remote_ip_filters_out(socket_info) and
            self._remote_port_filters_out(socket_info) and
            self._state_filters_out(socket_info))

        return filter_out
