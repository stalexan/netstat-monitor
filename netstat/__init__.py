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

"""
This module displays information about network connections on a system, similar to the kind
of information that the netstat command provides.

Classes:

NetStat -- Captures a snapshot of the current network connections.
Monitor -- Collects netstat snapshots at regular intervals.
SocketInfo -- Information about a particular connection.
GenericFilter -- Filters on properties of SocketInfo.

Variables:

DEFAULT_MONITOR_INTERVAL -- How often Monitor collects netstat snapshots, in seconds.
MIN_MONITOR_INTERVAL -- Minimum value for monitor interval.
LOOKUP_REMOTE_HOST_NAME -- Whether to convert IP addresses to host names.

"""

# Standard library imports
import argparse
import binascii
import configparser
import datetime
import errno
import glob
import ipaddress
import os
import platform
import pwd
import re
import socket
import sys
import time

# Third-party imports
import netaddr # pylint: disable=import-error

# Local imports
from .filters import GenericFilter
from .shared import MonitorException
from .sockets import SocketInfo

__version__ = "v1.1.3"

DEFAULT_MONITOR_INTERVAL = 1     # Number of seconds between each netstat.
MIN_MONITOR_INTERVAL =     0.001 # Minimum value for monitor interval.

LOOKUP_REMOTE_HOST_NAME = True # Whether to convert IP addresses to host names
                               # by doing a host name lookup.

PROC_TCP = "/proc/net/tcp"
PROC_TCP6 = "/proc/net/tcp6"
PROC_UDP = "/proc/net/udp"
PROC_UDP6 = "/proc/net/udp6"

TESTED_KERNEL = "3.17.2"

def main():
    """TODO: docstring for main()"""
    # Parse command line
    parser = argparse.ArgumentParser(prog='netstat-monitor',
        description='Monitor network connections.')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-i', '--ignore-loopback', action='store_true',
        help='Ignore connections to loopback address.')
    parser.add_argument('-m', '--monitor-interval', type=float,
        default=float(DEFAULT_MONITOR_INTERVAL),
        help='How often to check for new connections, in seconds.')
    parser.add_argument('-s', '--state-changes', action='store_true',
        help='Report connection state changes.')
    parser.add_argument('filter_file', nargs='*', help='Config file that defines filters')
    args = parser.parse_args()

    # Monitor
    return_code = 0
    try:
        monitor = Monitor(args.monitor_interval, args.ignore_loopback, args.state_changes,
            args.filter_file)
        monitor.monitor()
    except KeyboardInterrupt:
        print('')
    except MonitorException as ex:
        print(str(ex))
        return_code = ex.return_code

    sys.exit(return_code)

class Monitor():
    """Monitor creates, filters, and reports SocketInfos at regular intervals."""
    _closing_states = ['FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT',
        'LAST_ACK', 'CLOSING']

    def __init__(self, interval = DEFAULT_MONITOR_INTERVAL, ignore_loopback = False,
        state_changes = False, filter_files = None):
        """Create a Monitor that monitors every interval seconds using the specified filters."

        Keyword arguments:

        interval -- Number of seconds between each time Monitor creates a Netstat. Defaults
          to DEFAULT_MONITOR_INTERVAL.
        ignore_loopback -- Ignore local connections.
        state_changes -- Report connection state changes.
        filters -- List of filters to limit what SocketInfos are displayed to the user. Any
          SocketInfos that match a filter are not displayed. Optional.

        """
        if interval < MIN_MONITOR_INTERVAL:
            raise MonitorException(
                "ERROR: Monitor interval needs to be at least {0}".format(MIN_MONITOR_INTERVAL))

        self._interval = interval
        self._ignore_loopback = ignore_loopback
        self._state_changes = state_changes
        self._seen = {}

        self._netstat_id = 0

        # Check for root permissions, so filters work and connection details can be looked up.
        if os.geteuid() != 0:
            raise MonitorException("ERROR: Root permissions needed, to lookup connection details.")

        # Check python version.
        if sys.version_info.major != 3 or sys.version_info.minor < 2:
            raise MonitorException("ERROR: Python 3.2 or greater needed.")

        # Do a basic check of kernel version, by looking comparing /proc/net
        # headers to expected headers.
        # pylint: disable=line-too-long
        tcp_header = Monitor._read_first_line(PROC_TCP)
        udp_header = Monitor._read_first_line(PROC_UDP)
        if (tcp_header != "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode" or
            udp_header != "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"):
            raise MonitorException(
                "ERROR: Unexpected /proc/net file format. This could be due to kernel version. " +
                "Current kernel: {0}. Tested kernel: {1}.".format(
                platform.uname()[2], TESTED_KERNEL))

        # Load filters
        self._load_filters(filter_files)

    @staticmethod
    def _read_first_line(path):
        with open(path, 'r') as proc_file:
            line = proc_file.readline().strip()
        return line

    def _load_filters(self, filter_files):
        self._filters = []
        if filter_files is None:
            return

        for file_name in filter_files:
            try:
                filter_file = open(file_name)
                parser = configparser.ConfigParser()
                parser.read_file(filter_file)
                for section in parser.sections():
                    try:
                        # Reader parameters for this filter
                        filter_params = Monitor._read_filter_parameters(parser, section, file_name)

                        # Create filter
                        generic_filter = GenericFilter(section, **filter_params)
                        self._filters.append(generic_filter)
                        # LOG
                        #print("filter: {0}".format(generic_filter))
                        #sys.stdout.flush()
                    except configparser.Error as ex:
                        message = "ERROR: Parsing error creating {0} filter from "\
                            "file {1}: {2}.".format(section, file_name, str(ex))
                        raise MonitorException(message) from ex
                    except netaddr.core.AddrFormatError as ex:
                        message = "ERROR: Parsing error creating {0} filter from "\
                            "file {1}: {2}.".format(section, file_name, str(ex))
                        raise MonitorException(message) from ex
            except IOError as ex:
                raise MonitorException("ERROR: Unable to open file {0}: ({1})".
                    format(file_name, str(ex))) from ex
            except configparser.Error as ex:
                raise MonitorException("ERROR: Parsing error creating filters from file {0}: {1}.".
                    format(file_name, str(ex))) from ex

    @staticmethod
    def _read_filter_parameters(parser, section, file_name):
        # Reader parameters for this filter
        filter_params = {}
        items = parser.items(section)
        for pair in items:
            # Check parameter name
            param_name = pair[0].strip()
            if not param_name in GenericFilter.valid_parameter_names:
                raise MonitorException(
                    "ERROR: Unexpected filter parameter {0} for filter {1} in {2}.".
                    format(param_name, section, file_name))

            # Record parameter
            if param_name == "cmdline_is_re":
                try:
                    param_value = parser[section].getboolean("cmdline_is_re")
                except ValueError as value_error:
                    raise MonitorException(
                        "ERROR: Expecting true or false for cmdline_is_re for" +
                        " {0} in {1}".format(section, file_name)) from value_error
            else:
                param_value = pair[1].strip()
            filter_params[param_name] = param_value
        return filter_params

    def _do_netstat(self):
        """Create a NetStat, filter out SocketInfos, and report."""
        # Lookup all current sockets.
        self._netstat_id += 1
        netstat = NetStat(self._netstat_id)

        # Display active sockets.
        for socket_info in netstat.socket_infos:
            # Determine whether to display socket.
            socket_info = self._filter_socket(socket_info)

            # Display socket.
            if not socket_info is None:
                if LOOKUP_REMOTE_HOST_NAME:
                    socket_info.lookup_remote_host_name()
                socket_info.assign_uid()
                print(str(socket_info))
                socket_info.was_displayed = True

        # Mark closed sockets and display.
        seen_values = list(self._seen.values())
        for seen_info in seen_values:
            if seen_info.last_seen != self._netstat_id:

                # Mark closed.
                seen_info.mark_closed()

                # Display
                if self._state_changes and seen_info.was_displayed:
                    seen_info.update_time()
                    print(str(seen_info))

                # Remove from seen collection
                del self._seen[seen_info.fingerprint]

        sys.stdout.flush()

    # pylint: disable=too-many-return-statements
    def _filter_socket(self, socket_info):
        """Return the SocketInfo to use if not filtered, else None."""

        # Has this SocketInfo already been seen?
        seen_info = self.lookup_seen(socket_info)
        already_seen = not seen_info is None

        # Note when last seen
        if already_seen:
            seen_info.record_last_seen(self._netstat_id)

        # Filter out if already seen and state changes are not being reported.
        if already_seen and not self._state_changes:
            return None

        # Finish initializing SocketInfo.
        if already_seen:
            # Use the seen_info, since it's already looked up most things.
            orig_state = seen_info.state
            seen_info.update(socket_info.line)
            socket_info = seen_info
        else:
            socket_info.finish_initializing()

        # Filter out if state hasn't changed.
        if already_seen and socket_info.state == orig_state:
            return None

        # Filter out if PID was not found. PID can be missing if either of the following happens
        # in between the time the socket's inode was found in a /proc/net file and when its
        # PID was searched for in /proc/*/fd.
        #     -- Socket was closed. This can happen with short lived sockets; e.g. with a udp
        #        socket for a DNS lookup. Or, it's possible it could happen with a TCP socket
        #        although this is less likely since a TCP connection goes through a series
        #        of states to end.
        #     -- Process exited. The socket could still be exist, if the process that exited
        #        did an exec and the child process now owns the socket. It should be seen the
        #        next time a NetStat is done, as owned by the child.
        # One variable in all of this is monitor_interval, which determines how often the
        # /proc/net files are read. They're read every monitor_interval seconds. The lower
        # this value, the less likely it is a socket will not be seen. However, CPU load goes up.
        pid = socket_info.lookup_pid()
        if pid is None:
            return None

        # Mark SocketInfo as seen.
        if not already_seen:
            self._mark_seen(socket_info)

        # Filter out local connections.
        if self._ignore_loopback and socket_info.is_loopback:
            return None

        # Filter out any closing connections that have been turned over to init.
        if pid == "1" and socket_info.state in Monitor._closing_states:
            return None

        # Check filters provided by user.
        if not self._filters is None:
            for socket_filter in self._filters:
                if socket_filter.filter_out(socket_info):
                    return None

        return socket_info

    def lookup_seen(self, socket_info):
        """Return previously seen SocketInfo that matches fingerprint of socket_info."""
        seen_info = self._seen.get(socket_info.fingerprint)
        return seen_info

    def has_been_seen(self, socket_info):
        """Return True if a SocketInfo with same fingerprint as socket_info has
        already been seen."""
        seen_info = self.lookup_seen(socket_info)
        return not seen_info is None

    def _mark_seen(self, socket_info):
        """Record socket_info as seen."""
        socket_info.record_last_seen(self._netstat_id)
        self._seen[socket_info.fingerprint] = socket_info

    def monitor(self):
        """Perform a NetStat every monitor_interval seconds."""
        # Print header
        # pylint: disable=line-too-long
        print("Time            Proto ID  User     Local Address        Foreign Address      State       PID   Exe                  Command Line")
        sys.stdout.flush()

        while True:
            self._do_netstat()
            time.sleep(self._interval)

# pylint: disable=too-few-public-methods
class NetStat():
    """NetStat creates SocketInfo instances from lines in /proc/net/tcp and /proc/net/udp"""
    def __init__(self, netstat_id):
        """Create SocketInfo instances."""
        # Assign id.
        self.netstat_id = netstat_id

        # Load sockets
        self.socket_infos = []
        self._load('tcp', PROC_TCP6)
        self._load('tcp', PROC_TCP)
        self._load('udp', PROC_UDP6)
        self._load('udp', PROC_UDP)

    def _load(self, socket_type, path):
        """Create SocketInfo from either /proc/net/tcp or /proc/net/udp"""
        # Read the table of sockets & remove header
        with open(path, 'r') as proc_file:
            content = proc_file.readlines()
            content.pop(0)

        # Create SocketInfos.
        for line in content:
            info = SocketInfo.create_from_line(socket_type, line)
            self.socket_infos.append(info)
