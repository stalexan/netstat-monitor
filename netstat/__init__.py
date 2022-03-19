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

"""The netstat package displays information about network connections on a system,
similar to the kind of information that the netstat command provides.

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
from typing import Any, ClassVar, Dict, Optional, TextIO, Tuple

# Third-party imports
import netaddr # pylint: disable=import-error

# Local imports
from .filters import GenericFilter
from .shared import MonitorException, OptionType
from .sockets import SocketInfo

__version__ = "v1.1.4"

DEFAULT_MONITOR_INTERVAL = 1     # Number of seconds between each netstat.
MIN_MONITOR_INTERVAL =     0.001 # Minimum value for monitor interval.

LOOKUP_REMOTE_HOST_NAME = True # Whether to convert IP addresses to host names
                               # by doing a host name lookup.

# Location files used to collect connection information.
PROC_TCP = "/proc/net/tcp"
PROC_TCP6 = "/proc/net/tcp6"
PROC_UDP = "/proc/net/udp"
PROC_UDP6 = "/proc/net/udp6"

TESTED_KERNEL = "5.10"

def main() -> int:
    """Monitor network connections."""

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
    args: Any = parser.parse_args()

    # Monitor
    return_code: int = 0
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
    """Creates filters and reports SocketInfos at regular intervals.

    Attributes
    ----------
    _closing_states : list[str]
        List of socket states that indicate the connection is closing.
    _interval : float
        How often to look up connections, in seconds.
    _ignore_loopback : bool
        Whether to ignore connections on the loopback interface.
    _state_changes : bool
        Whether to report connection state changes to user.
    _seen : Dict[str, SocketInfo]
        Collection of connections already seen, indexed by connection fingerprint.
    _netstat_id : int
        The unique ID used for the last NetStat created.

    """
    _closing_states: ClassVar[list[str]] = ['FIN_WAIT1', 'FIN_WAIT2',
        'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'CLOSING']
    _interval: float = DEFAULT_MONITOR_INTERVAL
    _ignore_loopback: bool = False
    _state_changes: bool = False
    _seen: Dict[str, SocketInfo] = {}
    _netstat_id: int = 0

    def __init__(self, interval: float = DEFAULT_MONITOR_INTERVAL, ignore_loopback: bool = False,
        state_changes: bool = False, filter_files: Optional[list[str]] = None) -> None:
        """Create a Monitor that checks for connections every interval seconds using the
        specified filters.

        Parameters
        ----------
        interval : int, default DEFAULT_MONITOR_INTERVAL
            Number of seconds between each time Monitor creates a Netstat, and reports any new
            connections found.
        ignore_loopback : bool, default False
            Whether to ignore local connections.
        state_changes : bool, default False
            Whether to report connection state changes.
        filters: list[str], optional
            List of any filters to limit which connections are displayed. Any connections
            (SocketInfos) that match a filter are not displayed.

        """
        if interval < MIN_MONITOR_INTERVAL:
            raise MonitorException(
                f"ERROR: Monitor interval needs to be at least {MIN_MONITOR_INTERVAL}")

        self._interval: float = interval
        self._ignore_loopback: bool = ignore_loopback
        self._state_changes: bool = state_changes
        self._seen: Dict[str, SocketInfo] = {}

        self._netstat_id: int = 0

        # Check for root permissions, so filters work and connection details can be looked up.
        if os.geteuid() != 0:
            raise MonitorException("ERROR: Root permissions needed, to lookup connection details.")

        # Check python version.
        if sys.version_info.major != 3 or sys.version_info.minor < 2:
            raise MonitorException("ERROR: Python 3.2 or greater needed.")

        # Do a basic check of kernel version, by looking comparing /proc/net
        # headers to expected headers.
        # pylint: disable=line-too-long
        tcp_header: str = Monitor._read_first_line(PROC_TCP)
        udp_header: str = Monitor._read_first_line(PROC_UDP)
        if (tcp_header != "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode" or
            udp_header != "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"):
            raise MonitorException(
                "ERROR: Unexpected /proc/net file format. This could be due to kernel version. " +
                f"Current kernel: {platform.uname()[2]}. Tested kernel: {TESTED_KERNEL}.")

        # Load filters
        self._filters = GenericFilter.load_filters(filter_files)

    @staticmethod
    def _read_first_line(path: str) -> str:
        """Read the first line of the specified file.

        Parameters
        ----------
        path : str
            The path of the file to read.

        Returns
        -------
        str
            The first line of the file.

        """
        with open(path, 'r', encoding="utf-8") as proc_file:
            line: str = proc_file.readline().strip()
        return line

    def _do_netstat(self) -> None:
        """Check for connections.

        Check and report on current connections. Filters out any that have
        already been seen and whose state has not changed, or any filtered out
        by provided filters.

        """
        # Lookup all current sockets.
        self._netstat_id += 1
        netstat = NetStat(self._netstat_id)

        # Display active sockets.
        candidate: SocketInfo
        for candidate in netstat.socket_infos:
            # Determine whether to display socket.
            socket_info: Optional[SocketInfo] = self._filter_socket(candidate)

            # Display socket.
            if not socket_info is None:
                if LOOKUP_REMOTE_HOST_NAME:
                    socket_info.lookup_remote_host_name()
                socket_info.assign_id()
                print(str(socket_info))
                socket_info.was_displayed = True

        # Mark closed sockets and display.
        seen_values: list[SocketInfo] = list(self._seen.values())
        seen_info: SocketInfo
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
    def _filter_socket(self, socket_info: SocketInfo) -> Optional[SocketInfo]:
        """Determine what to display to the user for a given connection (SocketInfo).

        Parameters
        ----------
        socket_info : SocketInfo
            The candidate connection, or SocketInfo, to display to user.

        Returns
        -------
        SocketInfo : optional
            The SocketInfo to display to the user for this connection, or None
            if nothing should be displayed. Nothing should be displayed if the
            connection is filtered out, or if the connection's already been
            displayed and there isn't a state change to show.

            If the connection should be displayed, a SocketInfo is returned.
            For connections that haven't been seen before, the same SocketInfo
            passed to this method is returned.  For connections that have been
            seen, the previously used SocketInfo is returned.

        """
        # Has this SocketInfo already been seen?
        seen_info: Optional[SocketInfo] = self.lookup_seen(socket_info)
        already_seen: bool = not seen_info is None

        # Note when last seen
        if seen_info is not None:
            seen_info.record_last_seen(self._netstat_id)

        # Filter out if already seen and state changes are not being reported.
        if already_seen and not self._state_changes:
            return None

        # Finish initializing SocketInfo.
        if seen_info is not None:
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
        pid: Optional[str] = socket_info.lookup_pid()
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
            socket_filter: GenericFilter
            for socket_filter in self._filters:
                if socket_filter.is_socket_filtered_out(socket_info):
                    return None

        return socket_info

    def lookup_seen(self, socket_info: SocketInfo) -> Optional[SocketInfo]:
        """Lookup the SocketInfo that was previously used for the given connection.

        Parameters
        ----------
        socket_info : SocketInfo
            Which connection to lookup.

        Returns
        -------
        SocketInfo, optional
            The SocketInfo that was previously used for this connection. Or None
            if this connection hasn't been seen before.

        """
        seen_info: Optional[SocketInfo] = self._seen.get(socket_info.fingerprint)
        return seen_info

    def has_been_seen(self, socket_info: SocketInfo) -> bool:
        """Determine whether this connection has been seen before.

        Parameters
        ----------
        socket_info : SocketInfo
            The connection in question.

        Returns
        -------
        bool:
            True if the connection has already been seen.

        """
        seen_info = self.lookup_seen(socket_info)
        return not seen_info is None

    def _mark_seen(self, socket_info: SocketInfo) -> None:
        """Mark the given connection as seen.

        Parameters
        ----------
        socket_info : SocketInfo
            The connection to mark as seen.

        """
        socket_info.record_last_seen(self._netstat_id)
        self._seen[socket_info.fingerprint] = socket_info

    def monitor(self) -> None:
        """Check for connections at regular intervals and report to user."""

        # Print header
        # pylint: disable=line-too-long
        print("Time            Proto ID  User     Local Address        Foreign Address      State       PID   Exe                  Command Line")
        sys.stdout.flush()

        while True:
            self._do_netstat()
            time.sleep(self._interval)

# pylint: disable=too-few-public-methods
class NetStat():
    """Snapshot of connections found at a given instant of time.

    A SocketInfo is created for each line found in the files ``/proc/net/tcp``,
    ``/proc/net/tcp6``, ``/proc/net/udp``, and ``/proc/net/udp6``.

    Attributes
    ----------
    netstat_id : int
        A unique ID for this NetStat instance.

    socket_infos: list[SocketInfo]
        The collection of SocketInfos found, one per connection.

    """
    netstat_id: int
    socket_infos: list[SocketInfo] = []

    def __init__(self, netstat_id: int) -> None:
        """Lookup connections and create a SocketInfo for each.

        Parameters
        ----------
        netstat_id : int
            The unique ID to use for this NetStat instance.

        """
        # Assign id.
        self.netstat_id: int = netstat_id

        # Load sockets
        self.socket_infos: list[SocketInfo] = []
        self._load('tcp', PROC_TCP6)
        self._load('tcp', PROC_TCP)
        self._load('udp', PROC_UDP6)
        self._load('udp', PROC_UDP)

    def _load(self, socket_type: str, path: str) -> None:
        """Create SocketInfos for the connections found in the given file.

        Parameters
        ----------
        socket_type : {'tcp', 'udp'}
            The type of connection: TCP or UDP.
        path : str
            The path of the file to read connection info from.

        """
        # Read the table of sockets & remove header
        with open(path, 'r', encoding="utf-8") as proc_file:
            content: list[str] = proc_file.readlines()
            content.pop(0)

        # Create SocketInfos.
        line: str
        for line in content:
            info: SocketInfo = SocketInfo.create_from_line(socket_type, line)
            self.socket_infos.append(info)
