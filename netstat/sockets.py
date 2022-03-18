"""This file contains the SocketInfo class."""

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
import binascii
import datetime
import errno
import glob
import ipaddress
import os
import pwd
import socket
from typing import ClassVar, Optional

# Local imports
from .shared import MonitorException

# pylint: disable=too-many-instance-attributes
class SocketInfo():
    # pylint: disable=line-too-long
    """Information about a particular network connection.

    A SocketInfo is generated for each line found in the files IPv4 files
    ``/proc/net/tcp`` and ``/proc/net/udp``, and the IPv6 files
    ``/proc/net/tcp6`` and ``/proc/net/udp6``.

    Sample from /proc/net/tcp:
        sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
         0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10921 1 0000000000000000 100 0 0 10 -1
         1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 139166 1 0000000000000000 100 0 0 10 -1

    Sample from /proc/net/udp:
        sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
       268: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 139165 2 0000000000000000 0
       283: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 160578 2 0000000000000000 0

    Attributes That Are Set Explicity
    ---------------------------------
    socket_type : {'tcp', 'udp'}
        The type of socket: TCP or UDP.
    _info_id : int
        The unique ID for this SocketInfo instance.
    fingerprint : str
        A unique fingerprint or hash value for this SocketInfo.
    is_loopback : bool
        Whether this is a loopback connection.
    last_seen : int
        The unique ID of the last NetStat that saw this connection.
    was_displayed : bool
        Whether this connection has been displayed to the user.
    time : datetime.datetime
        When this SocketInfo was last updated.

    Attributes That Come From ``/proc/net`` Files
    ---------------------------------------------
    line : str
        The original ``/proc/net`` line this SocketInfo is based on.
    _line_array : list[str]
        Line parsed into string elements, with whitespace as delimiter.
    inode : str
        The inode for this connection.
    _user_id : str
        The user id for this connection.
    local_host : str
        The local IP address.
    local_port : str
        The local port.
    remote_host : str
        The remote IP address.
    remote_port : str
        The remote port.
    state : str
        The connection state; e.g. SYN_SENT, ESTABLISHED, etc.

    Attributes That Are Looked Up Later If Needed
    ---------------------------------------------
    _cmdline : Optional[str]
        The command line for the process associated with this connection. For
        example ``/usr/bin/python3 foo.py``.
    _exe : Optional[str]
        The exe associated with the process for this connection. For example
        `/usr/bin/python3.8`.
    _pid : Optional[str]
        The pid for the process associated with this connection.
    _pid_looked_up : bool
        Whether the pid has been looked up.
    _remote_host_name : Optional[str]
        The name of the remote host associated with this connection.
    _user_name : Optional[str]
        The user name for the process associated with this connection.

    """
    # These are set explicitly.
    socket_type: str
    _info_id: int # Unique ID for this SocketInfo
    fingerprint: str
    is_loopback: bool
    last_seen: int
    was_displayed: bool
    time: datetime.datetime

    # Lookup for these comes from lines in /proc/net/tcp and /proc/net/udp.
    line: str
    _line_array: list[str]
    inode: str
    _user_id: str
    local_host: str
    local_port: str
    remote_host: str
    remote_port: str
    state: str

    # Lookup is deferred for these.
    _cmdline: Optional[str]
    _exe: Optional[str]
    _pid: Optional[str]
    _pid_looked_up: bool
    _remote_host_name: Optional[str]
    _user_name: Optional[str]

    UNDEFINED_STATE: ClassVar[str] = 'UNDEFINED'
    CLOSED_STATE: ClassVar[str] = 'CLOSED'
    NA_STATE: ClassVar[str] = ''

    _state_mappings: dict[str, str] = {
         '01' : 'ESTABLISHED',  '02' : 'SYN_SENT',      '03' : 'SYN_RECV',
         '04' : 'FIN_WAIT1',    '05' : 'FIN_WAIT2',     '06' : 'TIME_WAIT',
         '07' : 'CLOSE',        '08' : 'CLOSE_WAIT',    '09' : 'LAST_ACK',
         '0A' : 'LISTEN',       '0B' : 'CLOSING' }

    _next_info_id: int = 1

    # pylint: disable=line-too-long
    # Indicies into fields of lines from /proc/net file
    # Example:
    # sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    # 0:  0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7369 1 ffff8801186bc040 100 0 0 10 -1
    LINE_INDEX_LOCAL_ADDRESS: int    = 1
    LINE_INDEX_REM_ADDRESS: int      = 2
    LINE_INDEX_ST: int               = 3
    LINE_INDEX_UID: int              = 7
    LINE_INDEX_INODE: int            = 9

    def __init__(self) -> None:

        # These are set explicitly.
        self.socket_type = ""
        self._info_id = 0
        self.fingerprint = ""
        self.is_loopback = False
        self.last_seen = 0
        self.was_displayed = False
        self.time = datetime.datetime.now()

        # Lookup for these comes from lines in /proc/net/tcp and /proc/net/udp.
        self.line = ""
        self._line_array = []
        self.inode = ""
        self._user_id = ""
        self.local_host = ""
        self.local_port = ""
        self.remote_host = ""
        self.remote_port = ""
        self.state = ""

        # Lookup for these is deferred.
        self._cmdline = None
        self._exe = None
        self._pid = None
        self._pid_looked_up = False
        self._remote_host_name = None
        self._user_name = None

    @staticmethod
    def create_from_line(socket_type: str, line: str) -> "SocketInfo":
        """Create a SocketInfo of type socket_type using data from line.

        Attributes
        ----------
        See ``init_from_line()``.

        Returns
        -------
        SocketInfo:
            The newly created SocketInfo.

        """
        info = SocketInfo()
        info.init_from_line(socket_type, line)
        return info

    def init_from_line(self, socket_type: str, line: str) -> None:
        """Initialize this SocketInfo of type socket_type using data from line.

        Parameters
        ----------
        socket_type : {'tcp', 'udp'}
            The type of socket: TCP or UDP.
        line : str
            The ``/proc/net`` line this connection is based on.

        """
        self.socket_type = socket_type

        self.record_line(line)

        self.inode = self._line_array[SocketInfo.LINE_INDEX_INODE]

        # Determine fingerprint.
        self.fingerprint = f"type:{self.socket_type} " \
            f"local_address:{self._line_array[SocketInfo.LINE_INDEX_LOCAL_ADDRESS]} " \
            f"rem_address:{self._line_array[SocketInfo.LINE_INDEX_REM_ADDRESS]}"

        self.state = self.UNDEFINED_STATE

        self.last_seen = 0

        self.was_displayed = False

    # pylint: disable=too-many-arguments
    @staticmethod
    def _create_from_params(user_name: Optional[str] = None, exe: Optional[str] = None,
        cmdline: Optional[str] = None, local_host: str = "", local_port: str = "",
        remote_host: str = "", remote_host_name: Optional[str] = None,
        remote_port: str = "", state: str = "", pid: str ="") -> "SocketInfo":
        """Create a SocketInfo using explicit parameters, for filter unit testing.

        See ``create_from_explicit_params()``.

        """
        info = SocketInfo()
        info.create_from_explicit_params(user_name, exe, cmdline, local_host, local_port,
            remote_host, remote_host_name, remote_port, state, pid)
        return info

    def create_from_explicit_params(self, user_name: Optional[str], exe: Optional[str],
        cmdline: Optional[str], local_host: str, local_port: str, remote_host: str,
        remote_host_name: Optional[str], remote_port: str, state: str, pid: Optional[str]) -> None:
        """Initialize this SocketInfo using explicit parameters, for filter unit testing.

        Attributes
        ----------
        user_name : str, optional
            The user name for the process associated with this connection.
        exe : str, optional
            The exe associated with the process for this connection.
        cmdline : Optional[str]
         The command line for the process associated with this connection.
        local_host : str
            The local IP address.
        local_port : str
            The local port.
        remote_host : str
            The remote IP address.
        remote_host_name : str, optional
            The name of the remote host associated with this connection.
        remote_port : str
            The remote port.
        state : str
            The connection state; e.g. SYN_SENT, ESTABLISHED, etc.
        pid : str
            The pid of the process associated with this connection.

        """
        self._user_name = user_name
        self._exe = exe
        self._cmdline = cmdline
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self._remote_host_name = remote_host_name
        self.remote_port = remote_port
        self.state = state
        self._pid = pid
        self._pid_looked_up = not pid is None

    def finish_initializing(self) -> None:
        """Finish initializing this SocketInfo.

        This is called only if this SocketInfo will be kept, and not filtered out.

        """
        # Default is 0. Assign later if SocketInfo is reported to user.
        self._info_id = 0

        # Lookup state and time.
        self.update_dynamic_attrs()

        # User ID
        self._user_id = self._line_array[SocketInfo.LINE_INDEX_UID]

        # Addresses
        self.local_host,self.local_port = SocketInfo._convert_ip_port(
            self._line_array[SocketInfo.LINE_INDEX_LOCAL_ADDRESS])
        self.remote_host,self.remote_port = SocketInfo._convert_ip_port(
            self._line_array[SocketInfo.LINE_INDEX_REM_ADDRESS])
        self.is_loopback = SocketInfo._is_ip_addr_loopback(self.local_host)

        # Save rest of lookup for "lookup" methods, since expensive and info
        # may not be needed if filtered out.
        self._user_name = None
        self._pid = None
        self._pid_looked_up = False
        self._exe = None
        self._cmdline = None
        self._remote_host_name = None

    def update(self, line: str) -> None:
        """Update this SocketInfo using latest line from ``/proc/net``."""
        self.record_line(line)
        self.update_dynamic_attrs()

    def record_line(self, line: str) -> None:
        """Records line for this socket from ``/proc/net``."""
        self.line = line
        self._line_array = SocketInfo._remove_empty(line.split(' '))

    def update_dynamic_attrs(self) -> None:
        """Lookup attributes that change over time."""

        # State
        if self.socket_type == "tcp":
            self.state = SocketInfo._state_mappings[self._line_array[SocketInfo.LINE_INDEX_ST]]
        else:
            self.state = SocketInfo.NA_STATE # "Not Applicable", for udp

        # Time
        self.update_time()

    def update_time(self) -> None:
        """Set time for this SocketInfo to now."""
        self.time = datetime.datetime.now()

    def has_been_reported(self) -> bool:
        """Return True if this socket has been reported to user."""
        reported = self._info_id != 0
        return reported

    def assign_id(self) -> None:
        """Give this SocketInfo a unique ID."""
        if self._info_id == 0:
            self._info_id = SocketInfo._next_info_id
            SocketInfo._next_info_id += 1

    def pid_was_found(self) -> bool:
        """Return True if a pid has been found for the process associated with this connection."""
        found: bool = self._pid_looked_up and not self._pid is None
        return found

    def lookup_user(self) -> str:
        """Lookup user name from user id."""
        if self._user_name is None:
            self._user_name = pwd.getpwuid(int(self._user_id))[0] # A bit expensive.
            self._user_name = self._user_name.strip()
        return self._user_name

    def lookup_pid(self) -> Optional[str]:
        """Lookup pid from inode."""
        if not self._pid_looked_up:
            self._pid = SocketInfo._get_pid_of_inode(self.inode) # Expensive.
            if not self._pid is None:
                self._pid = self._pid.strip()
            self._pid_looked_up = True
        return self._pid

    def lookup_exe(self) -> Optional[str]:
        """Lookup exe from pid."""
        if self._exe is None:
            try:
                pid = self.lookup_pid()
                if not pid is None:
                    self._exe = os.readlink('/proc/' + pid + '/exe')
                    self._exe = self._exe.strip()
            except OSError:
                self._exe = None
        return self._exe

    def lookup_cmdline(self) -> Optional[str]:
        """Lookup command line from pid."""
        if self._cmdline is None:
            try:
                pid = self.lookup_pid()
                if not pid is None:
                    with open('/proc/' + pid + '/cmdline', 'r', encoding="utf-8") as proc_file:
                        self._cmdline = proc_file.readline()
                        self._cmdline = self._cmdline.replace('\0', ' ')
                        self._cmdline = self._cmdline.strip()
            except OSError:
                self._cmdline = None
        return self._cmdline

    def lookup_remote_host_name(self) -> Optional[str]:
        """Lookup remote host name from IP address."""
        if self._remote_host_name is None:
            if SocketInfo._is_ip_addr_private(self.remote_host) or SocketInfo._is_ip_addr_loopback(self.remote_host):
                self._remote_host_name = self.remote_host
            else:
                try:
                    self._remote_host_name = socket.gethostbyaddr(self.remote_host)[0]
                except OSError:
                    self._remote_host_name = self.remote_host
            self._remote_host_name = self._remote_host_name.strip()
        return self._remote_host_name

    def record_last_seen(self, netstat_id: int) -> None:
        """Record the ID of the last NetStat that saw this connection."""
        self.last_seen = netstat_id

    def __str__(self) -> str:
        """Return formatted string to display to user, that describes this connection."""
        formatted_time: str = self.time.strftime("%b %d %X")
        local_address: str = self.local_host + ':' + self.local_port
        remote: str = self.remote_host
        if not self._remote_host_name is None:
            remote = self._remote_host_name
        remote_address: str = remote + ':' + self.remote_port
#Time            Proto ID  User     Local Address        Foreign Address      State       PID   Exe                  Command Line
#Sep 08 18:15:07 tcp   0   alice    127.0.0.1:8080       0.0.0.0:0            LISTEN      1810  /usr/bin/python2.7   /usr/bin/python foo.py
        string = f"{formatted_time} {self.socket_type:5} {str(self._info_id):3} " \
            f"{self.lookup_user():8} {local_address:20} {remote_address:20} " \
            f"{self.state:11} {self.lookup_pid():5} {self.lookup_exe():20} " \
            f"{self.lookup_cmdline()}"
        return string

    def mark_closed(self) -> None:
        """Set the state of the connection to closed."""
        self.state = self.CLOSED_STATE

    def is_closed(self) -> bool:
        """Whether this connection is closed."""
        return self.state == self.CLOSED_STATE

    def dump_str(self) -> str:
        """Return a debug string that describes this connection."""
        string = f"fingerprint: {self.fingerprint} ; remainder: {str(self)}"
        return string

    @staticmethod
    def _is_ip_addr_private(addr_str: str) -> bool:
        """Return True if the provided IP address is private."""
        addr = ipaddress.ip_address(addr_str)
        return addr.is_private

    @staticmethod
    def _is_ip_addr_loopback(addr_str: str) -> bool:
        """Return True if the provided IP address is localhost."""
        addr = ipaddress.ip_address(addr_str)
        return addr.is_loopback

    @staticmethod
    def _hex2dec(hex_str: str) -> str:
        """Return decimal equivalent of the provided hex number."""
        return str(int(hex_str, 16))

    @staticmethod
    def _ip(hex_str: str) -> str:
        """Return the decimal equivalent of the IP address provided as hex; e.g. "64.244.27.136" from "293DA83F"."""
        dec_str: str
        rev: str
        if len(hex_str) == 8: # This is an IPv4 address.
            # Reverse order of bytes; e.g. A0B1C2D3 becomes D3C2B1A0
            rev = "".join(reversed([hex_str[ii:ii+2] for ii in range(0, len(hex_str), 2)]))

            # Convert Unicode string in to UTF-8 string.
            utf: bytes = rev.encode()

            # Turn string into its binary equivalent.
            binary: bytes = binascii.unhexlify(utf)

            # Turn address into its dotted quad equivalent.
            dec_str = socket.inet_ntoa(binary)
        elif len(hex_str) == 32: # This is an IPv6 address.
            # Reverse order of bytes in each 4 byte word; e.g.
            #     B80D0120 00000000 67452301 EFCDAB89
            # becomes
            #     20010DB8 00000000 01234567 89ABCDEF
            # for the IPv6 address
            #     2001:db8::0123:4567:89ab:cdef
            rev = "".join(
                list(reversed([hex_str[ii:ii+2] for ii in range(0, 7, 2)])) +
                list(reversed([hex_str[ii:ii+2] for ii in range(8, 15, 2)])) +
                list(reversed([hex_str[ii:ii+2] for ii in range(16, 23, 2)])) +
                list(reversed([hex_str[ii:ii+2] for ii in range(24, 31, 2)])))

            # Add colons
            colons: str = ":".join(rev[ii:ii+4] for ii in range(0, len(rev), 4))

            # Shorten address, if possible.
            is_actually_ipv4: bool = colons[:29] == "0000:0000:0000:0000:0000:FFFF"
            if is_actually_ipv4:
                octets: list[str] = [colons[30:32], colons[32:34], colons[35:37], colons[37:39]]
                dec_str = ".".join([str(int(octet, 16)) for octet in octets])
            else:
                addr = ipaddress.IPv6Address(colons)
                dec_str = str(addr)
        else:
            raise MonitorException(f"ERROR: Invalid IP address {hex_str}")
        return dec_str

    @staticmethod
    def _remove_empty(array: list[str]) -> list[str]:
        """Remove zero length strings from array."""
        return [x for x in array if x != '']

    @staticmethod
    def _convert_ip_port(hexaddr: str) -> tuple[str, str]:
        """Convert IP address and port from hex to decimal; e.g. "293DA83F:0050" to ["64.244.27.136", "80"]."""
        host: str
        port: str
        host,port = hexaddr.split(':')
        host_converted: str = SocketInfo._ip(host)
        port_converted: str = SocketInfo._hex2dec(port)
        return host_converted,port_converted

    @staticmethod
    def _get_pid_of_inode(inode: str) -> Optional[str]:
        """Look up pid of inode.

        Looks through entries in /proc/*/fd/* for a file descriptor that references
        the specified inode.  For example, if inode is
            139164
        and
            /proc/12764/fd/4
        is a symbolic link to
            socket:[139165]
        This function returns
            12764

        """
        # LOG
        #print("_get_pid_of_inode(): inode {0}".format(inode))
        #sys.stdout.flush()

        pid: Optional[str] = None
        deref_match: str = f"socket:[{inode}]"
        fd_link: str
        for fd_link in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
            try:
                # Dereference symbolic link.
                # In above example, the link is:
                #     /proc/12764/fd/4 -> socket:[139165]
                # fd_link would be
                #     /proc/12764/fd/4
                # and dref will be
                #     socket:[139165]
                deref: Optional[str] = None
                deref = os.readlink(fd_link)

                # PID has been found if deref matches.
                if deref == deref_match:
                    pid = fd_link.split('/')[2]
                    break

            except OSError as ex:

                # LOG
                #message = 'PID search exception: inode {0}, fd_link {1}, deref {2}: {3}'.format(
                #   inode, fd_link, str(deref), str(ex))
                #print(message)
                #sys.stdout.flush()

                # ENOENT, "No such file or directory", can happen if socket closed in between
                # glob.glob() and readlink().
                if ex.errno != errno.ENOENT:
                    raise ex

        # LOG
        #print("    pid {0}, fd_link {1}, deref {2}".format(pid, fd_link, deref))
        #sys.stdout.flush()

        return pid
