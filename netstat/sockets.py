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
import binascii
import datetime
import errno
import glob
import ipaddress
import os
import pwd
import socket

# Local imports
from .shared import MonitorException

# pylint: disable=too-many-instance-attributes
class SocketInfo():
    # pylint: disable=line-too-long
    """
    Information about a particular network connection

    A SocketInfo is generated for each line found in /proc/net/tcp and /proc/net/udp.

    Sample from /proc/net/tcp:
        sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
         0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10921 1 0000000000000000 100 0 0 10 -1
         1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 139166 1 0000000000000000 100 0 0 10 -1

    Sample from /proc/net/udp:
        sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
       268: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 139165 2 0000000000000000 0
       283: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 160578 2 0000000000000000 0

    Attributes:

    socket_type -- Type of socket: "tcp" for sockets from /proc/net/tcp or "udp" for sockets
      that from /proc/net/udp
    line -- The original /proc/net line this SocketInfo is based on (from either /proc/net/tcp
      or /proc/net/udp)
    inode -- The inode for the socket.
    fingerprint -- A fingerprint, or hash value, for the SocketInfo.
    uid -- Unique id for this socket.
    state -- The socket state; e.g. SYN_SENT, ESTABLISHED, etc.
    time -- When SocketInfo was created.
    last_seen -- When this SocketInfo was last seen.
    local_host -- Connection local IP address.
    local_port -- Connection local port.
    remote_host -- Connection remote IP address.
    remote_port -- Connection report port.

    Other attributes are returned from lookup functions, to avoid the extra overhead required
    to look them up when they're not needed. See the functions: lookup_user(), lookup_pid(),
    lookup_exe(), lookup_cmdline(), and lookup_remote_host_name().
    """

    UNDEFINED_STATE = 'UNDEFINED'
    CLOSED_STATE = 'CLOSED'
    NA_STATE = ''

    _state_mappings = {
         '01' : 'ESTABLISHED',  '02' : 'SYN_SENT',      '03' : 'SYN_RECV',
         '04' : 'FIN_WAIT1',    '05' : 'FIN_WAIT2',     '06' : 'TIME_WAIT',
         '07' : 'CLOSE',        '08' : 'CLOSE_WAIT',    '09' : 'LAST_ACK',
         '0A' : 'LISTEN',       '0B' : 'CLOSING' }

    _next_uid = 1

    # pylint: disable=line-too-long
    # Indicies into fields of lines from /proc/net file
    # Example:
    # sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    # 0:  0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7369 1 ffff8801186bc040 100 0 0 10 -1
    LINE_INDEX_LOCAL_ADDRESS    = 1
    LINE_INDEX_REM_ADDRESS      = 2
    LINE_INDEX_ST               = 3
    LINE_INDEX_UID              = 7
    LINE_INDEX_INODE            = 9

    def __init__(self):
        self._user = None
        self.uid = None
        self._user_id = None
        self._exe = None
        self._cmdline = None
        self.local_host = None
        self.local_port = None
        self.remote_host = None
        self._remote_host_name = None
        self.remote_port = None
        self.state = None

        self.socket_type = None
        self.inode = None
        self.fingerprint = None
        self.is_loopback = None

        self.last_seen = None
        self.was_displayed = None

        self._pid = None
        self._pid_looked_up = None

        self.line = None
        self._line_array = None

        self.time = None

    @staticmethod
    def create_from_line(socket_type, line):
        """Create a SocketInfo of type socket_type from line.

        Keyword arguments:
        socket_type -- tcp or udp
        line -- line from either /proc/net/tcp or /proc/net/udp

        """
        info = SocketInfo()
        info.create_from_line2(socket_type, line)
        return info

    def create_from_line2(self, socket_type, line):
        """Create a SocketInfo of type socket_type from line."""
        self.socket_type = socket_type

        self.record_line(line)

        # Determine fingerprint.
        self.inode = self._line_array[SocketInfo.LINE_INDEX_INODE]
        self.fingerprint = 'type:{0} local_address:{1} rem_address:{2}'.format(
            self.socket_type,
            self._line_array[SocketInfo.LINE_INDEX_LOCAL_ADDRESS],
            self._line_array[SocketInfo.LINE_INDEX_REM_ADDRESS])

        self.state = self.UNDEFINED_STATE

        self.last_seen = 0

        self.was_displayed = False

    # pylint: disable=too-many-arguments
    @staticmethod
    def _create_from_params(user=None, exe=None, cmdline=None, local_host=None, local_port=None,
        remote_host=None, remote_host_name=None, remote_port=None, state=None):
        """Create a SocketInfo using explicit parameters, for filter unit testing. """
        info = SocketInfo()
        info.create_from_explicit_params(user, exe, cmdline, local_host, local_port,
            remote_host, remote_host_name, remote_port, state)
        return info

    def create_from_explicit_params(self, user, exe, cmdline, local_host, local_port,
        remote_host, remote_host_name, remote_port, state):
        """Create a SocketInfo using explicit parameters, for filter unit testing. """
        self._user = user
        self._exe = exe
        self._cmdline = cmdline
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self._remote_host_name = remote_host_name
        self.remote_port = remote_port
        self.state = state

    def finish_initializing(self):
        """Finish initializing. Only needed if this SocketInfo will be kept."""

        # Default UID. Assign later if SocketInfo is reported to user.
        self.uid = 0

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
        self._user = None
        self._pid = None
        self._pid_looked_up = False
        self._exe = None
        self._cmdline = None
        self._remote_host_name = None

    def update(self, line):
        """Updates the this SocketInfo using latest line from /proc."""
        self.record_line(line)
        self.update_dynamic_attrs()

    def record_line(self, line):
        """Records line for this socket from /proc."""
        self.line = line
        self._line_array = SocketInfo._remove_empty(line.split(' '))

    def update_dynamic_attrs(self):
        """Lookup attributes that change over time."""

        # State
        if self.socket_type == "tcp":
            self.state = SocketInfo._state_mappings[self._line_array[SocketInfo.LINE_INDEX_ST]]
        else:
            self.state = SocketInfo.NA_STATE # "Not Applicable", for udp

        # Time
        self.update_time()

    def update_time(self):
        """TODO: docstring"""
        self.time = datetime.datetime.now()

    def has_been_reported(self):
        """Return True if this socket has been reported to user."""
        reported = self.uid != 0
        return reported

    def assign_uid(self):
        """TODO: docstring"""
        if self.uid == 0:
            self.uid = SocketInfo._next_uid
            SocketInfo._next_uid += 1

    def pid_was_found(self):
        """TODO: docstring"""
        found = self._pid_looked_up and not self._pid is None
        return found

    def lookup_user(self):
        """Lookup user name from uid."""
        if self._user is None:
            self._user = pwd.getpwuid(int(self._user_id))[0] # A bit expensive.
            self._user = self._user.strip()
        return self._user

    def lookup_pid(self):
        """Lookup pid from inode."""
        if not self._pid_looked_up:
            self._pid = SocketInfo._get_pid_of_inode(self.inode) # Expensive.
            if not self._pid is None:
                self._pid = self._pid.strip()
            self._pid_looked_up = True
        return self._pid

    def lookup_exe(self):
        """Lookup exe from pid."""
        if self._exe is None:
            try:
                pid = self.lookup_pid()
                self._exe = os.readlink('/proc/' + pid + '/exe')
                self._exe = self._exe.strip()
            except OSError:
                self._exe = None
        return self._exe

    def lookup_cmdline(self):
        """Lookup command line from pid."""
        if self._cmdline is None:
            try:
                pid = self.lookup_pid()
                with open('/proc/' + pid + '/cmdline', 'r') as proc_file:
                    self._cmdline = proc_file.readline()
                    self._cmdline = self._cmdline.replace('\0', ' ')
                    self._cmdline = self._cmdline.strip()
            except OSError:
                self._cmdline = None
        return self._cmdline

    def lookup_remote_host_name(self):
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

    def record_last_seen(self, netstat_id):
        """TODO: docstring"""
        self.last_seen = netstat_id

    def __str__(self):
        formatted_time = self.time.strftime("%b %d %X")
        local_address = self.local_host + ':' + self.local_port
        remote = self.remote_host
        if not self._remote_host_name is None:
            remote = self._remote_host_name
        remote_address = remote + ':' + self.remote_port
#Time            Proto ID  User     Local Address        Foreign Address      State       PID   Exe                  Command Line
#Sep 08 18:15:07 tcp   0   alice    127.0.0.1:8080       0.0.0.0:0            LISTEN      1810  /usr/bin/python2.7   /usr/bin/python foo.py
        string = '{0} {1:5} {2:3} {3:8} {4:20} {5:20} {6:11} {7:5} {8:20} {9}'.format(
            formatted_time,        # 0
            self.socket_type,      # 1
            str(self.uid),         # 2
            self.lookup_user(),    # 3
            local_address,         # 4
            remote_address,        # 5
            self.state,            # 6
            self.lookup_pid(),     # 7
            self.lookup_exe(),     # 8
            self.lookup_cmdline()) # 9
        return string

    def mark_closed(self):
        """TODO: docstring"""
        self.state = self.CLOSED_STATE

    def is_closed(self):
        """TODO: docstring"""
        return self.state == self.CLOSED_STATE

    def dump_str(self):
        """TODO: docstring"""
        string = "fingerprint: {0} ; remainder: {1}".format(self.fingerprint, str(self))
        return string

    @staticmethod
    def _is_ip_addr_private(addr_str):
        """Determine if IP address addr is a private address."""
        addr = ipaddress.ip_address(addr_str)
        return addr.is_private

    @staticmethod
    def _is_ip_addr_loopback(addr_str):
        """Determine if IP address addr is localhost."""
        addr = ipaddress.ip_address(addr_str)
        return addr.is_loopback

    @staticmethod
    def _hex2dec(hex_str):
        """Convert hex number in string hex_str to a decimal number string."""
        return str(int(hex_str, 16))

    @staticmethod
    def _ip(hex_str):
        """Convert IP address hex_str from hex format (e.g. "293DA83F") to decimal format (e.g. "64.244.27.136")."""
        if len(hex_str) == 8: # This is an IPv4 address.
            # Reverse order of bytes; e.g. A0B1C2D3 becomes D3C2B1A0
            rev = "".join(reversed([hex_str[ii:ii+2] for ii in range(0, len(hex_str), 2)]))

            # Convert Unicode string in to UTF-8 string.
            utf = rev.encode()

            # Turn string into its binary equivalent.
            binary = binascii.unhexlify(utf)

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
            colons = ":".join(rev[ii:ii+4] for ii in range(0, len(rev), 4))

            # Shorten address, if possible.
            is_actually_ipv4 = colons[:29] == "0000:0000:0000:0000:0000:FFFF"
            if is_actually_ipv4:
                octets = [colons[30:32], colons[32:34], colons[35:37], colons[37:39]]
                dec_str = ".".join([str(int(octet, 16)) for octet in octets])
            else:
                addr = ipaddress.IPv6Address(colons)
                dec_str = str(addr)
        else:
            raise MonitorException("ERROR: Invalid IP address {0}".format(hex_str))
        return dec_str

    @staticmethod
    def _remove_empty(array):
        """Remove zero length strings from array."""
        return [x for x in array if x != '']

    @staticmethod
    def _convert_ip_port(hexaddr):
        """Convert IP address and port from hex to decimal; e.g. "293DA83F:0050" to ["64.244.27.136", "80"]."""
        host,port = hexaddr.split(':')
        host_converted = SocketInfo._ip(host)
        port_converted = SocketInfo._hex2dec(port)
        return host_converted,port_converted

    @staticmethod
    def _get_pid_of_inode(inode):
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

        pid = None
        deref_match = "socket:[{0}]".format(inode)
        for fd_link in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
            try:
                # Dereference symbolic link.
                # In above example, the link is:
                #     /proc/12764/fd/4 -> socket:[139165]
                # fd_link would be
                #     /proc/12764/fd/4
                # and dref will be
                #     socket:[139165]
                deref = None
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
