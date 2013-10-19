#!/usr/bin/python3
#
# Copyright 2012 Sean Alexandre
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

Netstat -- Captures a snapshot of the current network connections.
Monitor -- Collects netstat snapshots at regular intervals.
SocketInfo -- Information about a particular connection.
SocketFilter -- Base class for filters, to filter the set of connections reported by Monitor.
GenericFilter -- Filters on properties of SocketInfo.

Variables:

DEFAULT_MONITOR_INTERVAL -- How often Monitor collects netstat snapshots, in seconds.
MIN_MONITOR_INTERVAL -- Minimum value for monitor interval.
CLEAN_INTERVAL -- How often the list of connections is reset, in minutes.
LOOKUP_REMOTE_HOST_NAME -- Whether to convert IP addresses to host names.

"""

import argparse
import configparser
import datetime
import errno
import glob
import os
import platform
import pwd
import re
import socket
import sys
import time

__version__ = "1.1rc1"

DEFAULT_MONITOR_INTERVAL = 1     # Number of seconds between each netstat.
MIN_MONITOR_INTERVAL =     0.001 # Minimum value for monitor interval.
CLEAN_INTERVAL =           5     # Number of minutes "seen" list grows before being cleaned out.

LOOKUP_REMOTE_HOST_NAME = True # Whether to convert IP addresses to host names by doing a host name lookup.

PROC_TCP = "/proc/net/tcp"
PROC_UDP = "/proc/net/udp"

TESTED_KERNEL = "3.2.0"

class MonitorException(Exception):
    def __init__(self, message, return_code=-1):
        self.message = message
        self.return_code = return_code

    def __str__(self):
        return self.message

'''
SocketInfo records socket info from /proc/net/tcp and /proc/net/udp

Sample from /proc/net/tcp:
    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
     0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10921 1 0000000000000000 100 0 0 10 -1                    
     1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 139166 1 0000000000000000 100 0 0 10 -1                   

Sample from /proc/net/udp:
    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops             
   268: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 139165 2 0000000000000000 0        
   283: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 160578 2 0000000000000000 0        
'''
class SocketInfo():
    """
    Information about a particular network connection.

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

    _private_regex = [ re.compile(ex) for ex in [
        '^127.\d{1,3}.\d{1,3}.\d{1,3}$',
        '^10.\d{1,3}.\d{1,3}.\d{1,3}$',
        '^192.168.\d{1,3}$',
        '172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$']]

    _next_uid = 1

    # Indicies into fields of lines from /proc/net file
    # Example:
    # sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    # 0:  0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7369 1 ffff8801186bc040 100 0 0 10 -1
    LINE_INDEX_LOCAL_ADDRESS    = 1
    LINE_INDEX_REM_ADDRESS      = 2
    LINE_INDEX_ST               = 3
    LINE_INDEX_UID              = 7
    LINE_INDEX_INODE            = 9

    def __init__(self, socket_type, line):
        """Create a SocketInfo of type socket_type from line.

        Keyword arguments:
        socket_type -- tcp or udp
        line -- line from either /proc/net/tcp or /proc/net/udp
        monitor -- Monitor instance used to filter and report SocketInfo instances. Optional.

        """
        self.socket_type = socket_type

        self.record_line(line)

        # Determine fingerprint. 
        self.inode = self._line_array[SocketInfo.LINE_INDEX_INODE]
        self.fingerprint = 'type:{0} inode:{1} local_address:{2} rem_address:{3}'.format(
            self.socket_type, self.inode, 
            self._line_array[SocketInfo.LINE_INDEX_LOCAL_ADDRESS],
            self._line_array[SocketInfo.LINE_INDEX_REM_ADDRESS])

        self.state = self.UNDEFINED_STATE

        self.last_seen = 0

        self.was_displayed = False

    def finish_initializing(self):
        """Finish initializing. Only needed if this SocketInfo will be kept."""

        # Default UID. Assign later if SocketInfo is reported to user.
        self.uid = 0

        # Lookup state and time.
        self.update_dynamic_attrs()

        # User ID
        self._user_id = self._line_array[SocketInfo.LINE_INDEX_UID]

        # Addresses
        self.local_host,self.local_port = SocketInfo._convert_ip_port(self._line_array[SocketInfo.LINE_INDEX_LOCAL_ADDRESS])
        self.remote_host,self.remote_port = SocketInfo._convert_ip_port(self._line_array[SocketInfo.LINE_INDEX_REM_ADDRESS]) 
        self.is_loopback = SocketInfo._is_loopback(self.local_host)

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
        self.time = datetime.datetime.now();

    @staticmethod
    def _is_loopback(addr):
        """Determine if IP address addr is localhost."""
        # TODO: Do an ifconfig to lookup loopback address at runtime, instead of hardcoding here.
        is_loopback = addr == "127.0.0.1"
        return is_loopback

    def has_been_reported(self):
        """Return True if this socket has been reported to user."""
        reported = self.uid != 0
        return reported

    def assign_uid(self):
        if self.uid == 0:
            self.uid = SocketInfo._next_uid
            SocketInfo._next_uid += 1

    def pid_was_found(self):
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
            except:
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
            except:
                self._cmdline = None
        return self._cmdline

    def lookup_remote_host_name(self):
        """Lookup remote host name from IP address."""
        if self._remote_host_name is None:
            if SocketInfo._is_ip_addr_private(self.remote_host):
                self._remote_host_name = self.remote_host
            else:
                try:
                    self._remote_host_name = socket.gethostbyaddr(self.remote_host)[0]
                except:
                    self._remote_host_name = self.remote_host
            self._remote_host_name = self._remote_host_name.strip()
        return self._remote_host_name

    def record_last_seen(self, netstat_id):
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
        return string;                

    def mark_closed(self):
        self.state = self.CLOSED_STATE

    def is_closed(self):
        return self.state == self.CLOSED_STATE

    def dump_str(self):
        string = "fingerprint: {0} ; remainder: {1}".format(self.fingerprint, str(self))
        return string

    @staticmethod
    def _is_ip_addr_private(addr):
        """Determine if IP address addr is a private address."""
        is_private = False
        for regex in SocketInfo._private_regex:
            if regex.match(addr):
                is_private = True
                break
        return is_private
    
    @staticmethod
    def _hex2dec(hex_str):
        """Convert hex number in string hex_str to a decimal number string."""
        return str(int(hex_str, 16))
    
    @staticmethod
    def _ip(hex_str):
        """Convert IP address hex_str from hex format (e.g. "293DA83F") to decimal format (e.g. "64.244.27.136")."""
        dec_array = [
            SocketInfo._hex2dec(hex_str[6:8]), 
            SocketInfo._hex2dec(hex_str[4:6]), 
            SocketInfo._hex2dec(hex_str[2:4]), 
            SocketInfo._hex2dec(hex_str[0:2])
        ]
        dec_str = '.'.join(dec_array)
        return dec_str
    
    @staticmethod
    def _remove_empty(array):
        """Remove zero length strings from array."""
        return [x for x in array if x != '']
    
    @staticmethod
    def _convert_ip_port(hexaddr):
        """Convert IP address and port from hex to decimal; e.g. "293DA83F:0050" to ["64.244.27.136", "80"]."""
        host,port = hexaddr.split(':')
        return SocketInfo._ip(host),SocketInfo._hex2dec(port)
    
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
                deref = os.readlink(fd_link); 

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
    
class SocketFilter():
    """Base class for SocketInfo filters."""

    def filter_out(self):
        """Return False, to not filter out."""
        return False

class GenericFilter(SocketFilter):
    """GenericFilter is a SocketFilter that filters on properties of SocketInfo."""
    valid_parameter_names = ["pid", "exe", "cmdline", "cmdline_is_re", "user", "local_hosts", "local_ports", "remote_hosts", "remote_ports", "states"]

    def __init__(self, name, pid=None, exe=None, cmdline=None, cmdline_is_re=None, user=None, local_hosts=None, local_ports=None, remote_hosts=None, remote_ports=None, states=None):
        """Create a GenericFilter that filters out SocketInfos that match all the specified properties.

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
        remote_hosts -- If set, an array of IP addresses to filter on. A SocketInfo is filtered 
          out if its remote_host matches any of the addresses.
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
        self.remote_ports = GenericFilter._parse_list_string(remote_ports)
        self.states = GenericFilter._parse_list_string(states)

        # Create regular expression for cmdline
        self.cmdline_re = None
        if self.cmdline_is_re:
            self.cmdline_re = re.compile(self.cmdline)

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
        self._add_str_part(parts, 'remote_ports')
        self._add_str_part(parts, 'states')
        string = ''.join(parts)
        return string;                

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

    def _remote_host_filters_out(self, socket_info):
        """Return True if socket_info should be filtered out based on remote_host."""
        filter_out = True
        if not self.remote_hosts is None:
            host_name = socket_info.lookup_remote_host_name()
            for host in self.remote_hosts:
                if host_name.endswith(host):
                    filter_out = True
                    break
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
        filter_out = (
            self._pid_filters_out(socket_info) and 
            self._exe_filters_out(socket_info) and 
            self._cmdline_filters_out(socket_info) and
            self._user_filters_out(socket_info) and 
            self._local_host_filters_out(socket_info) and
            self._local_port_filters_out(socket_info) and
            self._remote_host_filters_out(socket_info) and
            self._remote_port_filters_out(socket_info) and
            self._state_filters_out(socket_info))
        return filter_out

class NetStat():
    """NetStat creates SocketInfo instances from lines in /proc/net/tcp and /proc/net/udp"""
    def __init__(self, netstat_id):
        """Create SocketInfo instances."""
        # Assign id.
        self.netstat_id = netstat_id

        # Load sockets 
        self.socket_infos = []
        self._load('tcp', PROC_TCP)
        self._load('udp', PROC_UDP)

    def _load(self, socket_type, path):
        """Create SocketInfo from either /proc/net/tcp or /proc/net/udp"""
        # Read the table of sockets & remove header
        with open(path, 'r') as proc_file:
            content = proc_file.readlines()
            content.pop(0)

        # Create SocketInfos. 
        for line in content:
            info = SocketInfo(socket_type, line)
            self.socket_infos.append(info)

class Monitor():
    """Monitor creates, filters, and reports SocketInfos at regular intervals."""
    _closing_states = ['FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'CLOSING']

    def __init__(self, interval = DEFAULT_MONITOR_INTERVAL, ignore_loopback = False, state_changes = False, filter_files = None):
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
            raise MonitorException("ERROR: Monitor interval needs to be at least {0}".format(MIN_MONITOR_INTERVAL))

        self._interval = interval
        self._ignore_loopback = ignore_loopback
        self._state_changes = state_changes
        self._seen = {}

        self._clean_counter = 0
        self._clean_interval = int(60 * CLEAN_INTERVAL / interval)

        self._netstat_id = 0

        # Check for root permissions, so filters work and connection details can be looked up.
        if os.geteuid() != 0:
            raise MonitorException("ERROR: Root permissions needed, to lookup connection details.")

        # Check python version.
        if sys.version_info.major != 3 or sys.version_info.minor < 2:
            raise MonitorException("ERROR: Python 3.2 or greater needed.")

        # Do a basic check of kernel version, by looking comparing /proc/net headers to expected headers.
        tcp_header = Monitor._read_first_line(PROC_TCP)
        udp_header = Monitor._read_first_line(PROC_UDP)
        if (tcp_header != "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode" or
            udp_header != "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"):
            raise MonitorException("ERROR: Unexpected /proc/net file format. This could be due to kernel version. Current kernel: {0}. Tested kernel: {1}.".format(
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
                        items = parser.items(section)
                        filter_params = {}
                        for pair in items:
                            # Check parameter name
                            param_name = pair[0].strip()
                            if not param_name in GenericFilter.valid_parameter_names:
                                raise MonitorException("ERROR: Unexpected filter parameter {0} for filter {1} in {2}.".format(
                                    param_name, section, file_name))
                        
                            # Record parameter
                            if param_name == "cmdline_is_re":
                                try:
                                    param_value = parser[section].getboolean("cmdline_is_re")
                                except ValueError:
                                    raise MonitorException("ERROR: Expecting true or false for cmdline_is_re for {0} in {1}".format(section, file_name))
                            else:
                                param_value = pair[1].strip()
                            filter_params[param_name] = param_value

                        # Create filter
                        generic_filter = GenericFilter(section, **filter_params)
                        self._filters.append(generic_filter)
                        # LOG
                        #print("filter: {0}".format(generic_filter))
                        #sys.stdout.flush()
                    except configparser.Error as ex:
                        raise MonitorException("ERROR: Parsing error creating {0} filter from file {1}: {2}.".format(section, file_name, str(ex)))
            except IOError as ex:
                raise MonitorException("ERROR: Unable to open file {0}: ({1})".format(file_name, str(ex)))
            except configparser.Error as ex:
                raise MonitorException("ERROR: Parsing error creating filters from file {0}: {1}.".format(file_name, str(ex)))

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

        # Display closed sockets.
        if self._state_changes:
            seen_values = list(self._seen.values())
            for seen_info in seen_values:
                if (seen_info.was_displayed and 
                    seen_info.last_seen != self._netstat_id and
                    not seen_info.is_closed()):

                    # Mark closed. 
                    seen_info.mark_closed()

                    # Update time.
                    seen_info.update_time()

                    # Display
                    print(str(seen_info))

                    # Remove from seen collection
                    del self._seen[seen_info.fingerprint]

        sys.stdout.flush()

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
        """Return True if a SocketInfo with same fingerprint as socket_info has already been seen."""
        seen_info = self.lookup_seen(socket_info)
        return not seen_info is None

    def _mark_seen(self, socket_info):
        """Record socket_info as seen."""
        socket_info.record_last_seen(self._netstat_id)
        self._seen[socket_info.fingerprint] = socket_info

    def _clean(self):
        """Discard seen SocketInfos that have ended, if CLEAN_INTERVAL has elapsed."""
        self._clean_counter += 1
        if self._clean_counter >= self._clean_interval:
            # LOG
            #before_count = len(self._seen.keys())
            keep = {}
            for socket_info in self._seen.values():
                if socket_info.last_seen == self._netstat_id:
                    keep[socket_info.fingerprint] = socket_info
            self._seen = keep
            self._clean_counter = 0
            # LOG
            #after_count = len(self._seen.keys())
            #print("clean: before {0}, after {1}".format(before_count, after_count))
            #sys.stdout.flush()

    def monitor(self):
        """Perform a NetStat every monitor_interval seconds."""
        # Print header
        print("Time            Proto ID  User     Local Address        Foreign Address      State       PID   Exe                  Command Line")
        sys.stdout.flush()

        while True:
            self._do_netstat()
            self._clean()
            time.sleep(self._interval)

def main():
    # Parse command line
    parser = argparse.ArgumentParser(prog='netstat-monitor', description='Monitor network connections.')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-i', '--ignore-loopback', action='store_true', help='Ignore connections to loopback address.')
    parser.add_argument('-m', '--monitor-interval', type=float, default=float(DEFAULT_MONITOR_INTERVAL),
        help='How often to check for new connections, in seconds.')
    parser.add_argument('-s', '--state-changes', action='store_true', help='Report connection state changes.')
    parser.add_argument('filter_file', nargs='*', help='Config file that defines filters')
    args = parser.parse_args()

    # Monitor
    return_code = 0
    try:
        monitor = Monitor(args.monitor_interval, args.ignore_loopback, args.state_changes, args.filter_file)
        monitor.monitor()
    except KeyboardInterrupt:
        print('')
    except MonitorException as ex:
        print(str(ex))
        return_code = ex.return_code

    exit(return_code)

