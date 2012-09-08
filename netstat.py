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

MONITOR_INTERVAL -- How often Monitor collects netstat snapshots, in seconds.
CLEAN_INTERVAL -- How often the list of connections is reset, in minutes.
LOOKUP_REMOTE_HOST_NAME -- Whether to convert IP addresses to host names.

"""

import time
import datetime
import sys
import pwd
import os
import re
import glob
import socket
import errno

MONITOR_INTERVAL =    1 # Number of seconds between each netstat.
CLEAN_INTERVAL =     60 # Number of minutes "seen" list grows before being cleaned out.

LOOKUP_REMOTE_HOST_NAME = True # Whether to convert IP addresses to host names by doing a hosth name lookup.

PROC_TCP = "/proc/net/tcp"
PROC_UDP = "/proc/net/udp"

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
    socket_id -- The kernel hash slot for the socket.
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

    _state_mappings = { '01' : 'ESTABLISHED', '02' : 'SYN_SENT', '03' : 'SYN_RECV', '04' : 'FIN_WAIT1',
        '05' : 'FIN_WAIT2', '06' : 'TIME_WAIT', '07' : 'CLOSE', '08' : 'CLOSE_WAIT',
        '09' : 'LAST_ACK', '0A' : 'LISTEN', '0B' : 'CLOSING' }

    _private_regex = [ re.compile(ex) for ex in [
        '^127.\d{1,3}.\d{1,3}.\d{1,3}$',
        '^10.\d{1,3}.\d{1,3}.\d{1,3}$',
        '^192.168.\d{1,3}$',
        '172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$']]

    _next_uid = 1

    def __init__(self, socket_type, line):
        """Create a SocketInfo of type socket_type from line.

        Keyword arguments:
        socket_type -- tcp or udp
        line -- line from either /proc/net/tcp or /proc/net/udp
        monitor -- Monitor instance used to filter and report SocketInfo instances. Optional.

        """
        self.socket_type = socket_type
        self.line = line
        self._line_array = SocketInfo._remove_empty(line.split(' '))

        # Determine fingerprint. 
        self.socket_id = self._line_array[0][:-1] # Remove trailing colon.
        self.inode = self._line_array[9]
        self.fingerprint = '{0} {1} {2}'.format(self.socket_type, self.socket_id, self.inode)

    def finish_initializing(self):
        """Finish initializing. Only needed if this SocketInfo will be kept."""

        # Default UID. Assign later if SocketInfo is reported to user.
        self.uid = 0

        # State
        self.state = SocketInfo._state_mappings[self._line_array[3]]

        # Time
        self.time = datetime.datetime.now();

        # User ID
        self._user_id = self._line_array[7]

        # Addresses
        self.local_host,self.local_port = SocketInfo._convert_ip_port(self._line_array[1])
        self.remote_host,self.remote_port = SocketInfo._convert_ip_port(self._line_array[2]) 

        # Save rest of lookup for "lookup" methods, since expensive and info
        # may not be needed if filtered out.
        self._user = None
        self._pid = None
        self._pid_looked_up = False
        self._exe = None
        self._cmdline = None
        self._remote_host_name = None

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

        # DEBUG_PRINT
        #print("_get_pid_of_inode(): inode {0}".format(inode))
        #sys.stdout.flush()

        pid = None
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

                # Does the dereferenced link have inode in it?
                if re.search(inode, deref):
                    # If so, PID has been found.
                    pid = fd_link.split('/')[2]
                    break

            except OSError as ex:

                # DEBUG_PRINT
                #message = 'PID search exception: inode {0}, fd_link {1}, deref {2}: {3}'.format(
                #   inode, fd_link, str(deref), str(ex))
                #print(message)
                #sys.stdout.flush()

                # "No such file or directory" is expected. Connection ended in between glob.glob() and readlink().
                # Often happens with udp sockets; e.g. for a DNS lookup.
                if ex.errno != errno.ENOENT:
                    raise ex
        
        # DEBUG_PRINT
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

    def __init__(self, pid=None, exe=None, cmdline=None, user=None, local_hosts=None, local_ports=None, remote_hosts=None, remote_ports=None, states=None):
        """Create a GenericFilter that filters out SocketInfos that match all the specified properties.

        All arguments are optional. Arguments that aren't set default to None, for "don't care." 
        Arguments that are set cause a SocketInfo to be filtered out if all attributes of the
        SocketInfo match the attributes of the arguments set.

        Keyword arguments:

        pid -- If set, pid that a SocketInfo must match to be filtered out.
        exe -- If set, exe that a SocketInfo must match to be filtered out.
        cmdline -- If set, cmdline that a SocketInfo must match to be filtered out.
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

        self.pid = pid 
        self.exe = exe
        self.cmdline = cmdline
        self.user = user
        self.local_hosts = local_hosts
        self.local_ports = local_ports
        self.remote_hosts = remote_hosts
        self.remote_ports = remote_ports
        self.states = states

    def __str__(self):
        string = 'pid: {0}, exe: {1}, cmdline: {2}, user: {3}, local_hosts: {4}, local_ports: {5}, remote_hosts: {6}, remote_ports: {7}, states: {8}'.format(
            self.pid, self.exe, self.cmdline, self.user, self.local_hosts, self.local_ports, self.remote_hosts, self.remote_ports, self.states)
        return string;                

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
            filter_out = socket_cmdline == self.cmdline
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
        self.netstat_id = netstat_id
        self.socket_infos = []

        # Load sockets 
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

    def __init__(self, interval = MONITOR_INTERVAL, filters = None):
        """Create a Monitor that monitors every interval seconds using the specified filters."
        
        Keyword arguments:

        interval -- Number of seconds between each time Monitor creates a Netstat. Defaults
          to MONITOR_INTERVAL.
        filters -- List of filters to limit what SocketInfos are displayed to the user. Any 
          SocketInfos that match a filter are not displayed. Optional.

        """
        self._interval = interval
        self._filters = filters
        self._seen = {}

        self._clean_counter = 0
        self._clean_interval = int(60 * CLEAN_INTERVAL / interval)

        self._next_netstat_id = 1

    def _do_netstat(self):
        """Create a NetStat, filter out SocketInfos, and report."""
        # Lookup all current sockets.
        netstat = NetStat(self._next_netstat_id)
        self._next_netstat_id += 1

        # Process results.
        for socket_info in netstat.socket_infos:
            # Determine whether to display socket.
            filter_out = self._filter_socket(socket_info)

            # Display socket.
            if not filter_out:
                if LOOKUP_REMOTE_HOST_NAME:
                    socket_info.lookup_remote_host_name()
                socket_info.assign_uid()
                print(str(socket_info))
                sys.stdout.flush()

    def _filter_socket(self, socket_info):
        """Return true if socket should be filtered out; i.e. not displayed to user."""

        # Has this SocketInfo already been seen?
        seen_info = self.lookup_seen(socket_info)
        if not seen_info is None:
            return True

        # Finish initializing SocketInfo.
        socket_info.finish_initializing()

        # Filter out if PID was not found. PID can be missing if process exited in between the time
        # when the socket's inode was found and when the search for the socket's PID was made. 
        # (See OSError exception handler in _get_pid_of_inode().) Sometimes this is because of a 
        # short lived socket; e.g. UDP sockets for things such as DNS lookups. Other times, 
        # it's because the process did an exec and the inode for the socket is now owned by 
        # the child process. The PID for the child should be found the next time Monitor does 
        # a NetStat, assuming the child doesn't exit too. Not all sockets will be seen, depending 
        # on what MONITOR_INTERVAL is set to. A NetStat is done every MONITOR_INTERVAL seconds. The 
        # default for MONITOR_INTERVAL is 1 second, so most connections (especially TCP connections) 
        # should be seen.
        pid = socket_info.lookup_pid()
        if pid is None:
            return True

        # Mark SocketInfo as seen, so overhead of processing isn't done again.
        self._mark_seen(socket_info)

        # Filter out any closing connections that have been turned over to init. 
        if pid == "1" and socket_info.state in Monitor._closing_states:
            return True

        # Check filters provided by user.
        if not self._filters is None:
            for socket_filter in self._filters:
                if socket_filter.filter_out(socket_info):
                    return True

        return False

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
        self._seen[socket_info.fingerprint] = socket_info

    def _clean(self):
        """Discard seen SocketInfos if CLEAN_INTERVAL has passed."""
        self._clean_counter += 1
        if self._clean_counter >= self._clean_interval:
            self._seen = {}
            self._clean_counter = 0
            print('*** cleaned ***')
            sys.stdout.flush()

    def monitor(self):
        """Perform a NetStat every MONITOR_INTERVAL seconds."""
        # Print header
        print("Time            Proto ID  User     Local Address        Foreign Address      State       PID   Exe                  Command Line")
        sys.stdout.flush()

        while True:
            self._do_netstat()
            self._clean()
            time.sleep(self._interval)

