# Netstat-monitor -- Monitor network connections on your system

## Description

Netstat-monitor is a command line tool for monitoring network connections. Its output is similar to the output from the netstat command with the options "netstat --inet -alp". Netstat-monitor can be left running, though, and will report new connections as they are made. Also, filters can be used to limit what's displayed to just what's unexpected or interesting.

## Installation

Netstat-monitor has been tested on Debian 11 Bullseye, which uses the Linux 5.10 kernel, but should work on other distros that have the same format for the socket files in `/proc/net` (`tcp`, `tcp6`, `udp`, and `udp6`.) Netstat-monitor does a quick preliminary check on start-up to see if those files have the expected header line. Previous versions of netstat-monitor were tested on Debian 7 (Wheezy) and Ubuntu 12.04, which were based on the Linux 3.2 kernel.

To clone the repo from GitHub and run netstat-monitor directly, on a Debian based distro:

    $ sudo apt-get install python3-netaddr
    $ cd /tmp
    $ git clone https://github.com/stalexan/netstat-monitor.git
    $ cd netstat-monitor
    $ ./netstat-monitor

Or, to create an installable package (tarball):

    $ sudo apt-get install python3-build
    $ cd /tmp
    $ git clone git@github.com:stalexan/netstat-monitor.git     
    $ cd netstat-monitor
    $ python3 -m build

This creates the tarball `netstat-monitor-1.1.4.tar.gz` in `./dist`. To install:

    $ sudo apt-get install python3-pip
    $ cd ./dist
    $ pip install netstat-monitor-1.1.4.tar.gz

This installs to ~/.local/bin. To run:

    $ ~/.local/bin/netstat-monitor

Or to instead install to /usr/local/bin run `pip install` as root:

    $ sudo pip install netstat-monitor-1.1.4.tar.gz

And then to run:

    $ netstat-monitor

## Running

To run:

    netstat-monitor

Here's some sample output:

    Time            Proto ID  User  Local Address        Foreign Address      State       PID   Exe                  Command Line
    Sep 16 14:20:50 tcp   1   root  0.0.0.0:22           0.0.0.0:0            LISTEN      875   /usr/sbin/sshd       /usr/sbin/sshd -D
    Sep 16 14:20:50 tcp   2   root  127.0.0.1:631        0.0.0.0:0            LISTEN      927   /usr/sbin/cupsd      /usr/sbin/cupsd -F
    Sep 16 14:56:13 tcp   3   root  192.168.1.4:22       other.com:41453      ESTABLISHED 24639 /usr/sbin/sshd       sshd: alice [priv]
    Sep 16 17:21:17 tcp   4   sean  192.168.1.4:32998    ocsp.entrust.net:80  ESTABLISHED 4872  /usr/sbin/firefox    /usr/sbin/firefox
    Sep 16 18:28:30 udp   5   root  0.0.0.0:1194         0.0.0.0:0            CLOSE       29906 /usr/sbin/openvpn    openvpn settings.ovpn
    Sep 16 18:39:42 udp   6   sean  192.168.1.4:48742    192.168.1.1:53       ESTABLISHED 31160 /usr/bin/ssh         ssh git@github.com git-receive-pack 'stalexan/netstat-monitor.git'

## Filters

Filters can be used to limit what's displayed to just unexpected or interesting connections. A typical use case is to run netstat-monitor without any filters at first, and then add filters over time until only interesting connections are displayed.

Filters are created in config files that are listed on the command line. For example:

    netstat-monitor sample-filters

The file [sample-filters](https://github.com/stalexan/netstat-monitor/blob/master/sample-filters) is provided with the install, and has some example filters. A few of them are:

    [ntpupdate]
    exe: /usr/sbin/ntpdate
    user: root

    [firefox]
    exe: /usr/lib/firefox/firefox
    user: alice 
    remote_ports: 53, 80, 443, 8080

    [upstart]
    exe: /sbin/upstart-udev-bridge
    user: root
    states = FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSE, CLOSE_WAIT, LAST_ACK, CLOSING

    [ignore-lan]
    remote_ips: 192.168.1.0/24  

Each section defines a new filter. A section starts with the filter name, enclosed in square brackets. The name can be any alphanumeric string. Each line after that defines a filter parameter. For example, the first section defines a filter called ntpupdate that has two parameters: exe and user. This filter will look for connections with exe set to /usr/sbin/ntpupdate and user set to root. Any connections with these settings will be filtered out, and not displayed.

The available filter parameters are:

* exe: The executable for the process that opened the connection.
* cmdline: The command line of the process that opened the connection.
* cmdline_is_re: Whether cmd_line is a regular expression (true/false). Default is false.
* pid: The pid of the process that opened the connection.
* user: The user for the process that opened the connection.
* local_hosts: Comma separated list of local hosts.
* local_ports: Comma separated list of local ports.
* remote_hosts: Comma separated list of remote hosts, specified with domain names. 
* remote_ips: Comma separated list of IP address ranges, in CIDR notation.
* remote_ports: Comma separated list of remote ports.
* states: Comma separated list of Connection states.

There's a command line parameter that acts as a kind of filter as well: --ignore-loopback. 
It will cause any connections on the loopback address (127.0.0.1) to be filtered out. 
By default it's false.

