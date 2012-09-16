=============================================================
Netstat-monitor -- Monitor network connections on your system
=============================================================

## Description

Netstat-monitor is a command line tool for monitoring network connections. Its output looks similar to the output from the netstat command with the options "netstat --inet -alp". One difference is that netstat-monitor can be left running, and will report new connections as they are made. Also, filters can be created to limit what's displayed to just what's unexpected or interesting.

## Installation

Netstat-monitor was written and tested on an Ubuntu 12.04 machine with Python 3.2. It should work fine on most recent distributions of Linux, though. 

Get the latest version:

    $ rm -rf /tmp/stalexan-netstat-monitor-*
    $ wget -O /tmp/netstat-monitor-last.tgz https://github.com/stalexan/netstat-monitor/tarball/master

Extract files:

    $ cd /tmp
    $ tar zxvf netstat-monitor-last.tgz
    $ cd stalexan-netstat-monitor-*

Install, on a Debian or Ubuntu machine:

    $ sudo apt-get update
    $ sudo apt-get install python3
    $ sudo python setup.py install

Or, the install step can be skipped and netstat-monitor can be run from the directory the files were extracted to. This doesn't put the files in their expected places, but should work fine.

## Running

To run:

    netstat-monitor

Here's some sample output:

    Time            Proto ID  User  Local Address        Foreign Address      State       PID   Exe                  Command Line
    Sep 16 14:20:50 tcp   1   root  0.0.0.0:22           0.0.0.0:0            LISTEN      875   /usr/sbin/sshd       /usr/sbin/sshd -D
    Sep 16 14:20:50 tcp   2   root  127.0.0.1:631        0.0.0.0:0            LISTEN      927   /usr/sbin/cupsd      /usr/sbin/cupsd -F
    Sep 16 14:56:13 tcp   3   root  192.168.1.4:22       other.com:41453      ESTABLISHED 24639 /usr/sbin/sshd       sshd: alice [priv]
    Sep 16 17:21:17 tcp   4   sean  192.168.1.4:32998    ocsp.entrust.net:80  ESTABLISHED 4872  /usr/sbin/firefox    /usr/sbin/firefox
    Sep 15 14:28:30 udp   5   root  0.0.0.0:1194         0.0.0.0:0            CLOSE       29906 /usr/sbin/openvpn    openvpn settings.ovpn
    Sep 15 14:39:42 udp   6   sean  192.168.1.4:48742    192.168.1.1:53       ESTABLISHED 31160 /usr/bin/ssh         ssh git@github.com git-receive-pack 'stalexan/netstat-monitor.git'

## Filters

By default netstat-monitor will report all connections.  TODO

