=============================================================
Netstat-monitor -- Monitor network connections on your system
=============================================================

## Description

Netstat-monitor is a command line tool for monitoring network connections. Its output looks similar to the output from the netstat command, when netstat is run with the options "netstat --inet -alp". One difference is that netstat-monitor can be left running, and it will report new connections as they are made. Also, filters can be created to limit what's displayed to just what's unexpected or interesting.

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

The install step is not necessary, though. Netstat-monitor can be run directly from the directory the files were extracted to.

## Running

To run:

    netstat-monitor

## Filters

By default netstat-monitor will report all connections.  <TODO>

