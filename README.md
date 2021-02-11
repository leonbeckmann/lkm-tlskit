# LKM-TLSKIT

A Linux rootkit, based on a Linux Kernel Module.

> This rootkit has been developed on Linux kernel version 4.19.0-12-amd64
on Debian 10.6

## Features

* **Module hiding:** 

The kernel module is hidden from lsmod and /sys/module. This is done by remapping
the module's core layout such that the memory of the rootkit is unlinked from the kernel
module. It allows unloading the kernel module and destroying all the corresponding files,
while keeping the rootkit alive. This approach seems to be more stealthy than just hiding
the module via syscall hooking and removing the module from internal kernel lists.
        

## Build dependencies

`apt-get install linux-headers-$(uname -r)`

## Build

A Makefile is provided for building the kernel module rootkit and its user-space
control program:

``make``

## Installation

The installation of the tlskit is done via the user-space control program.
See ***load*** and ***unload*** in the **Usage** section.

## Usage
The rootkit can be controlled via a user-space control program. 

The rootkit control program supports the following commands:

* ***Ping:*** 

    Check if the rootkit is currently alive: 

    ``./rkctl ping``

* ***Load:***

    Load the kernel module and install the rootkit: 

    ``./rkctl load <module.ko>``

* ***Unload:***

    Unload the rootkit: 

    ``./rkctl unload``