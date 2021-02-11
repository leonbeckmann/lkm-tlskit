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
     
* **SYSCALL hooking:**

The rootkit supports syscall hooking by redirecting syscalls from the user-space to 
a faked syscall table. In this ways, integrity checks on the syscall table will pass, since
the original syscall table will never be modified. In contrast, integrity checks on the
code itself will detect the rootkit, but due to runtime-patching of the kernel, 
this is more difficult to achieve.

The technique uses pattern matching on assembly code, starting at the address where the 
LSTAR MSR register points to (either entry_SYSCALL_64 or entry_SYSCALL_64_trampoline).

When the pattern matching fails (e.g. when different compiler versions are used that 
implements different optimizations) we will simply override the syscall table instead,
which is less stealthy and allows rootkit detection via syscall table integrity checks. 

* **Privilege Escalation via Backdoor:**

Execute an arbitrary program as root.

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
    
* ***Backdoor:***

    Run an arbitrary program as root (e.g. root shell via /bin/sh): 

    ``./rkctl backdoor <program>``