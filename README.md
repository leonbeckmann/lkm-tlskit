# LKM-TLSKIT

A Linux rootkit, based on a Linux Kernel Module.

> This rootkit has been developed on Linux kernel version 4.19.0-12-amd64
on Debian 10.6

## Features

## Build dependencies

`apt-get install linux-headers-$(uname -r)`

## Build

A Makefile is provided for building the kernel module rootkit and its user-space
control program:

``make``

## Installation

Insert the kernel module rootkit:

``insmod tlskit.ko``

Remove the kernel module rootkit:

``rmmod tlskit``

## Usage

