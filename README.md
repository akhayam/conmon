# Installing BCC

* [Introduction](#introduction)
* [Install IO Visor](#iovisor-install)
* [Install pyroute2](#pyroute-install)
* [Usage](#usage)

## Introduction
Conmon is a container monitoring tool that uses ebpf's
tracing capabilities to provide in-kernel hooks for monitoring 
network traffic and disk activities.
A userspace utility loads the kernel-space program using IO Visor BCC tools,
reads the IO Visor maps periodically, and correlates the
traffic and disk activity to specific containers.

## Install IO Visor

Following are instructions for Ubuntu Xenial (16.04) installation of iovisor/bcc:

```bash
echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools
```

For other operating systems, see the iovisor installation page: https://github.com/iovisor/bcc/blob/master/INSTALL.md

## Install pyroute2

Install pyroute2:

```bash
sudo pip install pyroute2
```

## Usage

General usage instructions are as follows:
```bash
sudo python container_monitor.py -h
usage: container_monitor.py [-h] [-d DOCKER_INFO] [-l LXC_INFO]
                            [-i MAP_POLLING_INTERVAL]

Container Monitor Tool.

optional arguments:
  -h, --help            show this help message and exit
  -d DOCKER_INFO        Specify comma-seperated dockers pid's and veth names as
                        strings in format veth:pid
  -l LXC_INFO           Specify comma-seperated lxc names as strings
  -i MAP_POLLING_INTERVAL

```

The specific command for docker containers would look like:
```bash
sudo python container_monitor.py -d DOCKER_VETH_NAME_1:DOCKER_PID_1, ..., DOCKER_VETH_NAME_n:DOCKER_PID_n 
```
The docker PID can be obtained by:
```bash
docker ps # <docker_pid> will be given in the "CONTAINER ID" column
ps aux | grep <docker_pid>
```
veth name can be obtained by running ```ifconfig```.

The command for LXC containers would be:
```bash
sudo python container_monitor.py -l LXC_NAME_1, ..., LXC_NAME_n 
```
Note that in the LXC case we do not need to specify veth interfaces.
The default polling interval to read from kernel space is 60 sec.

The values read from ebpf maps are printed in log files in the folder where the program is running.
A separate log file will be generated for each container with the name 'veth:pid.log' for dockers
and 'lxc_name.log' for LXCs.

```bash
time=1477510449.34:
<data-type>, <src-ip>, <dst-ip>, <src-port>, <dst-port>: <total-bytes>, <total-pkts>
TCP_DATA, 172.17.0.1, 172.17.0.2, 37626, 3306: 917, 6
<data-type>, <pid>: <total-bytes>, <total-disk-access>
VFS_WRITE, 9896: 64541330, 4147
VFS_READ, 9896: 43287429, 2662
```

