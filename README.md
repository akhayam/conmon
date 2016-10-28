# Installing BCC

* [Install IO Visor](#iovisor-install)
* [Install pyroute2](#pyroute-install)
* [Usage](#usage)

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

The command for LXC containers would be:
```bash
sudo python container_monitor.py -l LXC_NAME_1, ..., LXC_NAME_n 
```
Note that in the LXC case we do not need to specify veth interfaces.
