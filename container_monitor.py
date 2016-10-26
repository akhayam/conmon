#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
# This code correlate container INGRESS packets with disk access

from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute, IPDB
import socket
import time
import subprocess
import struct
import traceback
import os.path
import argparse

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

def get_all_pids_of_container(container_pid):
    pid_cmd = [ 'bash', '-c', '. getcpid.sh; getcpid ' + container_pid ]
    pid_cmd_output = subprocess.check_output(pid_cmd)
    res = filter( bool, pid_cmd_output.split('\n') )
    return map ( int, res )

def get_docker_info(docker_details):
    info = docker_details.split(':')
    return info[1], info[0]

def get_lxc_info(lxc_name):
    info_cmd = [ 'bash', '-c', 'lxc-info --name ' + lxc_name ]
    cmd_output = subprocess.check_output(info_cmd).split('\n')
    pid = filter(bool, cmd_output[2].split(' '))[1]
    veth = filter(bool, cmd_output[8].split(' '))[1]
    return pid, veth

def get_api_types(number):
    return {
      1:'TCP_DATA',
      2:'HTTP_GET',
      3:'HTTP_PUT',
      4:'HTTP_POST',
      5:'HTTP_DELETE',
    }[number]

def get_disk_access_type(number):
    return {
      1:'VFS_READ',
      2:'VFS_WRITE',
      3:'BLK_READ',
      4:'BLK_WRITE',
    }[number]

def write_api_table_and_reset(api_map, tracefile):
    for key in api_map:
        try:
            tracefile.write('%s %s, %s, %d: %d, %d\n' % (get_api_types(key.api_type),
              socket.inet_ntoa(struct.pack('=L',socket.htonl(key.sip))),
              socket.inet_ntoa(struct.pack('=L', socket.htonl(key.dip))),
              key.dport, api_map[key].bytes, api_map[key].count))
        except Exception:
            traceback.print_exc()
    api_map.clear()

def write_disk_table_and_reset(disk_map, pid_list, total_containers, tracefile):
    for key in disk_map:
        for container_number in range(0, total_containers):
            try:
                if key.process_id in pid_list[j]:
                    tracefile[j].write('%s %s: %d, %d\n' %
                      (get_disk_access_type(key.disk_type),
                      key.process_id, disk_map[key].bytes,
                      disk_map[key].count))
            except Exception:
                traceback.print_exc()
    disk_map.clear()

container_names = []
total_containers = 0
container_details = []
container_interface = []
logfile_names = []
bpf_programs = []
logfiles = []
pkt_monitors = []

parser = argparse.ArgumentParser(description='container monitor tool.')
parser.add_argument('-d', action='store', dest='docker_info',
                    help='''Specify comma seperated dockers pid
                    and veth name as sting in format PID:veth''')
parser.add_argument('-l', action='store', dest='lxc_info',
                    help='Specify comma seperated lxcs name as string')
parser.add_argument('-i', action='store', dest='map_polling_interval', default=60,
                    type=int, help='Specify maps polling interval')
args = parser.parse_args()

if args.docker_info:
    container_names = args.docker_info.split(',')
elif args.lxc_info:
    container_names = args.lxc_info.split(',')
else:
    parser.error("Specify either docker info or lxc info, use -h for more details")


for name in container_names:
    if args.docker_info:
        container_details.append(get_docker_info(name))
    elif args.lxc_info:
        container_details.append(get_lxc_info(name))
    logfile_names.append(name)
    container_interface.append(ipdb.interfaces[container_details[total_containers][1]])
    bpf_programs.append(BPF(src_file = "container_monitor.c", debug = 0))
    logfiles.append(open(logfile_names[total_containers]+".log", "a+", 0))
    pkt_monitors.append(bpf_programs[total_containers].load_func("hdr_parse", BPF.SCHED_CLS))
    total_containers += 1

bpf_programs[0].attach_kprobe(event="vfs_read", fn_name="vfs_read_func")
bpf_programs[0].attach_kprobe(event="vfs_write", fn_name="vfs_write_func")

bpf_programs[0].attach_kprobe(event="blk_start_request", fn_name="io_trace_start")
bpf_programs[0].attach_kprobe(event="blk_mq_start_request", fn_name="io_trace_start")
bpf_programs[0].attach_kprobe(event="blk_account_io_completion", fn_name="io_trace_completion")

for j in range(0, total_containers):
    ipr.tc("add", "sfq", container_interface[j].index, "1:")
    ipr.tc("add-filter", "bpf", container_interface[j].index, ":1", fd=pkt_monitors[j].fd,
      name=pkt_monitors[j].name, parent="1:", action="ok", classid=1)

try:
    while (1):
        container_pid_list = []
        time.sleep(args.map_polling_interval)
        for j in range(0, total_containers):
            logfiles[j].write("time=%s:\n" % time.time())
            container_pid_list.append(get_all_pids_of_container(container_details[j][0]))

        for j in range(0, total_containers):
            api_map = bpf_programs[j]["api_map"]
            if len(api_map) > 0:
                write_api_table_and_reset(api_map, logfiles[j])

        disk_map = bpf_programs[0]["disk_map"]
        if len(disk_map) > 0:
            write_disk_table_and_reset(disk_map, container_pid_list, total_containers, logfiles)

except Exception as e:
    traceback.print_exc()
finally:
    for j in range(0, total_containers):
        ipr.tc("del", "sfq", container_interface[j].index, "1:")
