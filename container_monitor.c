// Licensed under the Apache License, Version 2.0 (the 'License')

// This code calculates disk and network traffic statistics and
//   use maps to pass them to userspace.

// This program is made by adapting code snippets
//   from iovisor/bcc/{examples,tools} and tweeking them
//   according to the requirement of the container monitoring
//   userspace program.
//   In particular, the two examples that are used heavily in this code are:
//     http_filter by mbertrone
//     disksnoop and fileslower by brendangregg
//
// Copyright 2016 Ali Khayam


#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/blkdev.h>

#define IP_TCP   6
#define ETH_HLEN 14

enum api_types {
    TCP = 1,
    HTTP_GET,
    HTTP_PUT,
    HTTP_POST,
    HTTP_DELETE
};

enum disk_type {
    VFS_READ = 1,
    VFS_WRITE
};

/*
  Key struct is for API hash table.
*/
typedef struct api_key {
    u32 sip;
    u32 dip;
    u16 sport;
    u16 dport;
    u32 api_type;
} api_key_t;

/*
  Key struct is for disk hash table.
  We will use process_id to corelate
  container to disk accesses.
*/
typedef struct disk_key {
    u32 process_id;
    u32 disk_type;
} disk_key_t;

/*
   This is a generic structure to save
   API/disk_access count and their respective
   bytes.
*/
typedef struct counter {
    u64 bytes;
    u64 count;
} counter_t;

/*
  These are the main tables that will record
  api/disk data in kernel for a userspace program to read.
*/
BPF_HASH(api_map, api_key_t, counter_t);
BPF_HASH(disk_map, disk_key_t, counter_t);

/*
  This function records vfs stats ( read/write bytes & total accesses ).
  It save them with respect to the requesting process ID so we can filter and
  categorize them according to their respective containers.
*/
static int vfs_func(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, u32 disk_type)
{
    disk_key_t key;
    key.process_id = bpf_get_current_pid_tgid();
    key.disk_type = disk_type;

    counter_t *value_ptr, value;
    value.bytes = 0;
    value.count = 0;

    struct dentry *de = file->f_path.dentry;
    if (de->d_iname[0] == 0)
        return 0;

    value_ptr = disk_map.lookup_or_init(&key, &value);
    value_ptr->bytes += count;
    value_ptr->count++;
    return 0;
}

int vfs_read_func(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return vfs_func(ctx, file, buf, count, VFS_READ);
}

int vfs_write_func(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return vfs_func(ctx, file, buf, count, VFS_WRITE);
}

/*
   Parse packet headers.
   Filter IP and TCP packets, having payload not empty
   and containing 'HTTP', 'GET', 'POST' ... as first bytes of payload
*/
int hdr_parse(struct __sk_buff *skb) {
    u8 *cursor = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    //filter IP packets (ethernet type = 0x0800)
    if (!(ethernet->type == 0x0800)) {
        return 1;
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    //filter TCP packets (ip next protocol = 0x06)
    if (ip->nextp != IP_TCP) {
        return 1;
    }

    u32 tcp_header_length = 0;
    u32 ip_header_length = 0;
    u32 payload_offset = 0;
    u32 payload_length = 0;

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    //calculate ip header length
    ip_header_length = ip->hlen << 2;
    tcp_header_length = tcp->offset << 2;

    //calculate patload offset and length
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    payload_length = ip->tlen - ip_header_length - tcp_header_length;

    //This drop is to ignore any ack/handshakes to reduce TCP traffic noise
    if(payload_length < 1) {
        return 1;
    }

    api_key_t key;
    key.sip = ip->src;
    key.dip = ip->dst;
    key.dport = tcp->dst_port;
    key.sport = tcp->src_port;
    key.api_type = TCP;

    counter_t *value_ptr, value;
    value.bytes = 0;
    value.count = 0;

    value_ptr = api_map.lookup_or_init(&key, &value);
    value_ptr->bytes += payload_length;
    value_ptr->count++;


    //http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
    //minimum length of http request is always geater than 7 bytes
    //avoid invalid access memory
    //include empty payload
    if(payload_length < 7) {
        return 1;
    }

    //load firt 7 byte of payload into p (payload_array)
    //direct access to skb not allowed
    unsigned long p[7];
    int i = 0;
    int j = 0;
    for (i = payload_offset ; i < (payload_offset + 7) ; i++) {
        p[j] = load_byte(skb , i);
        j++;
    }

    counter_t *http_value_ptr, http_value;
    http_value.bytes = 0;
    http_value.count = 0;
    //find a match with an HTTP message
    //GET
    if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
        key.api_type = HTTP_GET;
        http_value_ptr = api_map.lookup_or_init(&key, &http_value);
        http_value_ptr->bytes += payload_length;
        http_value_ptr->count++;
        return 1;
    }
    //POST
    if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
        key.api_type = HTTP_POST;
        http_value_ptr = api_map.lookup_or_init(&key, &http_value);
        http_value_ptr->bytes += payload_length;
        http_value_ptr->count++;
        return 1;
    }
    //PUT
    if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
        key.api_type = HTTP_PUT;
        http_value_ptr = api_map.lookup_or_init(&key, &http_value);
        http_value_ptr->bytes += payload_length;
        http_value_ptr->count++;
        return 1;
    }
    //DELETE
    if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
        key.api_type = HTTP_DELETE;
        http_value_ptr = api_map.lookup_or_init(&key, &http_value);
        http_value_ptr->bytes += payload_length;
        http_value_ptr->count++;
        return 1;
    }
    return 1;
}
