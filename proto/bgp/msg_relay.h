/*
 * msg_relay.h
 *
 *  Created on: Apr 16, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_MSG_RELAY_H_
#define PROTO_BGP_MSG_RELAY_H_

#define PROT_CODE_RELAY 0x11

#include "brc_net_io.h"
#include "br_proto.h"

gtable_t msg_relay_socks;

#include "lib/ip.h"

#include "br_net_proto.h"

#pragma pack(push, 4)

typedef struct __mrl_data_packet
{
  _bp_header head;
  uint8_t code;
  uint8_t delivery_code;
  uint8_t ttl;
  struct prefix source;
  struct prefix dest;
  uint32_t data_len;
  uint8_t data[];
} mrl_dpkt;

#pragma pack(pop)

void
_mrl_startup (__sock_ca ca);

#define PROT_RELAY_AUTH		0x3
#define PROT_RELAY_FORWARD	0x7

#include "proto/bgp/bgp.h"

int
mrl_open_conn (struct bgp_proto *p, ip_addr ip, int port, __sock_ca ca);

typedef int
(*dsp_proc) (__sock_o pso, void *data);

struct mrl_dspobj
{
  dsp_proc proc;
  void *data;
};

void
dsp_register (struct mrl_dspobj *r, uint8_t code, dsp_proc proc, void *data);
struct mrl_dspobj *
dsp_lookup (struct mrl_dspobj *r, uint8_t code);

struct mrl_dspobj dsp_table[UCHAR_MAX];

int
net_baseline_relay_dispatcher (__sock_o pso, mrl_dpkt *pkt);
struct rte *
mrl_baseline_lookup_best_path (net *n);

#endif /* PROTO_BGP_MSG_RELAY_H_ */
