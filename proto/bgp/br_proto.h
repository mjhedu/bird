/*
 * br_proto.h
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BR_PROTO_H_
#define PROTO_BGP_BR_PROTO_H_

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"

#define MAX_PAYLOAD_SIZE	1024

#include <signal.h>

sigset_t gl_oldsigset;

#pragma pack(push, 4)

typedef struct base_ea_head
{
  uint16_t u1;
  uint16_t u2;
} base_ea_head;

typedef struct base_ea_payload
{
  struct base_ea_head server_flags;
  unsigned char data[];
} base_ea_payload;

typedef struct ea_event
{
  int code;
  u32 flags;
} ea_event;

#pragma pack(pop)

#include "brc_memory.h"

#include "proto/static/static.h"

#include "brc_net_io.h"

struct bgp_br_route
{
  struct static_route *r;
  net *n;
  struct prefix pfx;
  p_md_obj ref;
  __sock_o pso;
};

#define IS_FSETC(o, f) ((o & f)==f)

#define F_NET_NO_RX_PLP		(byte) 1

typedef struct generic_table
{
  mda r;
  hashtable_t *ht;
} gtable_t;

typedef struct gt_lwrap
{
  p_md_obj ref;
  uint32_t locks;
  void *ptr;
} gt_lwrap;


struct irc_srv_config
{
  char *hostname;
  ip_addr listen_add;
  ip_addr relay_listen_add;
  int listen_port;
  int relay_listen_port;
  struct prefix pfx;
  uint32_t max_hosts;
};

struct irc_srv_config _icf_global;

#endif /* PROTO_BGP_BR_PROTO_H_ */
