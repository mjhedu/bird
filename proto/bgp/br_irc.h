/*
 * br_irc.h
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BR_IRC_H_
#define PROTO_BGP_BR_IRC_H_

#include "brc_net_io.h"

int
irc_rx_translate (__sock_o pso, struct ___net_task *task);

#include "br_proto.h"

void
irc_brr_install (gtable_t *table, __sock_o pso);

#include "br_hasht.h"

typedef int
(*_irc_qc) (__sock_o pso, void *data);

/*
 struct irc_in_qc {
 _irc_qc handler;
 };*/

hashtable_t *irc_crf_in_table;

int
net_proto_irc_baseline (__sock_o pso, pmda base, pmda n, void *data);

typedef int
rx_handler (__sock_o pso, void *data);

rx_handler irc_c_user, irc_c_nick, irc_c_userhost, irc_c_dummy, irc_c_join,
    irc_c_part, irc_c_privmsg;

int
net_proto_irc_socket_init0 (__sock_o pso);
int
net_proto_irc_socket_destroy0 (__sock_o pso);

struct proto_irc_req *
irc_decode_request (char *data);
int
irc_send_simple_response (__sock_o pso, char *prefix, char *code, char *n,
			  char *trailer);

void
irc_hostname_assemble (__sock_o pso, char *b, size_t sz);
int
irc_ping (__sock_o pso, __net_task task);

#define F_RXP_GRACEFULL		(uint32_t) 1

int
irc_proto_rx_proc (net *n, uint32_t flags);

void
_irc_startup (__sock_ca ca);

#include "lib/ip.h"

#define IPL_MARK_UPDATE(ipl,f)  ipl->flags ^= ipl->flags & F_IRC_UPDATE; ipl->flags |= f;

int
irc_join_chan (__sock_o pso, char *chan);

typedef struct irc_srvctx
{
  gtable_t loc_chans;
  gtable_t map_nick_to_ipa;
} irc_srvctx;

irc_srvctx server_ctx;

typedef struct irc_pkasm_state
{
  mda base;
  uint32_t u1, u2;
  void *data;
} irc_pkasm_state;

typedef int
(*ifmtr_callback) (__sock_o pso, void *data);

#include "br_irc_proto.h"

int
irc_format_response_ex (__sock_o pso, struct proto_irc_resp *rsp,
			ifmtr_callback call, void *d);

typedef struct proto_irc_u
{
  struct proto_irc_u_config u_settings;
  uint32_t status;
  struct prefix net;
  gtable_t chans;
  p_md_obj ref;
} proto_irc_u;

int
irc_local_broadcast_to_chan (__sock_o self, char *name, char *data, size_t len);


#define MD_START(md,t) do {p_md_obj ptr=(md)->first;t *d;for(;ptr&&(d=(t *)ptr->ptr);ptr=ptr->next)
#define MD_START_N(md,t,n) do {p_md_obj ptr=(md)->first;t *n;for(;ptr&&(n=(t *)ptr->ptr);)
#define MD_END } while(0);

#define ERRMSG_IRC_G "%s: [%d]: "
#define ERRMSG_INVARG ERRMSG_IRC_G "invalid arguments"

#define IRC_C_ERRQUIT(c)  \
	    log(L_ERR ERRMSG_INVARG, r->cmd, pso->sock); \
	    pso->flags |= F_OPSOCK_TERM; return c;
#define IRC_C_ERRQUIT_M(c,m)  \
	    log(L_ERR ERRMSG_IRC_G m, r->cmd, pso->sock); \
	    pso->flags |= F_OPSOCK_TERM; return c;
#define IRC_C_QUIT_M(c,m,s)  \
	    log(L_ERR  "%s: [%d]: " m ": %s", r->cmd, pso->sock,s); \
	    return c;

int
irc_send_names (__sock_o pso, char *chan);

void
irc_proto_cache_n (net *n, irc_ea_payload *pl, uint32_t flags);


#define F_IRC_CACHE_REMOVE	(uint32_t)1
#define F_IRC_CACHE_UPDATE	(uint32_t)1 << 1

#define STR_HELPER(x) #x
#define _ST(x) STR_HELPER(x)


gtable_t br_routes;


gtable_t _ntglobal;


#define		DSP_CODE_IRC_MESSAGE	0x3C

int
irc_relay_message (__sock_o origin, int scope, char *code, char *target, char *message);

#endif /* PROTO_BGP_BR_IRC_H_ */
