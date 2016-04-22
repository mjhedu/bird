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
    irc_c_part, irc_c_privmsg, irc_c_whois, irc_c_ping, irc_c_userip,
    irc_c_cmodeis;

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
irc_proto_proc_update (net *n, uint32_t flags);

void
_irc_startup (pmda bpca);

#include "lib/ip.h"

#define IPL_MARK_UPDATE(ipl,f)  ipl->flags ^= ipl->flags & F_IRC_UPDATE; ipl->flags |= f;

int
irc_join_chan (__sock_o pso, char *chan);

typedef struct irc_srvctx
{
  gtable_t loc_chans;
  gtable_t map_nick_to_ipa;
  gtable_t map_chan_to_ipas;
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

#define ERRMSG_IRC_G "%s: [%d]: "
#define ERRMSG_INVARG ERRMSG_IRC_G "invalid arguments"

#define IRC_C_ERRQUIT(c)  \
	    log(L_ERR ERRMSG_INVARG, r->cmd, pso->sock); \
	    net_proto_irc_close_link(pso, "invalid arguments"); return c;
#define IRC_C_ERRQUIT_M(c,m)  \
	    log(L_ERR ERRMSG_IRC_G m, r->cmd, pso->sock); \
	    net_proto_irc_close_link(pso, m); return c;
#define IRC_C_QUIT_M(c,m,s)  \
	    log(L_ERR  "%s: [%d]: " m ": %s", r->cmd, pso->sock,s); \
	    return c;

int
irc_send_names (__sock_o pso, char *chan);

#define F_IRC_CACHE_REMOVE	(uint32_t)1
#define F_IRC_CACHE_UPDATE	(uint32_t)1 << 1

#define STR_HELPER(x) #x
#define _ST(x) STR_HELPER(x)

gtable_t br_routes;

gtable_t _ntglobal;

#define		DSP_CODE_IRC_MESSAGE	0x3C

int
irc_relay_message (__sock_o origin, int scope, char *code, char *target,
		   char *message);

#define M1_CSTRING(m,a) char _b[1024]; snprintf(_b, sizeof(_b), m, a);

struct ipc_gch
{
  ip_addr ipa;
  p_md_obj bref;
};

#define C_PRELOAD(n, c)   int n(__sock_o pso,void *data){ \
			struct proto_irc_u *uirc=pso->va_p1;struct proto_irc_req *r=(struct proto_irc_req *)data; \
			if (r->cmd_params.offset c) { IRC_C_ERRQUIT(1) } \
			char *subject = r->cmd_params.first ? (char*) r->cmd_params.first->ptr : NULL; \
			size_t slen = subject ? strlen (subject) : 0; \
			if (subject ) { if ( !slen ) { IRC_C_ERRQUIT(1) };}

#define GET_NET_NAME(nm) char net_name[MAX_CL_NAME_LEN]; \
			snprintf (net_name, MAX_CL_NAME_LEN, "%s", nm); \
			str_to_lower (net_name);

int
irc_send_ping (__sock_o pso, time_t t);
void
net_proto_irc_close_link (__sock_o pso, char *msg);
int
irc_proto_validate_update (net *n, struct rte *new);

struct irc_srv_config
{
  char *hostname;
  char *netname;

  char *default_ssl_key;
  char *default_ssl_cert;
  char *default_ssl_ca;
  char *default_ssl_cipher_list;

  _sock_ca ca_relay;

  ip_addr listen_add;

  int listen_port;

  uint32_t max_hosts;
  uint32_t relay_sock_in_flags;

  mda binds;
  struct prefix pfx;
};

struct irc_srv_config _icf_global;

#endif /* PROTO_BGP_BR_IRC_H_ */
