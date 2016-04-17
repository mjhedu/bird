/*
 * msg_relay.c
 *
 *  Created on: Apr 16, 2016
 *      Author: reboot
 */

#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>

#include "nest/bird.h"
#include "sysdep/unix/unix.h"
#include "proto/bgp/bgp.h"

#include "brc_net_io.h"
#include "br_proto.h"
#include "br_net_proto.h"
#include "msg_relay.h"

gtable_t msg_relay_socks =
  {

    { 0 } };

struct mrl_dspobj dsp_table[UCHAR_MAX] =
  {
    { 0 } };

void
dsp_register (struct mrl_dspobj *r, uint8_t code, dsp_proc proc, void *data)
{
  struct mrl_dspobj * obj = &r[code];
  obj->proc = proc;
  obj->data = data;
}

struct mrl_dspobj *
dsp_lookup (struct mrl_dspobj *r, uint8_t code)
{
  struct mrl_dspobj *p = &r[code];
  if (p->proc)
    {
      return p;
    }
  else
    {
      return NULL;
    }
}

static void
net_baseline_decrease_ttl (mrl_dpkt *pkt)
{
  if (pkt->ttl)
    {
      pkt->ttl--;
    }
}

struct rte *
mrl_baseline_lookup_best_path (net *n)
{
  struct bgp_proto *p;
  struct rte *routes = n->routes;

  while (routes)
    {
      p = (struct bgp_proto *) routes->attrs->src->proto;

      if (p && p->rlink_sock) // must have a relay connection
	{
	  break;
	}
      routes = routes->next;
    }

  return routes;
}

int
net_baseline_relay_dispatcher (__sock_o pso, mrl_dpkt *pkt)
{
  net_baseline_decrease_ttl (pkt);

  if (!pkt->ttl)
    {
      log (
	  L_DEBUG "net_baseline_relay_dispatcher: [%d]: TTL exceeded on packet from %I",
	  pso->sock, pkt->dest);

      return 1; // TTL exceeded
    }

  net *n = net_find (brc_st_proto->c.proto->table, pkt->dest.addr,
		     pkt->dest.len);

  if (!n || !n->routes)
    {
      return 1; // unreachable
    }

  if (!n->routes->attrs)
    {
      return 1; // ??
    }

  if (n->routes->attrs->source == RTS_STATIC) // deliver locally
    {
      if (!n->n.pso)
	{
	  log (
	      L_ERR "net_baseline_relay_dispatcher: [%d]: fixme: local path with no socket",
	      pso->sock);
	  abort ();
	}

      struct mrl_dspobj *dso = dsp_lookup (dsp_table, pkt->delivery_code);

      if (dso)
	{
	  return dso->proc (n->n.pso, (void*) pkt);
	}
      else
	{
	  return -2;
	}
    }
  else if (n->routes->attrs->source == RTS_BGP) // forward
    {
      struct rte *routes = mrl_baseline_lookup_best_path (n);

      if (routes)
	{

	  struct bgp_proto *p = (struct bgp_proto *) routes->attrs->src->proto;

	  log (
	      L_DEBUG "net_baseline_relay_dispatcher: [%d->%d]: forwarding from %I to %I",
	      pso->sock, p->rlink_sock->sock, pkt->source.addr, pkt->dest.addr);

	  return net_send_direct (p->rlink_sock, (void*) pkt,
				  pkt->head.content_length);
	}
      else
	{
	  log (
	  L_ERR,
	       "net_baseline_relay_dispatcher: [%d]: no available paths to %I",
	       pso->sock, pkt->dest.addr);
	  return 1;
	}
    }

  return 0;

}

static int
net_baseline_relay (__sock_o pso, pmda base, pmda threadr, void *data)
{

  if (pso->counters.b_read < pso->unit_size)
    {
      return -2;
    }

  mrl_dpkt *pkt = data;

  switch (pkt->code)
    {
    case PROT_RELAY_FORWARD:
      ;
      net_baseline_relay_dispatcher (pso, data);
      break;
    case PROT_RELAY_AUTH:
      ;
      break;
    }

  net_proto_reset_to_baseline (pso);

  return 0;
}

static int
mrl_sock_keepalive (__sock_o pso, __net_task task)
{
  time_t t = time (NULL);
  if (pso->policy.idle_timeout
      && (t - pso->timers.l_rx) >= pso->policy.idle_timeout / 2
      && t - pso->timers.l_ping > pso->policy.idle_timeout / 2)
    {
      pso->timers.l_ping = t;

      _bp_header bp =
	{ .prot_code = PROT_CODE_BASELINE_KEEPALIVE, .content_length =
	    sizeof(_bp_header) };

      net_send_direct (pso, &bp, sizeof(bp));
    }

  return 0;

}

static void
mrl_apply_default_policy (__sock_ca ca)
{
  ca->policy.ssl_accept_timeout = 30;
  ca->policy.accept_timeout = 30;
  ca->policy.ssl_connect_timeout = 30;
  ca->policy.connect_timeout = 30;
  ca->policy.idle_timeout = 240;
  ca->policy.close_timeout = 30;
  ca->policy.send_timeout = 30;
  ca->policy.max_sim_ip = 5;
  ca->policy.connect_retry_timeout = 30;

}

void
mrl_init_ca_default (__sock_ca ca)
{
  md_init (&ca->init_rc0, 16);
  md_init (&ca->init_rc1, 16);
  md_init (&ca->shutdown_rc0, 16);
  md_init (&ca->shutdown_rc1, 16);
  md_init (&ca->c_tasks, 16);
  md_init (&ca->ct_tasks, 16);
  md_init (&ca->t_tasks, 16);
  md_init (&ca->t_rcv, 2);
  md_init (&ca->c_pre_tasks, 16);
}

void
mrl_free_ca_default (__sock_ca ca)
{
  md_g_free (&ca->init_rc0);
  md_g_free (&ca->init_rc1);
  md_g_free (&ca->shutdown_rc0);
  md_g_free (&ca->shutdown_rc1);
  md_g_free (&ca->c_tasks);
  md_g_free (&ca->ct_tasks);
  md_g_free (&ca->t_tasks);
  md_g_free (&ca->t_rcv);
  md_g_free (&ca->c_pre_tasks);
}

static void
mrl_find_in_proto (struct proto *p, unsigned int verbose, int cnt, void *data)
{
  __sock_o pso = data;

  if (!(p->proto->name[0] == 0x42 && p->proto->name[1] == 0x47))
    {
      return;
    }

  struct bgp_proto *bgp = (struct bgp_proto*) p;

  if (!memcmp (&pso->ipr.ip, &bgp->cf->remote_ip, sizeof(ip_addr)))
    {
      bgp->rlink_sock = pso;
      pso->st_p0 = bgp;
      log (L_DEBUG "net_mrl_init: [%d]: relay link inbound: %I", pso->sock,
	   *((ip_addr*) &pso->ipr.ip));
    }

}

static int
net_mrl_init (__sock_o pso)
{
  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;

      if (pso->flags & F_OPSOCK_IN)
	{
	  proto_enum (mrl_find_in_proto, 0, pso);
	}
      else if (pso->flags & F_OPSOCK_CONNECT)
	{
	  struct bgp_proto *p = pso->st_p0;
	  p->rlink_sock = pso;
	  log (L_DEBUG "net_mrl_init: [%d]: relay link up", pso->sock);
	}
      break;
    }

  return 0;
}

static int
net_mrl_destroy (__sock_o pso)
{
  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;

      struct bgp_proto *p = pso->st_p0;
      if (p)
	{
	  p->rlink_sock = NULL;
	  log (L_DEBUG "net_mrl_init: [%d]: relay link down", pso->sock);
	}

      if (pso->flags & F_OPSOCK_PERSIST)
	{
	  __sock_ca oldca = pso->sock_ca;
	  if (net_open_connection (oldca->host, oldca->port, oldca))
	    {
	      log (
	      L_FATAL "net_mrl_destroy: [%d]: failed to restart connection",
		   pso->sock);
	      abort ();
	    }
	  else
	    {
	      log (L_DEBUG "net_mrl_destroy: [%d]: restarted connection..",
		   pso->sock);
	    }
	}

      break;
    }

  return 0;
}

void
mrl_fill_ca_default (__sock_ca ca)
{

  ca->flags |= F_OPSOCK_LISTEN | F_OPSOCK_INIT_SENDQ;

  ca->socket_register = &msg_relay_socks.r;

  ca->proc = (_p_sc_cb) net_baseline_prochdr;

  pc_a.objects[PROT_CODE_RELAY].ptr = (void*) net_baseline_relay;

  // net_register_task (&ca->c_tasks, irc_rx_translate, NULL, 0);
  net_register_task (&ca->ct_tasks, mrl_sock_keepalive, NULL, 0);

  //net_register_task (&ca->t_rcv, NULL , NULL, 0);

  net_push_rc (&ca->init_rc0, (_t_rcall) net_generic_socket_init1, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_mrl_init, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_baseline_socket_init0, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_socket_init_enforce_policy, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_generic_socket_init0, 0);

  net_push_rc (&ca->shutdown_rc0, (_t_rcall) net_mrl_destroy, 0);
  net_push_rc (&ca->shutdown_rc0, (_t_rcall) net_generic_socket_destroy0, 0);

  mrl_apply_default_policy (ca);
}

int
mrl_open_conn (struct bgp_proto *p, ip_addr ip, int port, __sock_ca ca)
{
  if (ca->ca_flags & F_SOCA_PROCED)
    {
      return 0;
    }

  if (ca->host)
    {
      free (ca->host);
    }

  if (ca->port)
    {
      free (ca->port);
    }

  mrl_free_ca_default (ca);

  memset (ca, 0x0, sizeof(_sock_ca));

  ca->host = malloc (64);
  ca->port = malloc (16);

  struct in_addr a = ipa_to_in4 (ip);
  inet_ntop (AF_INET, &a, ca->host, 64);

  snprintf (ca->port, 16, "%d", port);

  mrl_init_ca_default (ca);
  ca->st_p0 = p;

  net_register_task (&ca->c_pre_tasks, net_conn_establish_async, NULL, 0);
  mrl_fill_ca_default (ca);

  ca->flags |= F_OPSOCK_RETRY | F_OPSOCK_PERSIST;

  return net_open_connection (ca->host, ca->port, ca);
}

void
_mrl_startup (__sock_ca ca)
{

  md_init (&msg_relay_socks.r, 4096);

  msg_relay_socks.ht = ht_create (4096);

  struct in_addr a = ipa_to_in4 (_icf_global.relay_listen_add);

  char *o = malloc (64);
  inet_ntop (AF_INET, &a, o, 64);
  char *p = malloc (16);

  snprintf (p, 16, "%d", _icf_global.relay_listen_port);

  ca->host = o;
  ca->port = p;

  mrl_init_ca_default (ca);
  ca->st_p0 = p;

  mrl_fill_ca_default (ca);

  net_open_listening_socket (ca->host, ca->port, ca);

}

