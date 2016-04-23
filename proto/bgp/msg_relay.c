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
net_baseline_relay_forwarder (__sock_o origin, mrl_dpkt *pkt)
{
  net_baseline_decrease_ttl (pkt);

  if (!pkt->ttl)
    {
      log (
	  L_DEBUG "net_baseline_relay_forwarder: [%d]: TTL exceeded on packet from %I",
	  origin->sock, pkt->dest);

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
      struct bgp_proto *p;
      struct rte *routes = n->routes;

      for (; routes; routes = routes->next)
	{
	  p = (struct bgp_proto *) routes->attrs->src->proto;

	  if (!p || !p->rlink_sock || (p->rlink_sock->flags & F_OPSOCK_TERM)) // must have a relay connection
	    {
	      continue;
	    }

	  if (net_send_direct (p->rlink_sock, (void*) pkt,
			       pkt->head.content_length))
	    {
	      continue;
	    }

	  log (
	      L_DEBUG "net_baseline_relay_forwarder: [%d->%d]: forwarding from %I to %I",
	      origin->sock, p->rlink_sock->sock, pkt->source.addr,
	      pkt->dest.addr);

	  return 0;

	}

      log (
      L_ERR
      "net_baseline_relay_forwarder: [%d]: unreachable: %I",
	   origin->sock, pkt->dest.addr);

      return 1;

    }

  return 0;

}

int
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
      net_baseline_relay_forwarder (pso, data);
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
	{ 0 };

      bp.prot_code = PROT_CODE_BASELINE_KEEPALIVE;

      net_push_to_sendq (pso, &bp, sizeof(bp), 0);
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
  ca->policy.max_sim_ip = 4;
  ca->policy.connect_retry_timeout = 30;
  ca->policy.max_connect_retries = 0;
}

void
mrl_free_ca_default (__sock_ca ca)
{
  md_free (&ca->init_rc0);
  md_free (&ca->init_rc1);
  md_free (&ca->shutdown_rc0);
  md_free (&ca->shutdown_rc1);
  md_free (&ca->c_tasks);
  md_free (&ca->ct_tasks);
  md_free (&ca->t_tasks);
  md_free (&ca->t_rcv);
  md_free (&ca->c_pre_tasks);
}

static int
mrl_find_in_proto (struct proto *p, unsigned int verbose, int cnt, void *data)
{
  __sock_o pso = data;

  if (!(p->proto->name[0] == 0x42 && p->proto->name[1] == 0x47))
    {
      return 0;
    }

  struct bgp_proto *bgp = (struct bgp_proto*) p;

  if (memcmp (&pso->ipr.ip, &bgp->cf->remote_ip, sizeof(ip_addr)))
    {
      return 0;
    }

  if (bgp->rlink_sock)
    {
      log (
	  L_DEBUG "mrl_find_in_proto: [%d]: relay link already exists from %I for proto %s",
	  pso->sock, *((ip_addr*) &pso->ipr.ip), p->name);
      return 1;
    }

  if (!bgp->conn || bgp->conn->state != BS_ESTABLISHED)
    {
      log (
	  L_ERR "mrl_find_in_proto: [%d]: %I: BGP session down, terminating relay link [%s]",
	  pso->sock, *((ip_addr*) &pso->ipr.ip), p->name);
      return 1;
    }

  bgp->rlink_sock = pso;
  pso->st_p0 = bgp;
  log (L_DEBUG "mrl_find_in_proto: [%d]: relay link inbound: %I", pso->sock,
       *((ip_addr*) &pso->ipr.ip));

  return -2;

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
	  if (proto_enum (mrl_find_in_proto, 0, pso))
	    {
	      pso->flags |= F_OPSOCK_TERM;
	      return -1;
	    }

	  if (!pso->st_p0)
	    {
	      pso->flags |= F_OPSOCK_TERM;
	      log (L_ERR "net_mrl_init: [%d]: could not find adjacent protocol",
		   pso->sock);
	      return -1;
	    }
	}
      else if (pso->flags & F_OPSOCK_CONNECT)
	{
	  struct bgp_proto *p = pso->st_p0;

	  if (p)
	    {
	      if (p->rlink_sock)
		{
		  log (
		      L_DEBUG "net_mrl_init: [%d]: relay link already exists from %I for proto %s",
		      pso->sock, *((ip_addr*) &pso->ipr.ip), p->p.name);
		  pso->flags |= F_OPSOCK_TERM;
		  return -1;
		}

	      p->rlink_sock = pso;
	      log (L_DEBUG "net_mrl_init: [%d]: relay link up", pso->sock);
	    }
	  else
	    {
	      log (L_ERR "net_mrl_init: [%d]: protocol unavailable", pso->sock);
	      pso->flags |= F_OPSOCK_TERM;
	      return -1;
	    }
	}
      else
	{
	  die ("????");
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
	  if (p->rlink_sock)
	    {
	      p->rlink_sock = NULL;
	      log (L_DEBUG "net_mrl_init: [%d]: relay link down", pso->sock);

	      if (!p->conn || p->conn->state != BS_ESTABLISHED)
		{
		  log (
		  L_WARN "net_mrl_destroy: [%d]: BGP session not connected",
		       pso->sock);
		  break;
		}
	    }

	  if (p->rlink_sock != pso)
	    {
	      break; // we don't govern the link, quit silently
	    }
	}

      if (!(pso->flags & F_OPSOCK_IN) && (pso->flags & F_OPSOCK_CONNECT)
	  && (pso->flags & F_OPSOCK_PERSIST))
	{
	  __sock_ca oldca = pso->sock_ca;
	  oldca->policy.socket_initproc_delay = 15;
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

  ca->policy.socket_initproc_delay = 5;
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

  if (ca->host)
    {
      free (ca->host);
    }

  if (ca->port)
    {
      free (ca->port);
    }

  net_ca_free (ca);

  ca->host = malloc (64);
  ca->port = malloc (16);

  struct in_addr a = ipa_to_in4 (ip);
  inet_ntop (AF_INET, &a, ca->host, 64);

  snprintf (ca->port, 16, "%d", port);

  net_ca_init (ca);
  ca->st_p0 = p;

  ca->bind_ip = ipa_to_in4 (p->source_addr);
  log (L_DEBUG "binding to %I", p->source_addr);

  net_register_task (&ca->c_pre_tasks, net_socket_proc_delay, NULL, 0);
  net_register_task (&ca->c_pre_tasks, net_conn_establish_async, NULL, 0);
  mrl_fill_ca_default (ca);

  ca->flags |= F_OPSOCK_RETRY | F_OPSOCK_PERSIST | F_OPSOCK_BIND;

  int ret = net_open_connection (ca->host, ca->port, ca);

  return ret;

}

