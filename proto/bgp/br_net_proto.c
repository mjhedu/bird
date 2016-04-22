/*
 * net_proto.c
 *
 *  Created on: Mar 9, 2014
 *      Author: reboot
 */

#include <stdio.h>
#include <limits.h>

#include "brc_memory.h"
#include "brc_net_io.h"

#include "br_net_proto.h"

md_obj pc_a[UCHAR_MAX] =
  {
    { 0 } };

int
net_baseline_socket_init0 (__sock_o pso)
{
  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;
      pso->unit_size = BP_HEADER_SIZE;
      break;
    }
  return 0;
}

int
net_baseline_socket_t (__sock_o pso)
{
  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;
      pso->unit_size = 8192;
      break;
    }
  return 0;
}

int
net_baseline_socket_init1 (__sock_o pso)
{

  char ip[128];
  uint16_t port = net_get_addrinfo_port (pso);
  net_get_addrinfo_ip_str (pso, (char*) ip, sizeof(ip));

  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;
      if (pso->flags & F_OPSOCK_IN)
	{
	  log (L_INFO "[%d] client connected from %s:%hu\n", pso->sock, ip,
	       port);

	}
      else
	{
	  log (L_INFO "[%d] connected to host %s:%hu\n", pso->sock, ip, port);
	}
      break;
    case SOCKET_OPMODE_LISTENER:
      ;
      log (L_INFO "[%d]: listening on %s:%hu\n", pso->sock, ip, port);
      break;
    }

  pso->timers.last_act = time (NULL);

  return 0;
}

#include <unistd.h>
#include <sys/syscall.h>

int
net_baseline_socket_destroy_rc0 (__sock_o pso)
{

  pid_t _tid = (pid_t) syscall (SYS_gettid);
  log (L_INFO "[%d] socket closed: [%d]\n", _tid, pso->sock);

  return 0;
}

static void
net_baseline_respond_protocol_version (__sock_o pso)
{
  int ret;

  char buffer[32];

  snprintf (buffer, 32, "%d.%d\n", BASELINE_PROTOCOL_VERSION_MAJOR,
  BASELINE_PROTOCOL_VERSION_MINOR);

  if ((ret = net_send_direct (pso, &buffer, 4)) == -1)
    {
      log (L_ERR
      "net_baseline_respond_protocol_version: net_send_direct failed: %d\n",
	   ret);
    }
  else
    {
      log (L_DEBUG
      "net_baseline_respond_protocol_version: net_send_direct ok\n");
    }

  //pso->flags |= F_OPSOCK_TERM;
}

static void
net_baseline_respond_pong (__sock_o pso)
{

  _bp_header bp =
    { 0 };

  bp.prot_code = PROT_CODE_BASELINE_KEEPALIVE_PONG;

  net_send_direct (pso, &bp, sizeof(bp));

  //pso->flags |= F_OPSOCK_TERM;
}

static int
net_baseline_proc_tier1_req (__sock_o pso, __bp_header bph)
{
  switch (bph->prot_code)
    {
    case PROT_CODE_BASELINE_PROTO_VERSION:
      net_baseline_respond_protocol_version (pso);
      break;
    case PROT_CODE_BASELINE_KEEPALIVE:
      /*log (L_DEBUG "net_baseline_proc_tier1_req: [%d]: got keepalive ping",
       pso->sock);*/
      net_baseline_respond_pong (pso);
      break;
    case PROT_CODE_BASELINE_KEEPALIVE_PONG:
      /*log (L_DEBUG "net_baseline_proc_tier1_req: [%d]: got keepalive pong",
       pso->sock);*/
      break;
    default:
      return 1;
    }

  return 0;
}

int
net_baseline_prochdr (__sock_o pso, pmda base, pmda threadr, void *data)
{

  if (pso->counters.b_read < BP_HEADER_SIZE)
    {
      return -2;
    }

  if (!net_baseline_proc_tier1_req (pso, (__bp_header ) data))
    {
      pso->counters.b_read = 0;
      goto end;
    }

  __bp_header bph = (__bp_header) data;

  _p_s_cb protf = (_p_s_cb) pc_a[bph->prot_code].ptr;

  if (NULL == protf)
    {
      log (L_ERR
      "net_baseline_prochdr: [%d]: invalid protocol code: %hhu\n",
	   pso->sock, bph->prot_code);
      return -11;
    }

  if (0 == bph->content_length)
    {
      log (L_ERR
      "net_baseline_prochdr: [%d]: protocol %hhu empty packet\n",
	   pso->sock, bph->prot_code);
      return -12;
    }

  //printf("%d - %d\n", (int) bph->content_length, (int) pso->unit_size);

  if (bph->content_length > pso->buffer0_len)
    {
      log (L_ERR
      "net_baseline_prochdr: [%d]: protocol %d: packet too large\n",
	   pso->sock, bph->prot_code);
      return -13;
    }

  pso->unit_size = bph->content_length;

  pso->rcv1 = protf;

  end: ;

  return 0;
}

void
net_proto_reset_to_baseline (__sock_o pso)
{
  pso->unit_size = BP_HEADER_SIZE;
  pso->rcv1 = (_p_s_cb) net_baseline_prochdr;
  pso->counters.b_read = 0;
}

int
net_proto_baseline_send (__sock_o pso, void *data, size_t len)
{
  _bp_header bph =
    { .content_length = len };

  return 0;

}
