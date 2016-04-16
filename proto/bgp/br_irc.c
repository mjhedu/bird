/*
 * br_irc.c
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#include <arpa/inet.h>

#include "bgp.h"
#include "sysdep/unix/unix.h"

#include "brc_net_io.h"
#include "br_proto.h"
#include "br_ea.h"
#include "br_string.h"

#include "br_irc_proto.h"
#include "msg_relay.h"

#include "br_irc.h"

hashtable_t *irc_crf_in_table = NULL;
struct irc_srv_config _icf_global =
  { 0 };

irc_srvctx irc_sv_context =
  {
    {
      { 0 } } };

gtable_t br_routes =
  {
    { 0 } };

struct generic_table _ntglobal =
  {
    { 0 } };

#define F_CTX_CHAN_RADD		(uint32_t)1

static irc_ea_payload *
get_irc_payload (struct proto *p, net *n)
{
  base_ea_payload *eap = br_get_net_payload (p, n);

  if (!eap)
    {
      return NULL;
    }

  return (irc_ea_payload *) eap->data;

}

static irc_ea_payload *
get_irc_payload_pfx (struct proto *p, struct prefix *pfx)
{
  base_ea_payload *eap = br_get_route_payload (p, pfx);

  if (!eap)
    {
      return NULL;
    }

  return (irc_ea_payload *) eap->data;

}
/*
 static int
 irc_payload_validate (irc_ea_payload *ipl)
 {

 return 0;
 }*/

#define IRC_NICK_AC_CHR		"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

static int
irc_payload_str_validate (char *chan, size_t l)
{
  if (chan[l] != 0x0)
    {
      return 1;
    }
  if (strspn (chan, IRC_NICK_AC_CHR) != strlen (chan))
    {
      return 1;
    }
  return 0;
}

static int
irc_payload_str_validate2 (char *chan, size_t l)
{
  if (chan[l] != 0x0)
    {
      return 1;
    }
  size_t sl = strlen (chan);
  if (!sl)
    {
      return 1;
    }
  if (strspn (chan, IRC_NICK_AC_CHR) != strlen (chan))
    {
      return 1;
    }
  return 0;
}

static void
irc_hostname_update (__sock_o pso)
{

  struct proto_irc_u *uirc = pso->va_p1;
  char h[1024];
  irc_hostname_assemble (pso, h, sizeof(h));

  if (uirc->u_settings.hostname)
    {
      free (uirc->u_settings.hostname);
    }

  uirc->u_settings.hostname = strdup (h);
}

gt_lwrap *
irc_ctx_add_channel (proto_irc_chan *pic, gtable_t *gt, char *key, size_t klen)
{

  md_alloc (&gt->r, 0, 0, pic);

  /*
   md_init (&pic->sockref, 4096);
   pic->sockref.flags |= F_MDA_REFPTR;
   */

  gt_lwrap *lw = malloc (sizeof(gt_lwrap));

  lw->ref = gt->r.pos;
  lw->ptr = pic;
  lw->locks = 0;

  ht_set (gt->ht, (unsigned char*) key, klen, lw, sizeof(gt_lwrap));

  return lw;
}

int
irc_ctx_remove_channel (gt_lwrap *lw, gtable_t *gt, char *chan, size_t klen)
{

  md_unlink (&gt->r, lw->ref);

  ht_remove (gt->ht, (unsigned char*) chan, klen);

  free (lw);

  return 0;
}

int
net_proto_irc_baseline (__sock_o pso, pmda base, pmda n, void *data)
{
  char *msg = (char*) data;

  char *dl = strstr (msg, "\xD\xA");

  if (NULL == dl)
    {
      /*if (pso->counters.b_read == pso->unit_size)
       {
       return 2;
       }*/
      return -3;
    }

  size_t len = ((size_t) dl - (size_t) msg);

  if (len > pso->unit_size - pso->counters.b_read)
    {
      return 4;
    }

  if (len < 0)
    {
      return 6;
    }

  dl[0] = 0x0;

  pso->va_p3 = msg;
  if (net_proc_tasks (pso, &pso->tasks))
    {
      return 7;
    }

  dl = dl + 2;
  len += 2;

  ssize_t diff = pso->counters.b_read - len;

  if (diff > 0)
    {
      memmove (msg, dl, diff);
      msg[diff] = 0x0;
    }
  else if (diff < 0)
    {
      return 8;
    }

  pso->counters.b_read = diff;

  return net_proto_irc_baseline (pso, base, n, msg);
}

int
irc_rx_translate (__sock_o pso, struct ___net_task *task)
{

  struct proto_irc_req *request = irc_decode_request (pso->va_p3);

  if (!request)
    {
      return 1;
    }

  _irc_qc handler = ht_get (irc_crf_in_table, (unsigned char*) request->cmd,
			    strlen (request->cmd));

  struct proto_irc_u *uirc = pso->va_p1;

  int r;

  if (handler)
    {
      if (!IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN)
	  && !(!strncmp (request->cmd, "USER", 4)
	      || !strncmp (request->cmd, "NICK", 4)))
	{
	  char b[1024];
	  snprintf (b, sizeof(b), "%s %s", uirc->u_settings.nick, request->cmd);
	  r = irc_send_simple_response (pso, _icf_global.hostname, "451", b,
					"You have not registered");
	}
      else
	{
	  r = handler (pso, request);
	}
    }
  else
    {

      if (IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN))
	{
	  char b[1024];
	  snprintf (b, sizeof(b), "%s %s", uirc->u_settings.nick, request->cmd);
	  r = irc_send_simple_response (pso, _icf_global.hostname, "421", b,
					"Unknown command");
	}
      else
	{
	  r = 0;
	}

    }

  md_g_free (&request->cmd_params);
  free (request);

  return r;
}

static ip_addr
irc_assign_ip4 (gtable_t *table, __sock_o pso)
{
  ip_addr ip;

  if (table->r.offset)
    {
      p_md_obj ptr = table->r.pos;

      struct proto_irc_u * uirc = ptr->ptr;

      struct prefix lpfx = uirc->net;

      uint32_t fip = (uint32_t) _icf_global.pfx.addr;

      uint32_t max_ip = fip + _icf_global.max_hosts;
      uint8_t ic = 0;

      while (ht_get (table->ht, (unsigned char*) &lpfx, sizeof(struct prefix)))
	{
	  if (lpfx.addr == max_ip)
	    {
	      lpfx.addr = fip;
	      if (ic == 2)
		{
		  pso->status |= SOCKET_STATUS_PFAIL;
		  break;
		}
	      ic++;
	    }
	  else
	    {
	      lpfx.addr += 1;
	    }
	}

      ip = (ip_addr) lpfx.addr;

    }
  else
    {
      ip = _icf_global.pfx.addr;
    }

  return ip;
}

void
irc_brr_install (gtable_t *table, __sock_o pso)
{
  struct proto_irc_u *uirc = pso->va_p1;

  struct static_route r =
    {
      { 0 } };

  r.net = uirc->net.addr;
  r.masklen = uirc->net.len;
  r.dest = RTD_UNREACHABLE;

  struct bgp_br_route * bbr = pso->va_p0 = br_route_add (
      brc_st_proto->c.proto, table, &r, pso->va_p2,
      sizeof(base_ea_payload) + sizeof(irc_ea_payload));

  if (bbr)
    {
      bbr->pso = pso;
      bbr->n->n.pso = pso;
      //bbr->n->pso = pso;
    }
}

#define MAX_IRC_ARGS	512

char *
irc_format_response (struct proto_irc_resp *data)
{
  char *b = malloc (MAX_IRC_MSGLEN + 4);

  char args[MAX_IRC_ARGS];

  md_string_join (&data->cmd_params, 0x20, args, sizeof(args));

  if (data->prefix)
    {
      if (data->cmd_params.offset)
	{
	  snprintf (b, MAX_IRC_MSGLEN, ":%s %s %s :%s\r\n", data->prefix,
		    data->cmd, args, data->trailer);
	}
      else
	{
	  snprintf (b, MAX_IRC_MSGLEN, ":%s %s :%s\r\n", data->prefix,
		    data->cmd, data->trailer);
	}
    }
  else
    {
      if (data->cmd_params.offset)
	{
	  snprintf (b, MAX_IRC_MSGLEN, "%s %s :%s\r\n", data->cmd, args,
		    data->trailer);
	}
      else
	{
	  snprintf (b, MAX_IRC_MSGLEN, "%s :%s\r\n", data->cmd, data->trailer);
	}
    }

  md_g_free (&data->cmd_params);

  return b;
}

char *
irc_assemble_response (char *prefix, char *code, char *trailer)
{
  struct proto_irc_resp r =
    { 0 };

  r.prefix = prefix;
  r.cmd = code;
  r.trailer = trailer;

  return irc_format_response (&r);

}

int
irc_send_simple_response (__sock_o pso, char *prefix, char *code, char *n,
			  char *trailer)
{
  struct proto_irc_resp r =
    { 0 };

  r.prefix = prefix;
  r.cmd = code;
  r.trailer = trailer;

  if (n)
    {
      md_init (&r.cmd_params, 1);
      r.cmd_params.flags |= F_MDA_REFPTR;
      md_alloc (&r.cmd_params, 0, 0, n);
    }

  char *data = irc_format_response (&r);

  if (net_push_to_sendq (pso, data, strlen (data), NET_PUSH_SENDQ_ASSUME_PTR))
    {
      free (data);
      return 1;
    }

  return 0;

}

int
irc_send_response (__sock_o pso, struct proto_irc_resp *r)
{
  char *data = irc_format_response (r);

  if (net_push_to_sendq (pso, data, strlen (data), NET_PUSH_SENDQ_ASSUME_PTR))
    {
      free (data);
      return 1;
    }

  return 0;

}

struct proto_irc_req *
irc_decode_request (char *data)
{
  size_t req_len = strlen (data);

  if (!req_len)
    {
      return NULL;
    }

  if (data[0] == 0x20)
    {
      return NULL;
    }

  struct proto_irc_req *request = calloc (
      1, sizeof(struct proto_irc_req) + req_len + 1);

  memcpy (request->request, data, req_len + 1);

  char *c = (char *) request->request, *ptr = c;

  while (ptr[0] && ptr[0] != 0x20)
    {
      ptr++;
    }

  ptr[0] = 0x0;

  request->cmd = c;

  ptr++;
  c = ptr;

  while (ptr[0]
      && !(ptr[0] == 0x3A
	  && ((ptr[-1] == 0x0 || ptr[-1] == 0x20) || ptr[1] == 0x20)))
    {
      ptr++;
    }

  if (ptr[0] == 0x3A)
    {
      ptr[0] = 0x0;
      ptr++;
      request->trailer = ptr;
    }

  if (c[0])
    {
      md_init (&request->cmd_params, 32);
      string_split (c, 0x20, &request->cmd_params);
    }

  return request;

}

static struct payload_chan*
irc_find_pl_chan (struct payload_chan *pl, char *chan)
{
  int i;

  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
    {
      struct payload_chan *c = &pl[i];
      if (!strncmp (chan, c->name, MAX_CH_NAME_LEN))
	{
	  return c;
	}
    }
  return NULL;
}

static void
irc_channel_cleanup_loc (proto_irc_chan *pic, __sock_o pso, char *chan)
{

  size_t clen = strlen (chan);

  gt_lwrap *lw_g = ht_get (server_ctx.loc_chans.ht, (unsigned char*) chan,
			   clen);

  if (!lw_g)
    {
      log (L_ERR "irc_part_chan: [%d]: BUG: global reference missing (part %s)",
	   pso->sock, chan);
      abort ();
    }

  lw_g->locks--;

  if (!lw_g->locks)
    {
      irc_ctx_remove_channel (lw_g, &server_ctx.loc_chans, chan, clen);
      md_g_free (&pic->sockref);
      free (pic);
    }
  else
    {
      p_md_obj ptr = pic->sockref.first;

      while (ptr)
	{
	  __sock_o so = ptr->ptr;
	  if (pso->sock == so->sock)
	    {
	      md_unlink (&pic->sockref, ptr);
	      break;
	    }
	  ptr = ptr->next;
	}
    }

}

int
irc_do_user_quit (__sock_o pso)
{
  struct proto_irc_u *uirc = pso->va_p1;

  char *bd = irc_assemble_response (uirc->u_settings.hostname, "QUIT", "none");
  size_t dlen = strlen (bd);

  MD_START(&uirc->chans.r, proto_irc_chan)
	{
	  irc_local_broadcast_to_chan (pso, d->name, bd, dlen);

	  irc_channel_cleanup_loc (d, pso, d->name);

	}MD_END

  free (bd);

  return 0;

}

int
irc_join_chan (__sock_o pso, char *chan)
{
  struct bgp_br_route * bbr = pso->va_p0;
  struct proto_irc_u *uirc = pso->va_p1;

  if (uirc->chans.r.offset == PAYLOAD_CR_SIZE)
    {
      log (
	  L_ERR "irc_join_chan: [%d]: failed to join %s: maximum number of channels exceeded",
	  pso->sock, chan);
      return 1;
    }

  irc_ea_payload *ipl = get_irc_payload (brc_st_proto->c.proto, bbr->n);
  if (!ipl)
    {
      log (L_ERR "irc_join_chan: [%d]: join %s: failed to resolve payload",
	   pso->sock, chan);
      return 1;
    }

  size_t clen = strlen (chan);

  gt_lwrap *lw_l = ht_get (uirc->chans.ht, (unsigned char*) chan, clen);

  if (lw_l)
    {
      log (L_ERR "irc_join_chan: [%d]: already joined %s", pso->sock, chan);
      return 4;
    }

  int i;
  struct payload_chan *av = NULL;

  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
    {
      struct payload_chan *c = &(ipl->joined)[i];
      if (c->name[0])
	{
	  if (!strncmp (chan, c->name, MAX_CH_NAME_LEN))
	    {
	      return -2; // already joined
	    }
	}
      else
	{
	  if (av == NULL)
	    {
	      av = c;
	    }
	}
    }

  if (av == NULL)
    {
      return 3; // can't join any more
    }

  gt_lwrap *lw_g = ht_get (server_ctx.loc_chans.ht, (unsigned char*) chan,
			   clen);
  proto_irc_chan *pic;

  if (!lw_g)
    {
      pic = calloc (1, sizeof(proto_irc_chan));
      md_init (&pic->sockref, 4096);
      pic->sockref.flags |= F_MDA_REFPTR;
      snprintf (pic->name, sizeof(pic->name), "%s", chan);

      lw_g = irc_ctx_add_channel (pic, &server_ctx.loc_chans, chan, clen);
    }
  else
    {
      pic = lw_g->ptr;
    }

  md_alloc (&pic->sockref, 0, 0, pso);

  lw_g->locks++;

  irc_ctx_add_channel (pic, &uirc->chans, chan, clen);

  snprintf (av->name, MAX_CH_NAME_LEN, "%s", chan);

  IPL_MARK_UPDATE(ipl, F_IRC_UPDATE_CHAN);
  memcpy (&bbr->n->n.ea_cache, ipl, sizeof(irc_ea_payload));
  br_trigger_update (brc_st_proto->c.proto, bbr->n);

  // propagate update locally

  char cb[MAX_CH_NAME_LEN + 2];
  snprintf (cb, MAX_CH_NAME_LEN + 1, "#%s", chan);
  char *bd = irc_assemble_response (uirc->u_settings.hostname, "JOIN", cb);
  size_t dlen = strlen (bd);
  MD_START(&uirc->chans.r, proto_irc_chan)
	{
	  irc_local_broadcast_to_chan (pso, d->name, bd, dlen);
	}MD_END
  net_push_to_sendq (pso, bd, dlen, 0);
  free (bd);

  irc_send_names (pso, cb);

  return 0;

}

int
irc_part_chan (__sock_o pso, char *chan)
{
  struct bgp_br_route * bbr = pso->va_p0;
  struct proto_irc_u *uirc = pso->va_p1;

  irc_ea_payload *ipl = get_irc_payload (brc_st_proto->c.proto, bbr->n);
  if (!ipl)
    {
      log (L_ERR "irc_part_chan: [%d]: join %s: failed to resolve payload",
	   pso->sock, chan);
      abort ();
    }

  size_t clen = strlen (chan);

  gt_lwrap *lw_l = ht_get (uirc->chans.ht, (unsigned char*) chan, clen);
  proto_irc_chan *pic;

  if (!lw_l)
    {
      log (L_ERR "irc_part_chan: [%d]: attempt to part %s: not joined",
	   pso->sock, chan);
      return 4;
    }
  else
    {
      pic = lw_l->ptr;
    }

  int i;
  struct payload_chan *av = NULL;

  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
    {
      if (!strncmp (chan, ipl->joined[i].name, MAX_CH_NAME_LEN))
	{
	  av = &(ipl->joined)[i];
	  break;
	}

    }

  if (av == NULL)
    {
      return 2; // not joined (global)
    }

  char cb[MAX_CH_NAME_LEN + 2];
  snprintf (cb, MAX_CH_NAME_LEN + 1, "#%s", chan);
  char *bd = irc_assemble_response (uirc->u_settings.hostname, "PART", cb);
  size_t dlen = strlen (bd);
  MD_START(&uirc->chans.r, proto_irc_chan)
	{
	  irc_local_broadcast_to_chan (pso, d->name, bd, dlen);
	}MD_END

  net_push_to_sendq (pso, bd, dlen, 0);
  free (bd);

  irc_ctx_remove_channel (lw_l, &uirc->chans, chan, clen);

  irc_channel_cleanup_loc (pic, pso, chan);

  memset (av, 0x0, sizeof(struct payload_chan));

  IPL_MARK_UPDATE(ipl, F_IRC_UPDATE_CHAN);
  memcpy (&bbr->n->n.ea_cache, ipl, sizeof(irc_ea_payload));
  br_trigger_update (brc_st_proto->c.proto, bbr->n);

  return 0;

}

static int
if_login (__sock_o pso)
{
  struct proto_irc_u *uirc = pso->va_p1;

  if (IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN))
    {

      base_ea_payload *pl = pso->va_p2 = calloc (
	  1, sizeof(base_ea_payload) + sizeof(irc_ea_payload) + 8);

      irc_ea_payload *ipl = (irc_ea_payload *) pl->data;

      snprintf (ipl->net_name, MAX_CL_NAME_LEN, "%s", uirc->u_settings.nick);
      ipl->flags = F_IRC_UPDATE_AUTH | F_IRC_UPDATE_NAME;

      /*memcpy (&uirc->net.addr, uirc->u_settings.nick,
       strlen (uirc->u_settings.nick));
       uirc->net.len = sizeof(ip_addr) * 8;*/

      irc_brr_install (&br_routes, pso);

      pso->va_p2 = NULL;

      if (!pso->va_p0)
	{
	  if (!(pso->status & SOCKET_STATUS_SKIP_RX_PROC))
	    {
	      pso->flags |= F_OPSOCK_TERM;

	    }
	  free (pl);
	  return 1;
	}

      struct bgp_br_route *bbr = pso->va_p0;
      memcpy (&bbr->n->n.ea_cache, ipl, sizeof(irc_ea_payload));
      irc_proto_cache_n (bbr->n, ipl, F_IRC_CACHE_UPDATE);

      free (pl);

      irc_hostname_update (pso);

      char b[4096];

      snprintf (b, sizeof(b), "Welcome to the BGP relay network %s",
		uirc->u_settings.hostname);
      irc_send_simple_response (pso, _icf_global.hostname, "001",
				uirc->u_settings.nick, b);

      pso->flags |= F_OPSOCK_BRK;

    }

  return 0;

}

int
irc_ping (__sock_o pso, __net_task task)
{
  time_t t = time (NULL);
  if (pso->policy.idle_timeout
      && (t - pso->timers.l_rx) >= pso->policy.idle_timeout / 2
      && t - pso->timers.l_ping > pso->policy.idle_timeout / 2)
    {
      pso->timers.l_ping = t;
      //log (L_INFO "[%d]: PING %u", pso->sock, t);

      char *data = malloc (32);

      snprintf (data, 32, "PING :%.8X\r\n", (unsigned int) t);

      if (net_push_to_sendq (pso, data, strlen (data),
      NET_PUSH_SENDQ_ASSUME_PTR))
	{
	  return 1;
	}

    }

  return 0;

}

#define IPA_TO_STR(ipa) char ip[128];do { struct in_addr a = ipa_to_in4 (ipa);inet_ntop (AF_INET, &a, ip, sizeof(ip)); } while(0);

#define MSG_IRC_HOSTNAME "%s!%s@%s"

void
irc_hostname_assemble (__sock_o pso, char *b, size_t sz)
{
  struct proto_irc_u *uirc = pso->va_p1;

  if (!IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN))
    {
      return;
    }

  struct bgp_br_route * bbr = pso->va_p0;

  IPA_TO_STR(bbr->pfx.addr)

  //net_get_addrinfo_ip_str (pso, ip, sizeof(ip));
  snprintf (b, sz, MSG_IRC_HOSTNAME, uirc->u_settings.nick,
	    uirc->u_settings.username, ip);

}

void
irc_hostname_assemble_va (char *b, size_t sz, char *nick, char *user,
			  ip_addr ipa)
{

  IPA_TO_STR(ipa)
  snprintf (b, sz, MSG_IRC_HOSTNAME, nick, user, ip);
}

int
irc_c_dummy (__sock_o pso, void *data)
{
  /*
   struct proto_irc_req *r = (struct proto_irc_req *) data;

   log (L_INFO "[%d]: %s %s", pso->sock, r->cmd, r->cmd_params.first->ptr);
   */

  return 0;
}

static int
irc_validate_chan_scope (char *name)
{
  size_t len = strlen (name);
  if (len > MAX_CH_NAME_LEN || len < MIN_CH_NAME_LEN + 1)
    {
      return 1;
    }
  return 0;
}

static int
irc_validate_chan_name (char *name)
{
  if (irc_validate_chan_scope (name))
    {
      return 1;
    }

  if (name[0] != 0x23 || name[1] == 0x23)
    {
      return 2;
    }

  return 0;
}

static int
irc_build_names_list (__sock_o pso, net *n, void *data)
{
  irc_pkasm_state *pkasm = data;

  irc_ea_payload *ipl = &n->n.ea_cache;
  if (!ipl->net_name[0])
    {
      return 1;
    }

  char *chan = pkasm->data;

  if (!irc_find_pl_chan (ipl->joined, &chan[1]))
    {
      return 2;
    }

  size_t nl = strlen (ipl->net_name) + 1;

  pkasm->u2 += nl;

  pmda base = &pkasm->base;
  pmda md = base->pos->ptr;

  if (pkasm->u1 + pkasm->u2 > MAX_IRC_MSGLEN)
    {
      md = md_alloc (base, sizeof(mda), 0, NULL);
      md_init (md, 1024);
      pkasm->u2 = nl;
    }

  char *name = md_alloc (md, nl, 0, NULL);

  snprintf (name, nl, "%s", ipl->net_name);

  return 0;
}
/*
 static int
 irc_build_test (__sock_o pso, net *n, void *data)
 {
 char tn[1024];

 snprintf (tn, sizeof(tn), "%d", rand ());
 size_t nl = strlen (tn) + 1;

 irc_pkasm_state *pkasm = data;

 pkasm->u2 += nl;

 pmda base = &pkasm->base;
 pmda md = base->pos->ptr;

 if (pkasm->u1 + pkasm->u2 > MAX_IRC_MSGLEN)
 {
 md = md_alloc (base, sizeof(mda), 0, NULL);
 md_init (md, 1024);
 pkasm->u2 = nl;
 }

 char *name = md_alloc (md, nl, 0, NULL);

 snprintf (name, nl, "%s", tn);

 return 0;
 }
 */
static int
irc_names_iterate (__sock_o pso, void *data)
{

  return br_fib_iterator (pso, irc_build_names_list, data);

}

int
irc_send_names (__sock_o pso, char *chan)
{
  struct proto_irc_u *uirc = pso->va_p1;

  struct proto_irc_resp rsp =
    { 0 };

  rsp.cmd = "353";
  md_init (&rsp.cmd_params, 8);
  rsp.cmd_params.flags |= F_MDA_REFPTR;
  md_alloc (&rsp.cmd_params, 0, 0, uirc->u_settings.nick);
  md_alloc (&rsp.cmd_params, 0, 0, "@");
  md_alloc (&rsp.cmd_params, 0, 0, chan);
  rsp.prefix = _icf_global.hostname;
  rsp.trailer = "";

  irc_format_response_ex (pso, &rsp, irc_names_iterate, chan);

  md_g_free (&rsp.cmd_params);

  rsp.cmd = "366";
  md_init (&rsp.cmd_params, 8);
  rsp.cmd_params.flags |= F_MDA_REFPTR;
  md_alloc (&rsp.cmd_params, 0, 0, uirc->u_settings.nick);
  md_alloc (&rsp.cmd_params, 0, 0, chan);
  rsp.prefix = _icf_global.hostname;
  rsp.trailer = "End of /NAMES list.";

  irc_send_response (pso, &rsp);

  md_g_free (&rsp.cmd_params);

  return 0;

}

int
irc_format_response_ex (__sock_o pso, struct proto_irc_resp *rsp,
			ifmtr_callback call, void *d)
{

  char *main_chunk = irc_format_response (rsp);

  irc_pkasm_state pkasm =
    {
      { 0 } };

  pkasm.u1 = strlen (main_chunk);

  main_chunk[pkasm.u1 - 2] = 0x0;

  if (pkasm.u1 >= MAX_IRC_MSGLEN)
    {
      free (main_chunk);
      return 2;
    }

  pkasm.u2 = 0;
  pkasm.data = d;

  md_init (&pkasm.base, 1024);
  pmda md = md_alloc (&pkasm.base, sizeof(mda), 0, NULL);
  md_init (md, 1024);

  call (pso, &pkasm);

  p_md_obj ptr = pkasm.base.first;

  char o[IRC_MSGBUFLEN];
  char rb[IRC_MSGBUFLEN];

  size_t max_trailer = (sizeof(rb) - pkasm.u1) - 1;

  while (ptr)
    {
      md = ptr->ptr;

      md_string_join (md, 0x20, o, max_trailer);

      snprintf (rb, sizeof(rb), "%s%s\r\n", main_chunk, o);

      if (net_push_to_sendq (pso, rb, strlen (rb), 0))
	{
	  break;
	}

      md_g_free (md);

      ptr = ptr->next;
    }

  md_g_free (&pkasm.base);

  free (main_chunk);

  return 0;
}

int
irc_c_join (__sock_o pso, void *data)
{

  struct proto_irc_req *r = (struct proto_irc_req *) data;

  if (r->cmd_params.offset != 1)
    {
      IRC_C_ERRQUIT(0)
    }

  char *chan = r->cmd_params.first->ptr;

  if (irc_validate_chan_name (chan))
    {
      IRC_C_QUIT_M(0, "invalid channel name", chan)
    }

  int ret = irc_join_chan (pso, &chan[1]);

  if (ret)
    {
      log (L_ERR "%d: failed to join channel: %s [%d]", pso->sock, chan, ret);
      return 0;
    }

  return 0;
}

int
irc_c_part (__sock_o pso, void *data)
{

  struct proto_irc_req *r = (struct proto_irc_req *) data;

  if (r->cmd_params.offset != 1)
    {
      IRC_C_ERRQUIT(0)
    }

  char *chan = r->cmd_params.first->ptr;

  if (irc_validate_chan_name (chan))
    {
      IRC_C_QUIT_M(0, "invalid channel name", chan)
    }

  int ret = irc_part_chan (pso, &chan[1]);

  if (ret)
    {
      IRC_C_QUIT_M(0, "failed to part channel", chan)
    }

  return 0;
}

int
irc_c_userhost (__sock_o pso, void *data)
{
  struct proto_irc_u *uirc = pso->va_p1;

  struct proto_irc_req *r = (struct proto_irc_req *) data;

  if (r->cmd_params.offset != 1)
    {
      IRC_C_ERRQUIT(1)
    }

  if (strcmp (uirc->u_settings.nick, r->cmd_params.first->ptr))
    {
      irc_send_simple_response (pso, _icf_global.hostname, "481",
				uirc->u_settings.nick, ERR_NOPRIVILEGES_TEXT);

    }
  else
    {
      irc_send_simple_response (pso, _icf_global.hostname, "302",
				uirc->u_settings.nick,
				uirc->u_settings.hostname);
    }

  return 0;
}

int
irc_c_privmsg (__sock_o pso, void *data)
{
  struct proto_irc_u *uirc = pso->va_p1;

  struct proto_irc_req *r = (struct proto_irc_req *) data;

  if (r->cmd_params.offset != 1)
    {
      IRC_C_ERRQUIT(1)
    }

  if (strlen (r->trailer) > MAX_IRC_MSGLEN)
    {
      IRC_C_ERRQUIT_M(1, "message too large")
    }

  char *t = r->cmd_params.first->ptr;

  if (strlen (t) > MAX_CL_NAME_LEN)
    {
      log (L_ERR "irc_c_privmsg: [%d]: nick too long", pso->sock);
      return 0;
    }

  int ret = irc_relay_message (pso, sizeof(ip_addr) * 8, "PRIVMSG", t,
			       r->trailer);

  if (ret == 1)
    {
      char b[1024];
      snprintf (b, sizeof(b), ERR_NOSUCHNICK_TEXT, t);

      irc_send_simple_response (pso, _icf_global.hostname, _ST(ERR_NOSUCHNICK),
      NULL,
				b);
      return 0;
    }

  return 0;
}

int
irc_c_nick (__sock_o pso, void *data)
{
  struct proto_irc_u *uirc = pso->va_p1;

  struct proto_irc_req *r = (struct proto_irc_req *) data;

  char *nick;

  if (r->cmd_params.offset == 1)
    {
      nick = r->cmd_params.first->ptr;
    }
  else if (r->trailer)
    {
      nick = r->trailer;
    }
  else
    {
      IRC_C_ERRQUIT(1)
    }

  size_t nlen = strlen (nick);

  if (!nlen || nlen > MAX_CL_NAME_LEN)
    {
      irc_send_simple_response (pso, _icf_global.hostname,
				_ST(ERR_ERRONEUSNICKNAME), NULL,
				ERR_ERRONEUSNICKNAME_TEXT);
      return 0;
    }

  ip_addr *ha = ht_get (server_ctx.map_nick_to_ipa.ht, nick, nlen);

  if (ha)
    {
      if (!(IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN)
	  && !memcmp (ha, &uirc->net.addr, sizeof(ip_addr))))
	{
	  char b[256];
	  snprintf (b, sizeof(b), ERR_NICKNAMEINUSE_TEXT, nick);
	  irc_send_simple_response (pso, _icf_global.hostname,
				    _ST(ERR_NICKNAMEINUSE), NULL, b);
	  return 0;
	}

    }

  if (uirc->u_settings.nick)
    {
      free (uirc->u_settings.nick);
    }

  uirc->u_settings.nick = malloc (MAX_CL_NAME_LEN);
  snprintf (uirc->u_settings.nick, MAX_CL_NAME_LEN, "%s", nick);

  if (!(uirc->status & IRC_STATUS_HAS_NAME))
    {
      uirc->status |= IRC_STATUS_HAS_NAME;
      if (if_login (pso))
	{
	  return 1;
	}
    }

  struct bgp_br_route *bbr = pso->va_p0;

  if (IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN))
    {

      irc_ea_payload *ipl = get_irc_payload (brc_st_proto->c.proto, bbr->n);
      if (ipl)
	{
	  snprintf (ipl->net_name, sizeof(ipl->net_name), "%s",
		    uirc->u_settings.nick);
	  irc_proto_cache_n (bbr->n, &bbr->n->n.ea_cache,
	  F_IRC_CACHE_REMOVE);
	  irc_proto_cache_n (bbr->n, ipl, F_IRC_CACHE_UPDATE);
	  memcpy (&bbr->n->n.ea_cache, ipl, sizeof(irc_ea_payload));
	  br_trigger_update (brc_st_proto->c.proto, bbr->n);
	}

      char *data = irc_assemble_response (uirc->u_settings.hostname, "NICK",
					  uirc->u_settings.nick);

      size_t dlen = strlen (data);
      p_md_obj ptr = uirc->chans.r.first;

      while (ptr)
	{
	  proto_irc_chan *pic = ptr->ptr;
	  irc_local_broadcast_to_chan (pso, pic->name, data, dlen);
	  ptr = ptr->next;
	}

      if (net_push_to_sendq (pso, data, dlen, 0))
	{
	  return 1;
	}

      free (data);

      irc_hostname_update (pso);

    }

  return 0;

}

int
irc_c_user (__sock_o pso, void *data)
{
  struct proto_irc_u *uirc = pso->va_p1;

  if (IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN))
    {
      irc_send_simple_response (pso, _icf_global.hostname, "462",
				uirc->u_settings.nick,
				ERR_ALREADYREGISTRED_TEXT);
      return 0;
    }

  struct proto_irc_req *r = (struct proto_irc_req *) data;

  if (r->cmd_params.offset < 3)
    {
      IRC_C_ERRQUIT(1)
    }

  if (!r->trailer)
    {
      IRC_C_ERRQUIT_M(1, "missing real name")
    }

  uirc->u_settings.username = strdup (r->cmd_params.first->ptr);
  uirc->u_settings.ident = strdup (r->cmd_params.first->next->ptr);
  uirc->u_settings.rl_name = strdup (r->trailer);

  uirc->status |= IRC_STATUS_AUTHED;

  int ret = irc_send_simple_response (pso, _icf_global.hostname, "NOTICE",
				      "AUTH", "Processing..");

  if (ret)
    {
      return ret;
    }

  return if_login (pso);

}

int
net_proto_irc_socket_init0 (__sock_o pso)
{
  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;

      if (br_routes.r.offset >= _icf_global.max_hosts)
	{
	  pso->flags |= F_OPSOCK_TERM;
	  log (L_WARN "net_proto_irc_socket_init0: [%d]: server full",
	       pso->sock);
	  return -1;
	}

      struct proto_irc_u *p = pso->va_p1 = calloc (1,
						   sizeof(struct proto_irc_u));

      p->net.len = sizeof(ip_addr) * 8;
      p->net.addr = irc_assign_ip4 (&br_routes, pso);

      if (pso->status & SOCKET_STATUS_PFAIL)
	{
	  log (
	      L_WARN "net_proto_irc_socket_init0: [%d]: server full (irc_assign_ip4 failed)",
	      pso->sock);
	  pso->flags |= F_OPSOCK_TERM;
	}
      else
	{
	  md_init (&p->chans.r, PAYLOAD_CR_SIZE + 1);
	  p->chans.r.flags |= F_MDA_REFPTR;
	  p->chans.ht = ht_create (PAYLOAD_CR_SIZE + 1);

	  ht_set (br_routes.ht, (unsigned char*) &p->net, sizeof(p->net), p, 0);
	  md_alloc (&br_routes.r, 0, 0, p);

	  p->ref = br_routes.r.pos;

	  pso->flags |= F_OPSOCK_BRK;

	}

      break;

    }

  return 0;
}

int
net_proto_irc_socket_destroy0 (__sock_o pso)
{
  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;
      struct bgp_br_route * bbr = pso->va_p0;

      struct proto_irc_u *uirc = pso->va_p1;

      if (uirc)
	{
	  irc_do_user_quit (pso);

	  md_unlink (&br_routes.r, uirc->ref);
	  ht_remove (br_routes.ht, (unsigned char*) &uirc->net,
		     sizeof(uirc->net));

	  if (uirc->u_settings.username)
	    {
	      free (uirc->u_settings.username);
	    }
	  if (uirc->u_settings.ident)
	    {
	      free (uirc->u_settings.ident);
	    }
	  if (uirc->u_settings.nick)
	    {
	      ht_remove (server_ctx.map_nick_to_ipa.ht, uirc->u_settings.nick,
			 strlen (uirc->u_settings.nick));
	      free (uirc->u_settings.nick);
	    }
	  if (uirc->u_settings.rl_name)
	    {
	      free (uirc->u_settings.rl_name);
	    }
	  if (uirc->u_settings.hostname)
	    {
	      free (uirc->u_settings.hostname);
	    }

	  md_g_free (&uirc->chans.r);
	  if (uirc->chans.ht)
	    {
	      ht_destroy (uirc->chans.ht);
	    }

	  free (uirc);

	}

      if (bbr)
	{

	  bbr->n->n.pso = NULL;

	  br_route_remove (&br_routes, bbr);

	  free (bbr);

	  pso->flags |= F_OPSOCK_BRK;

	}
    }

  return 0;
}

int
irc_local_broadcast_to_chan (__sock_o self, char *name, char *data, size_t len)
{

  gt_lwrap *lw = ht_get (server_ctx.loc_chans.ht, name, strlen (name));

  if (lw)
    {
      proto_irc_chan *pic = lw->ptr;
      p_md_obj ptr = pic->sockref.first;

      while (ptr)
	{
	  __sock_o pso = ptr->ptr;

	  if (self != pso)
	    {
	      if (net_push_to_sendq (pso, data, len, 0))
		{
		  return 1;
		}
	    }

	  ptr = ptr->next;
	}
    }

  return 0;
}

#include "br_crypto.h"

void
irc_proto_cache_n (net *n, irc_ea_payload *pl, uint32_t flags)
{
  if (!pl->net_name[0])
    {
      return;
    }

  if (flags & F_IRC_CACHE_UPDATE)
    {
      ht_set (server_ctx.map_nick_to_ipa.ht, pl->net_name,
	      strlen (pl->net_name), &n->n.prefix, sizeof(ip_addr));
    }
  else if (flags & F_IRC_CACHE_REMOVE)
    {
      ht_remove (server_ctx.map_nick_to_ipa.ht, pl->net_name,
		 strlen (pl->net_name));
    }
}

static int
irc_process_route_withdraw (net *n, uint32_t flags)
{
  irc_ea_payload *cache = (irc_ea_payload *) &n->n.ea_cache;

  if (!cache->net_name[0])
    {
      return 1;
    }

  int i;

  IPA_TO_STR(n->n.prefix)

  char h[1024];
  snprintf (h, sizeof(h), MSG_IRC_HOSTNAME, cache->net_name, "none", ip);

  char *data = irc_assemble_response (
      h, "QUIT", flags & F_RXP_GRACEFULL ? "Route dissapeared" : "Dead peer");
  size_t dlen = strlen (data);

  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
    {
      char *name = cache->joined[i].name;

      if (!name[0])
	{
	  continue;
	}

      irc_local_broadcast_to_chan (NULL, name, data, dlen);

    }

  free (data);

  irc_proto_cache_n (n, cache, F_IRC_CACHE_REMOVE);
  memset (cache, 0x0, sizeof(irc_ea_payload));

  return 0;
}

int
irc_proto_rx_proc (net *n, uint32_t flags)
{
  if (!n)
    {
      log (L_WARN "irc_proto_rx_proc: NULL net");
      return 0;
    }

  if (!n->routes)
    {
      log (L_WARN "irc_proto_rx_proc: NULL route");

      irc_process_route_withdraw (n, flags);
      return 0;
    }

  if (!n->routes->attrs)
    {
      log (L_WARN "irc_proto_rx_payload_proc: NULL route attributes");
      return 0;
    }

  if (n->routes->attrs->source != RTS_BGP)
    {
      return 0;
    }

  IPA_TO_STR(n->n.prefix)

  if (!n->routes->attrs->eattrs)
    {
      log (
      L_WARN "irc_proto_rx_payload_proc: %I: NULL route extended attributes",
	   n->n.prefix);
      return 0;
    }

  eattr *e = ea_find (n->routes->attrs->eattrs, EA_CODE(EAP_BGP, BA_COMMUNITY));

  if (!e)
    {
      return 0;
    }

  if (e->u.ptr->length != sizeof(base_ea_payload) + sizeof(irc_ea_payload) + 4)
    {
      return 0;
    }

  irc_ea_payload *pl = get_irc_payload (NULL, n);

  if (irc_payload_str_validate (pl->net_name, MAX_CL_NAME_LEN)
      || pl->net_name[0] == 0x0)
    {
      log (L_WARN "Invalid payload from %I", n->n.prefix);
      return 0;
    }

  size_t pl_nlen = strlen (pl->net_name);
  ip_addr *ha;
  if ((ha = ht_get (server_ctx.map_nick_to_ipa.ht, pl->net_name, pl_nlen)))
    {
      if (memcmp (ha, &n->n.prefix, sizeof(ip_addr)))
	{
	  net *nex = net_find (brc_st_proto->c.proto->table, *ha, 32);

	  if (nex && nex->n.pso)
	    {
	      irc_send_simple_response (nex->n.pso, _icf_global.hostname,
					_ST(ERR_NICKCOLLISION), pl->net_name,
					ERR_NICKCOLLISION_TEXT);
	      nex->n.pso->flags |= F_OPSOCK_TERM;
	    }

	  log (L_ERR "Nick collision detected: %s | %I / %I", pl->net_name, *ha,
	       n->n.prefix);
	  return 0;
	}
    }

  irc_ea_payload *cache = (irc_ea_payload *) &n->n.ea_cache;

  char hostname[1024];
  snprintf (hostname, sizeof(hostname), MSG_IRC_HOSTNAME, pl->net_name, "none",
	    ip);

  int i, j;
  uint8_t f = 0;

  if (cache->net_name[0])
    {
      if (strncmp (pl->net_name, cache->net_name, sizeof(pl->net_name)))
	{

	  log (L_INFO "Name change: %s to %s", cache->net_name, pl->net_name);

	  char h[1024];
	  snprintf (h, sizeof(h), MSG_IRC_HOSTNAME, cache->net_name, "none",
		    ip);

	  char *data = irc_assemble_response (h, "NICK", pl->net_name);
	  size_t dlen = strlen (data);

	  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
	    {
	      char *name = pl->joined[i].name;

	      if (!name[0])
		{
		  continue;
		}

	      if (irc_payload_str_validate (name, MAX_CH_NAME_LEN))
		{
		  log (L_WARN "%s: invalid channel string", pl->net_name);
		  continue;
		}

	      irc_local_broadcast_to_chan (NULL, name, data, dlen);

	    }

	  free (data);

	  irc_proto_cache_n (n, cache, F_IRC_CACHE_REMOVE);
	}

      for (i = 0; i < PAYLOAD_CR_SIZE; i++)
	{
	  char *name = cache->joined[i].name;

	  if (!name[0])
	    {
	      continue;
	    }

	  for (j = 0; j < PAYLOAD_CR_SIZE; j++)
	    {
	      if (!strncmp (name, pl->joined[j].name, MAX_CH_NAME_LEN))
		{
		  goto end1;
		}
	    }

	  log (L_DEBUG "%s parted %s", pl->net_name, name);

	  char c[MAX_CH_NAME_LEN + 2];
	  snprintf (c, sizeof(c), "#%s", name);

	  char *data = irc_assemble_response (hostname, "PART", c);

	  irc_local_broadcast_to_chan (NULL, name, data, strlen (data));

	  free (data);

	  end1: ;

	}
    }

  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
    {

      char *name = pl->joined[i].name;

      if (!name[0])
	{
	  continue;
	}

      if (irc_payload_str_validate (name, MAX_CH_NAME_LEN))
	{
	  log (L_WARN "%s: invalid channel string", pl->net_name);
	  f = 1;
	  continue;
	}

      for (j = 0; j < PAYLOAD_CR_SIZE; j++)
	{
	  if (!strncmp (name, cache->joined[j].name, MAX_CH_NAME_LEN))
	    {
	      goto end0;
	    }
	}

      log (L_DEBUG "%s joined %s", pl->net_name, name);

      char c[MAX_CH_NAME_LEN + 1];
      snprintf (c, MAX_CH_NAME_LEN, "#%s", name);

      char *data = irc_assemble_response (hostname, "JOIN", c);

      irc_local_broadcast_to_chan (NULL, name, data, strlen (data));

      free (data);

      end0: ;

    }

  if (!f)
    {
      memcpy (cache, pl, sizeof(irc_ea_payload));
      irc_proto_cache_n (n, pl, F_IRC_CACHE_UPDATE);
    }

  return 0;
}

static int
irc_deliver_relayed_msg (__sock_o pso, void *data)
{
  mrl_dpkt *pkt = data;

  struct proto_irc_rlmsg *msg = (struct proto_irc_rlmsg *) pkt->data;

  if (irc_payload_str_validate2 (msg->code, sizeof(msg->code) - 1)
      || irc_payload_str_validate2 (msg->message, sizeof(msg->message) - 1)
      || irc_payload_str_validate2 (msg->args, sizeof(msg->args) - 1)
      || irc_payload_str_validate2 (msg->hostname, sizeof(msg->hostname) - 1))
    {
      return 1;
    }

  if (strncmp (msg->code, "PRIVMSG", 8))
    {
      log (L_WARN "irc_proc_relayed_msg: [%d]: unknown code '%s'", pso->sock,
	   msg->code);
      return 0;
    }

  log (L_DEBUG "irc_proc_relayed_msg: [%d]: delivering '%s' to '%s'", pso->sock,
       msg->code, msg->args);

  if (msg->args[0] == 0x23)
    {
    }
  else
    {
      irc_send_simple_response (pso, msg->hostname, msg->code, msg->args,
				msg->message);
    }

  return 0;

}

int
irc_relay_message (__sock_o origin, int scope, char *code, char *target,
		   char *message)
{

  mrl_dpkt *pkt = calloc (
      1, sizeof(mrl_dpkt) + sizeof(struct proto_irc_rlmsg) + 1);
  struct proto_irc_rlmsg *msg = (struct proto_irc_rlmsg *) pkt->data;

  snprintf (msg->message, sizeof(msg->message), "%s", message);
  snprintf (msg->args, sizeof(msg->args), "%s", target);

  struct proto_irc_u *uirc = origin->va_p1;

  snprintf (msg->hostname, sizeof(msg->hostname), "%s",
	    uirc->u_settings.hostname);
  snprintf (msg->code, sizeof(msg->code), "%s", code);

  pkt->data_len = sizeof(struct proto_irc_rlmsg);

  pkt->head.content_length = sizeof(mrl_dpkt) + sizeof(struct proto_irc_rlmsg);
  pkt->head.prot_code = PROT_CODE_RELAY;
  pkt->delivery_code = DSP_CODE_IRC_MESSAGE;

  if (target[0] == 0x23)
    {

    }
  else
    {
      ip_addr *ha = ht_get (server_ctx.map_nick_to_ipa.ht, msg->args,
			    strlen (target));

      if (!ha)
	{
	  log (L_ERR "irc_relay_message: [%d]: %s: unreachable (intmap)",
	       origin->sock, target);
	  free (pkt);
	  return 1;
	}

      pkt->source = uirc->net;
      pkt->dest.addr = *ha;
      pkt->dest.len = scope;
      pkt->code = PROT_RELAY_FORWARD;

      net *n = net_find (brc_st_proto->c.proto->table, pkt->dest.addr,
			 pkt->dest.len);

      if (!n || !n->routes || !n->routes->attrs || !n->routes->attrs->src)
	{
	  log (L_ERR "irc_relay_message: [%d]: %I unreachable (no path)",
	       origin->sock, *ha);
	  free (pkt);
	  return 1;
	}

      if (n->routes->attrs->source == RTS_STATIC) // deliver locally
	{
	  log (L_DEBUG "irc_relay_message: [%d]: %I sending %u bytes (local)",
	       origin->sock, *ha, pkt->head.content_length);

	  return net_push_to_sendq (n->n.pso, pkt, pkt->head.content_length,
	  NET_PUSH_SENDQ_ASSUME_PTR);
	}
      else if (n->routes->attrs->source == RTS_BGP) // send out
	{
	  struct bgp_proto *p;

	  struct rte *routes = n->routes;

	  while (routes)
	    {
	      p = (struct bgp_proto *) n->routes->attrs->src->proto;
	      if (p && p->rlink_sock)
		{
		  break;
		}
	      routes = routes->next;
	    }

	  if (!routes || !p)
	    {
	      log (
	      L_ERR "irc_relay_message: [%d]: %I unreachable (upstream down)",
		   origin->sock, *ha);
	      free (pkt);
	      return 1;
	    }

	  log (L_DEBUG "irc_relay_message: [%d]: %I sending %u bytes (global)",
	       origin->sock, *ha, pkt->head.content_length);

	  return net_push_to_sendq (p->rlink_sock, pkt,
				    pkt->head.content_length,
				    NET_PUSH_SENDQ_ASSUME_PTR);
	}
      else
	{
	  log (
	      L_ERR "irc_relay_message: unknown protocol detected, check your configuration");
	  abort ();
	}

    }

  free (pkt);

  return 0;
}

void
_irc_startup (__sock_ca ca)
{
  _icf_global.max_hosts = UINT32_MAX >> _icf_global.pfx.len;

  dsp_register (dsp_table, DSP_CODE_IRC_MESSAGE, irc_deliver_relayed_msg, NULL);

  md_init (&_ntglobal.r, 4096);

  _ntglobal.ht = ht_create (4096);

  md_init (&server_ctx.loc_chans.r, 10000);
  server_ctx.loc_chans.ht = ht_create (10000);

  server_ctx.map_nick_to_ipa.ht = ht_create (100000);

  md_init (&ca->init_rc0, 16);
  md_init (&ca->init_rc1, 16);
  md_init (&ca->shutdown_rc0, 16);
  md_init (&ca->shutdown_rc1, 16);
  md_init (&ca->c_tasks, 16);
  md_init (&ca->ct_tasks, 16);
  md_init (&ca->t_tasks, 16);
  md_init (&ca->t_rcv, 2);

  struct in_addr a = ipa_to_in4 (_icf_global.listen_add);

  char *o = malloc (64);

  inet_ntop (AF_INET, &a, o, 64);

  char *p = malloc (16);

  snprintf (p, 16, "%d", _icf_global.listen_port);

  ca->host = o;
  ca->port = p;

  ca->policy.mode = ca->mode;
  ca->flags |= F_OPSOCK_LISTEN | F_OPSOCK_INIT_SENDQ;

  ca->socket_register = &_ntglobal.r;
  //ca->rc0 = net_gl_socket_init0;
  //ca->rc1 = net_gl_socket_init1;
  ca->proc = (_p_sc_cb) net_proto_irc_baseline;

  net_register_task (&ca->c_tasks, irc_rx_translate, NULL, 0);
  net_register_task (&ca->ct_tasks, irc_ping, NULL, 0);

  //net_register_task (&ca->t_rcv, NULL , NULL, 0);

  net_push_rc (&ca->init_rc0, (_t_rcall) net_generic_socket_init1, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_proto_irc_socket_init0, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_socket_init_enforce_policy, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_generic_socket_init0, 0);

  net_push_rc (&ca->shutdown_rc0, (_t_rcall) net_generic_socket_destroy0, 0);
  net_push_rc (&ca->shutdown_rc0, (_t_rcall) net_proto_irc_socket_destroy0, 0);

  if (!ca->policy.ssl_accept_timeout)
    {
      ca->policy.ssl_accept_timeout = 30;
    }

  if (!ca->policy.accept_timeout)
    {
      ca->policy.accept_timeout = 30;
    }

  if (!ca->policy.ssl_connect_timeout)
    {
      ca->policy.ssl_connect_timeout = 30;
    }

  if (!ca->policy.connect_timeout)
    {
      ca->policy.connect_timeout = 30;
    }

  if (!ca->policy.idle_timeout)
    {
      ca->policy.idle_timeout = 900;
    }

  if (!ca->policy.close_timeout)
    {
      ca->policy.close_timeout = 30;
    }

  if (!ca->policy.send_timeout)
    {
      ca->policy.send_timeout = 30;
    }

  ca->policy.max_sim_ip = 5;

  irc_crf_in_table = ht_create (128);

  ht_set (irc_crf_in_table, "USER", 4, irc_c_user, 0);
  ht_set (irc_crf_in_table, "NICK", 4, irc_c_nick, 0);
  ht_set (irc_crf_in_table, "USERHOST", 8, irc_c_userhost, 0);
  ht_set (irc_crf_in_table, "PONG", 4, irc_c_dummy, 0);
  ht_set (irc_crf_in_table, "JOIN", 4, irc_c_join, 0);
  ht_set (irc_crf_in_table, "PART", 4, irc_c_part, 0);
  ht_set (irc_crf_in_table, "PRIVMSG", 7, irc_c_privmsg, 0);

  br_routes.ht = ht_create (_icf_global.max_hosts + 32);
  md_init (&br_routes.r, _icf_global.max_hosts + 32);
  br_routes.r.flags |= F_MDA_REFPTR;

  net_open_listening_socket (ca->host, ca->port, ca);

  //static_add());

  /*pid_t c_pid, p_pid = getpid ();

   if ((c_pid = fork ()) == (pid_t) -1)
   {
   abort ();
   }

   if (0 == c_pid)
   {
   net_io_sched (p_pid);
   }*/
}
