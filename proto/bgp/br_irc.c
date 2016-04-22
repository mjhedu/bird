/*
 * br_irc.c
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#include <unistd.h>
#include <stdio.h>
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
  base_ea_payload *eap = br_get_net_payload (sizeof(irc_ea_payload), n,
					     n->routes);

  if (!eap)
    {
      return NULL;
    }

  return (irc_ea_payload *) eap->data;

}

static irc_ea_payload *
get_irc_payload_pfx (struct proto *p, struct prefix *pfx)
{
  base_ea_payload *eap = br_get_route_payload (p, sizeof(irc_ea_payload), pfx);

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

#define T_MSG_ALPHANUM		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#define IRC_GEN_AC_CHR		"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
#define IRC_NICK_AC_CHR		"0123456789<>ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}"
#define IRC_USER_AC_CHR		T_MSG_ALPHANUM
#define IRC_REAL_AC_CHR		IRC_NICK_AC_CHR "* "

#define IRC_NICK_AC_CHR_C	"#" IRC_NICK_AC_CHR

#define IRC_CHAN_AC		"#0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_abcdefghijklmnopqrstuvwxyz"

static int
irc_payload_str_basevalid (char *chan, size_t l)
{
  size_t c;

  for (c = 0; c < l; c++)
    {
      if (!chan[c])
	{
	  return 0;
	}
    }

  return 1;
}

static int
irc_payload_str_validate_generic (char *chan, size_t l)
{
  if (irc_payload_str_basevalid (chan, l))
    {
      return 1;
    }

  if (strspn (chan, IRC_GEN_AC_CHR) != strlen (chan))
    {
      return 1;
    }
  return 0;
}

static int
irc_payload_str_validate2 (char *chan, size_t l)
{
  if (irc_payload_str_basevalid (chan, l))
    {
      return 1;
    }

  if (chan[0] == 0x0)
    {
      return 1;
    }
  if (strspn (chan, IRC_GEN_AC_CHR) != strlen (chan))
    {
      return 1;
    }
  return 0;
}

static int
irc_payload_validate_gen (char *n, size_t l, char *c)
{
  if (irc_payload_str_basevalid (n, l))
    {
      return 1;
    }

  if (strspn (n, c) != strlen (n))
    {
      return 1;
    }
  return 0;
}

static int
irc_payload_validate_gen2 (char *n, size_t l, char *c)
{
  if (n[0] == 0x0)
    {
      return 1;
    }

  if (irc_payload_str_basevalid (n, l))
    {
      return 1;
    }

  if (strspn (n, c) != strlen (n))
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

  if (pso->counters.b_read < 2)
    {
      return -3;
    }

  char *dl = strstr (msg, IRC_MESSAGE_DLMT);

  if (NULL == dl)
    {
      return -3;
    }

  size_t len = ((size_t) dl - (size_t) msg);

  if (!len)
    {
      log (L_WARN "net_proto_irc_baseline: [%d]: null message from %I",
	   pso->sock, *((ip_addr*) &pso->ipr.ip));
      //net_proto_irc_close_link (pso, "zero-length message recieved");
      goto finalize;
    }

  if (len > MAX_IRC_MSGLEN)
    {
      log (L_ERR "net_proto_irc_baseline: [%d]: message too large from %I",
	   pso->sock, *((ip_addr*) &pso->ipr.ip));
      net_proto_irc_close_link (pso, "message too large");
      return 0;
    }

  dl[0] = 0x0;

  pso->va_p3 = msg;
  if (net_proc_tasks (pso, &pso->tasks))
    {
      return 7;
    }

  finalize: ;
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
  else
    {
      msg = msg + len;
    }

  pso->counters.b_read -= len;

  return net_proto_irc_baseline (pso, base, n, msg);
}

static int
irc_validate_request (struct proto_irc_req * request)
{
  if (strspn (request->cmd, T_MSG_ALPHANUM) != strlen (request->cmd))
    {
      return 1;
    }

  return 0;
}

int
irc_rx_translate (__sock_o pso, struct ___net_task *task)
{

  struct proto_irc_req *request = irc_decode_request (pso->va_p3);

  if (!request)
    {
      return 1;
    }

  if (irc_validate_request (request))
    {
      log (L_ERR "irc_rx_translate: [%d]: request validation failed",
	   pso->sock);
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
	      || !strncmp (request->cmd, "NICK", 4)
	      || !strncmp (request->cmd, "PING", 4)
	      || !strncmp (request->cmd, "PONG", 4)))
	{
	  char b[1024];
	  snprintf (b, sizeof(b), "%s %s", uirc->u_settings.true_name,
		    request->cmd);
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
	  snprintf (b, sizeof(b), "%s %s", uirc->u_settings.true_name,
		    request->cmd);
	  r = irc_send_simple_response (pso, _icf_global.hostname, "421", b,
					"Unknown command");
	}
      else
	{
	  r = 0;
	}

    }

  md_free (&request->cmd_params);
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
	  if (data->trailer)
	    {
	      snprintf (b, MAX_IRC_MSGLEN, ":%s %s %s :%s\r\n", data->prefix,
			data->cmd, args, data->trailer);
	    }
	  else
	    {
	      snprintf (b, MAX_IRC_MSGLEN, ":%s %s %s\r\n", data->prefix,
			data->cmd, args);
	    }
	}
      else
	{
	  if (data->trailer)
	    {
	      snprintf (b, MAX_IRC_MSGLEN, ":%s %s :%s\r\n", data->prefix,
			data->cmd, data->trailer);
	    }
	  else
	    {
	      snprintf (b, MAX_IRC_MSGLEN, ":%s %s\r\n", data->prefix,
			data->cmd);
	    }
	}
    }
  else
    {
      if (data->cmd_params.offset)
	{
	  if (data->trailer)
	    {
	      snprintf (b, MAX_IRC_MSGLEN, "%s %s :%s\r\n", data->cmd, args,
			data->trailer);
	    }
	  else
	    {
	      snprintf (b, MAX_IRC_MSGLEN, "%s %s\r\n", data->cmd, args);
	    }
	}
      else
	{
	  if (data->trailer)
	    {
	      snprintf (b, MAX_IRC_MSGLEN, "%s :%s\r\n", data->cmd,
			data->trailer);
	    }
	  else
	    {
	      snprintf (b, MAX_IRC_MSGLEN, "%s\r\n", data->cmd);
	    }
	}
    }

  md_free (&data->cmd_params);

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
      md_init (&r.cmd_params);
      r.cmd_params.flags |= F_MDA_REFPTR;
      md_alloc (&r.cmd_params, 0, 0, n);
    }

  char *data = irc_format_response (&r);

  if (net_send_direct (pso, data, strlen (data)))
    {
      free (data);
      return 1;
    }

  free (data);

  return 0;

}

int
irc_send_response (__sock_o pso, struct proto_irc_resp *r)
{
  char *data = irc_format_response (r);

  if (net_send_direct (pso, data, strlen (data)))
    {
      free (data);
      return 1;
    }

  free (data);

  return 0;

}

struct proto_irc_req *
irc_decode_request (char *data)
{
  size_t req_len = strlen (data);

  if (!req_len)
    {
      log (L_ERR "irc_decode_request: null request");
      return NULL;
    }

  if (req_len > MAX_IRC_MSGLEN)
    {
      log (L_ERR "irc_decode_request: request too large");
      return NULL;
    }

  if (data[0] == 0x20)
    {
      log (L_ERR "uh?");
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
      md_init (&request->cmd_params);
      string_split (c, 0x20, &request->cmd_params);
    }

  return request;

}

static net *
irc_get_net_from_param (hashtable_t *ht, unsigned char *s, size_t l)
{
  ip_addr *ha = ht_get (ht, s, l);

  if (!ha)
    {
      return NULL;
    }

  net *n = net_find (brc_st_proto->c.proto->table, *ha, sizeof(ip_addr) * 8);

  if (!n || !n->routes || !n->routes->attrs)
    {
      return NULL;
    }

  return n;
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
      log (
      L_ERR "irc_part_chan: [%d]: BUG: global reference missing (part %s)",
	   pso->sock, chan);
      abort ();
    }

  lw_g->locks--;

  if (!lw_g->locks)
    {
      irc_ctx_remove_channel (lw_g, &server_ctx.loc_chans, chan, clen);
      md_free (&pic->sockref);
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

static void
irc_proto_cache_n (net *n, irc_ea_payload *pl, uint32_t flags)
{
  if (!pl->net_name[0])
    {
      return;
    }

  if (flags & F_IRC_CACHE_UPDATE)
    {
      ip_addr *ipa = malloc (sizeof(ip_addr));
      *ipa = n->n.prefix;
      ht_set (server_ctx.map_nick_to_ipa.ht, pl->net_name,
	      strlen (pl->net_name), ipa, 0);
    }
  else if (flags & F_IRC_CACHE_REMOVE)
    {
      server_ctx.map_nick_to_ipa.ht->flags |= F_HT_FREEVAL_ONCE;
      ht_remove (server_ctx.map_nick_to_ipa.ht, pl->net_name,
		 strlen (pl->net_name));
    }
}

static void
irc_proto_cache_gch (ip_addr *prefix, char *name, uint32_t flags)
{
  if (!name[0])
    {
      return;
    }

  size_t chlen = strlen (name);

  if (flags & F_IRC_CACHE_UPDATE)
    {
      gtable_t *item = ht_get (server_ctx.map_chan_to_ipas.ht, name, chlen);

      if (!item)
	{
	  item = calloc (1, sizeof(gtable_t));
	  md_init (&item->r);
	  item->r.flags |= F_MDA_REFPTR;
	  item->ht = ht_create (1000);
	  item->p = strdup (name);

	  ht_set (server_ctx.map_chan_to_ipas.ht, (unsigned char*) name, chlen,
		  item, 0);

	  md_alloc (&server_ctx.map_chan_to_ipas.r, 0, 0, item);
	  item->rp = server_ctx.map_chan_to_ipas.r.pos;
	}

      struct ipc_gch *igch = ht_get (item->ht, (unsigned char*) prefix,
				     sizeof(ip_addr));

      if (igch)
	{
	  return;
	}

      igch = malloc (sizeof(struct ipc_gch));
      igch->ipa = *prefix;

      md_alloc (&item->r, 0, 0, igch);

      igch->bref = item->r.pos;

      ht_set (item->ht, (unsigned char*) prefix, sizeof(ip_addr), igch, 0);

    }
  else if (flags & F_IRC_CACHE_REMOVE)
    {
      gtable_t *item = ht_get (server_ctx.map_chan_to_ipas.ht, name, chlen);

      if (!item)
	{
	  return;
	}

      struct ipc_gch *igch = ht_get (item->ht, (unsigned char*) prefix,
				     sizeof(ip_addr));

      if (!igch)
	{
	  return;
	}

      md_unlink (&item->r, igch->bref);
      free (igch);

      ht_remove (item->ht, (unsigned char*) prefix, sizeof(ip_addr));

      if (!item->r.offset)
	{
	  md_free (&item->r);
	  ht_destroy (item->ht);
	  ht_remove (server_ctx.map_chan_to_ipas.ht, (unsigned char*) name,
		     chlen);
	  md_unlink (&server_ctx.map_chan_to_ipas.r, (p_md_obj) item->rp);
	  free (item->p);
	  free (item);
	}

    }
}

int
irc_do_user_quit (__sock_o pso)
{
  struct proto_irc_u *uirc = pso->va_p1;

  char *bd = irc_assemble_response (uirc->u_settings.hostname, "QUIT", "none");
  size_t dlen = strlen (bd);

  MD_START(&uirc->chans.r, proto_irc_chan, d)
	{
	  irc_local_broadcast_to_chan (pso, d->name, bd, dlen);

	  irc_proto_cache_gch (&uirc->net.addr, d->name, F_IRC_CACHE_REMOVE);
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
      return 2;
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
      return 1; // can't join any more
    }

  // update caches

  gt_lwrap *lw_g = ht_get (server_ctx.loc_chans.ht, (unsigned char*) chan,
			   clen);
  proto_irc_chan *pic;

  if (!lw_g)
    {
      pic = calloc (1, sizeof(proto_irc_chan));
      md_init (&pic->sockref);
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

  irc_proto_cache_gch (&bbr->n->n.prefix, chan, F_IRC_CACHE_UPDATE);

  // propagate globally

  memcpy (&bbr->n->n.ea_cache, ipl, sizeof(irc_ea_payload));
  br_trigger_update (brc_st_proto->c.proto, bbr->n);

  // propagate locally

  char cb[MAX_CH_NAME_LEN + 2];
  snprintf (cb, MAX_CH_NAME_LEN + 1, "#%s", chan);
  char *bd = irc_assemble_response (uirc->u_settings.hostname, "JOIN", cb);
  size_t dlen = strlen (bd);
  net_send_direct (pso, bd, dlen);
  MD_START(&uirc->chans.r, proto_irc_chan, d)
	{
	  irc_local_broadcast_to_chan (pso, d->name, bd, dlen);
	}MD_END

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

  // propagate update locally

  char cb[MAX_CH_NAME_LEN + 2];
  snprintf (cb, MAX_CH_NAME_LEN + 1, "#%s", chan);
  char *bd = irc_assemble_response (uirc->u_settings.hostname, "PART", cb);
  size_t dlen = strlen (bd);
  net_send_direct (pso, bd, dlen);
  MD_START(&uirc->chans.r, proto_irc_chan, d)
	{
	  irc_local_broadcast_to_chan (pso, d->name, bd, dlen);
	}MD_END

  free (bd);

  // propagate globally

  memset (av, 0x0, sizeof(struct payload_chan));
  memcpy (&bbr->n->n.ea_cache, ipl, sizeof(irc_ea_payload));
  br_trigger_update (brc_st_proto->c.proto, bbr->n);

  // clear caches

  irc_proto_cache_gch (&bbr->n->n.prefix, chan, F_IRC_CACHE_REMOVE);
  irc_ctx_remove_channel (lw_l, &uirc->chans, chan, clen);
  irc_channel_cleanup_loc (pic, pso, chan);

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

      snprintf (ipl->net_name, MAX_CL_NAME_LEN, "%s",
		uirc->u_settings.net_name);
      snprintf (ipl->true_name, MAX_CL_NAME_LEN, "%s",
		uirc->u_settings.true_name);
      snprintf (ipl->user_name, MAX_IRC_USERNAME, "%s",
		uirc->u_settings.username);
      snprintf (ipl->real_name, MAX_IRC_REALNAME, "%s",
		uirc->u_settings.real_name);
      ipl->pnode_pxlen = _icf_global.pfx.len;

      if (pso->flags & F_OPSOCK_SSL)
	{
	  ipl->flags |= F_IRC_USER_SECURE;
	}

      //ipl->flags = F_IRC_UPDATE_AUTH | F_IRC_UPDATE_NAME;

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
				uirc->u_settings.true_name, b);

      snprintf (b, sizeof(b), "Your host is %s, running %s",
		_icf_global.hostname, "rbird-1.5.0.1");
      irc_send_simple_response (pso, _icf_global.hostname, "001",
				uirc->u_settings.true_name, b);

      snprintf (b, sizeof(b), "%s %s %s i nrt", uirc->u_settings.true_name,
		_icf_global.hostname, "rbird-1.5.0.1");
      irc_send_simple_response (pso, _icf_global.hostname, "004", b, NULL);

      snprintf (
	  b,
	  sizeof(b),
	  "%s MODES=12 CASEMAPPING=ascii NETWORK=%s CHANTYPES=# MAXCHANNELS=%u CHANLIMIT=#:%u CHANNELLEN=%u",
	  uirc->u_settings.true_name, _icf_global.netname,
	  PAYLOAD_CR_SIZE,
	  PAYLOAD_CR_SIZE,
	  MAX_CH_NAME_LEN);

      irc_send_simple_response (pso, _icf_global.hostname, "005", b,
				"are supported by this server");

      pso->flags |= F_OPSOCK_BRK;

    }
  else if (IS_FSETC(uirc->status, (IRC_STATUS_AUTHED|IRC_STATUS_HAS_NAME)))
    {
      irc_send_ping (pso, time (NULL));
    }

  return 0;

}

int
irc_send_ping (__sock_o pso, time_t t)
{
  char *data = malloc (32);

  snprintf (data, 32, "PING :%.8X\r\n", (unsigned int) t);

  if (net_push_to_sendq (pso, data, strlen (data),
  NET_PUSH_SENDQ_ASSUME_PTR))
    {
      free (data);
      return 1;
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
      return irc_send_ping (pso, t);
    }

  return 0;

}

#define IPA_TO_STR(ipa) char ip[128];do { struct in_addr a = ipa_to_in4 (ipa);inet_ntop (AF_INET, &a, ip, sizeof(ip)); } while(0);

#define MSG_IRC_HOSTNAME "%s!%s@%s"
#define MSG_IRC_USERHOST "%s*=+%s@%s"

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
  snprintf (b, sz, MSG_IRC_HOSTNAME, uirc->u_settings.true_name,
	    uirc->u_settings.username, ip);

}

void
irc_hostname_assemble_va (char *b, size_t sz, char *nick, char *user,
			  ip_addr ipa)
{

  IPA_TO_STR(ipa)
  snprintf (b, sz, MSG_IRC_HOSTNAME, nick, user, ip);
}

static void
irc_hostname_assemble_va_cf (char *cf, char *b, size_t sz, char *nick,
			     char *user, ip_addr ipa)
{

  IPA_TO_STR(ipa)
  snprintf (b, sz, cf, nick, user, ip);
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
irc_validate_chan_scope (char *name, size_t clen)
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
  size_t clen = strlen (name);

  if (irc_validate_chan_scope (name, clen))
    {
      return 1;
    }
  if (strspn (name, IRC_CHAN_AC) != clen)
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
irc_validate_nick (char *name)
{
  size_t len = strlen (name);
  if (len > MAX_CL_NAME_LEN)
    {
      return 1;
    }

  if (strspn (name, IRC_NICK_AC_CHR) != strlen (name))
    {
      return 1;
    }

  return 0;
}

static int
irc_build_names_list (__sock_o pso, net *n, void *data)
{
  irc_pkasm_state *pkasm = data;

  irc_ea_payload *ipl = &n->n.ea_cache;
  if (!ipl->true_name[0])
    {
      return 1;
    }

  char *chan = pkasm->data;

  if (!irc_find_pl_chan (ipl->joined, &chan[1]))
    {
      return 2;
    }

  size_t nl = strlen (ipl->true_name) + 1;

  pkasm->u2 += nl;

  pmda base = &pkasm->base;
  pmda md = base->pos->ptr;

  if (pkasm->u1 + pkasm->u2 > MAX_IRC_MSGLEN)
    {
      md = md_alloc (base, sizeof(mda), 0, NULL);
      md_init (md);
      pkasm->u2 = nl;
    }

  char *name = md_alloc (md, nl, 0, NULL);

  snprintf (name, nl, "%s", ipl->true_name);

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
  md_init (&rsp.cmd_params);
  rsp.cmd_params.flags |= F_MDA_REFPTR;
  md_alloc (&rsp.cmd_params, 0, 0, uirc->u_settings.true_name);
  md_alloc (&rsp.cmd_params, 0, 0, "@");
  md_alloc (&rsp.cmd_params, 0, 0, chan);
  rsp.prefix = _icf_global.hostname;
  rsp.trailer = "";

  irc_format_response_ex (pso, &rsp, irc_names_iterate, chan);

  md_free (&rsp.cmd_params);

  rsp.cmd = "366";
  md_init (&rsp.cmd_params);
  rsp.cmd_params.flags |= F_MDA_REFPTR;
  md_alloc (&rsp.cmd_params, 0, 0, uirc->u_settings.true_name);
  md_alloc (&rsp.cmd_params, 0, 0, chan);
  rsp.prefix = _icf_global.hostname;
  rsp.trailer = "End of /NAMES list.";

  irc_send_response (pso, &rsp);

  md_free (&rsp.cmd_params);

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

  md_init (&pkasm.base);
  pmda md = md_alloc (&pkasm.base, sizeof(mda), 0, NULL);
  md_init (md);

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

      if (net_send_direct (pso, rb, strlen (rb)))
	{
	  break;
	}

      md_free (md);

      ptr = ptr->next;
    }

  md_free (&pkasm.base);

  free (main_chunk);

  return 0;
}

C_PRELOAD(irc_c_join, ==0)

  if (irc_validate_chan_name (subject))
    {
      M1_CSTRING(ERR_CANNOTSENDTOCHAN_TEXT, subject)
      irc_send_simple_response (pso, _icf_global.hostname,
				_ST(ERR_CANNOTSENDTOCHAN), subject, _b);
      return 0;
    }

  str_to_lower (subject);

  int ret = irc_join_chan (pso, &subject[1]);
  if (ret == 1)
    {
      M1_CSTRING(ERR_TOOMANYCHANNELS_TEXT, subject)
      irc_send_simple_response (pso, _icf_global.hostname,
				_ST(ERR_TOOMANYCHANNELS), subject, _b);
    }
  else if (ret)
    {
      log (L_ERR "%d: failed to join channel: %s [%d]", pso->sock, subject,
	   ret);
    }

  return 0;
}

C_PRELOAD(irc_c_part, ==0)

  if (irc_validate_chan_name (subject))
    {
      M1_CSTRING(ERR_CANNOTSENDTOCHAN_TEXT, subject)
      irc_send_simple_response (pso, _icf_global.hostname,
				_ST(ERR_CANNOTSENDTOCHAN), subject, _b);
      return 0;
    }

  str_to_lower (subject);

  int ret = irc_part_chan (pso, &subject[1]);

  if (ret)
    {
      IRC_C_QUIT_M(0, "failed to part channel", subject)
    }

  return 0;
}

C_PRELOAD(irc_c_userhost, ==0)

  TO_LOWER(subject, subject_l, slen)

  net *n = irc_get_net_from_param (server_ctx.map_nick_to_ipa.ht, subject_l,
				   slen);

  if (!n)
    {
      M1_CSTRING(ERR_NOSUCHNICK_TEXT, subject)
      irc_send_simple_response (pso, _icf_global.hostname, _ST(ERR_NOSUCHNICK),
				subject, _b);
      return 0;
    }

  irc_ea_payload *pl = get_irc_payload (brc_st_proto->c.proto, n);

  char b[512];
  irc_hostname_assemble_va_cf (MSG_IRC_USERHOST, b, sizeof(b), pl->net_name,
			       pl->user_name, n->n.prefix);

  irc_send_simple_response (pso, _icf_global.hostname, "302",
			    uirc->u_settings.true_name, b);

  return 0;
}

C_PRELOAD(irc_c_list, <0)

  char b[4096];

  snprintf (b, sizeof(b), "%s Channel", uirc->u_settings.true_name);

  if (irc_send_simple_response (pso, _icf_global.hostname, "321", b,
				"Users  Name"))
    {
      return 0;
    }

  MD_START(&server_ctx.map_chan_to_ipas.r, gtable_t, cho)
	{
	  snprintf (b, sizeof(b), "%s #%s %llu", uirc->u_settings.true_name,
		    (char*) cho->p, (unsigned long long int) cho->r.offset);
	  if (irc_send_simple_response (pso, _icf_global.hostname, "322", b,
					"[+nrt] "))
	    {
	      break;
	    }
	}MD_END

  irc_send_simple_response (pso, _icf_global.hostname, "323",
			    uirc->u_settings.true_name, "End of /LIST");

  return 0;
}

C_PRELOAD(irc_c_userip, ==0)

  TO_LOWER(subject, subject_l, slen)

  net *n = irc_get_net_from_param (server_ctx.map_nick_to_ipa.ht, subject_l,
				   slen);

  if (!n)
    {
      M1_CSTRING(ERR_NOSUCHNICK_TEXT, subject)
      irc_send_simple_response (pso, _icf_global.hostname, _ST(ERR_NOSUCHNICK),
				subject, _b);
      return 0;
    }
  IPA_TO_STR(n->n.prefix);
  irc_send_simple_response (pso, _icf_global.hostname, "340",
			    uirc->u_settings.true_name, ip);

  return 0;
}

C_PRELOAD(irc_c_ping, ==0)
/*char b[32];
 snprintf (b, sizeof(b), "%u\n", (unsigned int)time (NULL));*/
  return irc_send_simple_response (pso, _icf_global.hostname, "PONG",
				   _icf_global.hostname, subject);
}

C_PRELOAD(irc_c_whois, ==0)
  if (irc_validate_nick (subject))
    {
      return 0;
    }

  char b[4096];

  if (slen > MAX_CL_NAME_LEN)
    {
      slen = slen > MAX_CL_NAME_LEN;
    }

  TO_LOWER(subject, subject_l, slen)

  net *n = irc_get_net_from_param (server_ctx.map_nick_to_ipa.ht, subject_l,
				   slen);

  if (!n)
    {
      M1_CSTRING(ERR_NOSUCHNICK_TEXT, subject)
      irc_send_simple_response (pso, _icf_global.hostname, _ST(ERR_NOSUCHNICK),
				subject, _b);
      return 0;
    }

  char nrl[4096];

  IPA_TO_STR(n->n.prefix);

  snprintf (nrl, sizeof(nrl), "%s %s", uirc->u_settings.true_name, subject);

  irc_ea_payload *pl = get_irc_payload (brc_st_proto->c.proto, n);

  snprintf (b, sizeof(b), "%s %s %s *", nrl, pl->user_name, ip);

  irc_send_simple_response (pso, _icf_global.hostname, "311", b, pl->real_name);

  if (n->n.ea_cache.flags & F_IRC_USER_SECURE)
    {
      irc_send_simple_response (pso, _icf_global.hostname, "671", nrl,
				"is using a Secure Connection");
    }

  irc_send_simple_response (pso, _icf_global.hostname, "318", nrl,
			    "End of /WHOIS list.");

  return 0;

}

C_PRELOAD(irc_c_privmsg, !=1)
  str_to_lower (subject);

  if (strspn (subject, IRC_NICK_AC_CHR_C) != slen)
    {
      return 0;
    }

  if (slen > MAX_NAME_LEN)
    {
      log (L_ERR "irc_c_privmsg: [%d]: target too long: %s", pso->sock,
	   subject);
      return 0;
    }

  if (strlen (r->trailer) > MAX_IRC_MSGLEN)
    {
      IRC_C_ERRQUIT_M(1, "message too large")
    }

  int ret = irc_relay_message (pso, r->cmd, subject, r->trailer);

  if (ret == 1)
    {
      M1_CSTRING(ERR_NOSUCHNICK_TEXT, subject)
      irc_send_simple_response (pso, _icf_global.hostname, _ST(ERR_NOSUCHNICK),
				subject, _b);
      return 0;
    }

  return 0;
}

C_PRELOAD(irc_c_cmodeis, == 0)
  str_to_lower (subject);

  if (irc_validate_chan_name (subject))
    {
      return 0;
    }

  struct proto_irc_resp rsp =
    { 0 };

  md_init (&rsp.cmd_params);
  rsp.cmd_params.flags |= F_MDA_REFPTR;

  rsp.prefix = _icf_global.hostname;
  rsp.cmd = _ST(RPL_CHANNELMODEIS);

  md_alloc (&rsp.cmd_params, 0, 0, uirc->u_settings.true_name);

  char bm[MAX_CH_NAME_LEN + 32];
  snprintf (bm, sizeof(bm), RPL_CHANNELMODEIS_TEXT, subject, "+nrt");

  md_alloc (&rsp.cmd_params, 0, 0, bm);

  /* FIXME: this only fabricates a response, since no chan modes exist */

  return irc_send_response (pso, &rsp);
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

  if (!nlen || nlen > MAX_CL_NAME_LEN || strspn (nick, IRC_NICK_AC_CHR) != nlen)
    {
      char b[1024];
      snprintf (b, sizeof(b), "%s %s",
		uirc->u_settings.true_name ? uirc->u_settings.true_name : "*",
		nick);

      irc_send_simple_response (pso, _icf_global.hostname,
				_ST(ERR_ERRONEUSNICKNAME), b,
				ERR_ERRONEUSNICKNAME_TEXT);
      return 0;
    }

  GET_NET_NAME(nick)

  ip_addr *ha = ht_get (server_ctx.map_nick_to_ipa.ht, net_name, nlen);

  if (ha)
    {
      if (!(IS_FSETC(uirc->status, IRC_STATUS_LOGGED_IN)
	  && !memcmp (ha, &uirc->net.addr, sizeof(ip_addr))))
	{
	  char b[1024];
	  snprintf (
	      b, sizeof(b), "%s %s",
	      uirc->u_settings.true_name ? uirc->u_settings.true_name : "*",
	      nick);

	  irc_send_simple_response (pso, _icf_global.hostname,
				    _ST(ERR_NICKNAMEINUSE), b,
				    ERR_NICKNAMEINUSE_TEXT);
	  return 0;
	}

    }

  if (uirc->u_settings.net_name)
    {
      free (uirc->u_settings.net_name);
    }

  if (uirc->u_settings.true_name)
    {
      free (uirc->u_settings.true_name);
    }

  uirc->u_settings.net_name = strdup (net_name);
  uirc->u_settings.true_name = strdup (nick);

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
		    uirc->u_settings.net_name);
	  snprintf (ipl->true_name, sizeof(ipl->true_name), "%s",
		    uirc->u_settings.true_name);
	  irc_proto_cache_n (bbr->n, &bbr->n->n.ea_cache,
	  F_IRC_CACHE_REMOVE);
	  irc_proto_cache_n (bbr->n, ipl, F_IRC_CACHE_UPDATE);
	  memcpy (&bbr->n->n.ea_cache, ipl, sizeof(irc_ea_payload));
	  br_trigger_update (brc_st_proto->c.proto, bbr->n);
	}

      char *data = irc_assemble_response (uirc->u_settings.hostname, "NICK",
					  uirc->u_settings.true_name);

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
	  free (data);
	  return 1;
	}

      free (data);

      irc_hostname_update (pso);

    }

  return 0;

}

int
irc_c_pong (__sock_o pso, void *data)
{
  struct proto_irc_u *uirc = pso->va_p1;

  if (!(uirc->status & IRC_STATUS_HAS_PONG))
    {
      uirc->status |= IRC_STATUS_HAS_PONG;

      return if_login (pso);
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
				uirc->u_settings.true_name,
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

  char *username = r->cmd_params.first->ptr;

  size_t ulen = strlen (username);
  size_t rnlen = strlen (r->trailer);

  if (!ulen || strspn (username, IRC_USER_AC_CHR) != ulen)
    {
      IRC_C_ERRQUIT_M(1, "illegal user name")
      return 0;
    }

  if (strspn (r->trailer, IRC_REAL_AC_CHR) != rnlen)
    {
      IRC_C_ERRQUIT_M(1, "illegal real name")
      return 0;
    }

  uirc->u_settings.username = strdup (r->cmd_params.first->ptr);
  //uirc->u_settings.ident = strdup (r->cmd_params.first->next->ptr);
  uirc->u_settings.real_name = strdup (r->trailer);

  uirc->status |= IRC_STATUS_AUTHED;

  int ret = irc_send_simple_response (pso, _icf_global.hostname, "NOTICE",
				      "AUTH", "Processing..");

  if (ret)
    {
      return ret;
    }

  return if_login (pso);

}

void
net_proto_irc_close_link (__sock_o pso, char *msg)
{
  char b[MAX_IRC_MSGLEN + 1];
  struct proto_irc_u *uirc = pso->va_p1;

  IPA_TO_STR(uirc->net.addr);
  snprintf (b, sizeof(b), LINK_CLOSE_TEXT, uirc->u_settings.true_name, ip, msg);

  net_send_direct (pso, b, strlen (b));
  pso->flags |= F_OPSOCK_TERM;
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
	  md_init (&p->chans.r);
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
	  if (uirc->u_settings.net_name)
	    {
	      ht_remove (server_ctx.map_nick_to_ipa.ht,
			 uirc->u_settings.net_name,
			 strlen (uirc->u_settings.net_name));
	      free (uirc->u_settings.net_name);
	    }
	  if (uirc->u_settings.true_name)
	    {
	      free (uirc->u_settings.true_name);
	    }
	  if (uirc->u_settings.real_name)
	    {
	      free (uirc->u_settings.real_name);
	    }
	  if (uirc->u_settings.hostname)
	    {
	      free (uirc->u_settings.hostname);
	    }

	  md_free (&uirc->chans.r);
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
	      if (net_send_direct (pso, data, len))
		{
		  return 1;
		}
	    }

	  ptr = ptr->next;
	}
    }

  return 0;
}

static int
irc_process_route_withdraw (net *n, uint32_t flags)
{
  irc_ea_payload *cache = (irc_ea_payload *) &n->n.ea_cache;

  if (!cache->net_name[0])
    {
      return 0;
    }

  int i;

  IPA_TO_STR(n->n.prefix)

  char h[1024];
  snprintf (h, sizeof(h), MSG_IRC_HOSTNAME, cache->true_name, cache->user_name,
	    ip);

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
      irc_proto_cache_gch (&n->n.prefix, name, F_IRC_CACHE_REMOVE);

    }

  free (data);

  irc_proto_cache_n (n, cache, F_IRC_CACHE_REMOVE);
  memset (cache, 0x0, sizeof(irc_ea_payload));

  return 0;
}

int
irc_proto_validate_update (net *n, struct rte *new)
{
  if (n->n.kflags & F_FN_LOCORIGIN)
    {
      return 0;
    }

  if (n->n.pxlen != 32)
    {
      return 0;
    }

  if (new->attrs->source != RTS_BGP)
    {
      return 0;
    }

  if (!new->attrs)
    {
      log (L_ERR "irc_proto_validate_update: %I: NULL route attributes",
	   n->n.prefix);
      return 1;
    }

  if (!new->attrs->eattrs)
    {
      log (
      L_WARN "irc_proto_validate_update: %I: NULL route extended attributes",
	   n->n.prefix);
      return 1;
    }

  base_ea_payload *bpl = br_get_net_payload (sizeof(irc_ea_payload), n, new);

  if (!bpl)
    {
      log (L_WARN "irc_proto_validate_update: %I: invalid/missing EA payload",
	   n->n.prefix);
      return 1;
    }

  irc_ea_payload *pl = (irc_ea_payload *) bpl->data;

  if (pl->pnode_pxlen < 8 || pl->pnode_pxlen > 8 * sizeof(ip_addr))
    {
      log (
	  L_WARN "irc_proto_proc_update: %I: EA payload has invalid parent node pxlen",
	  n->n.prefix);
      return 1;
    }

  if (irc_payload_validate_gen2 (pl->net_name, MAX_CL_NAME_LEN,
  IRC_NICK_AC_CHR) || irc_payload_validate_gen2 (pl->true_name, MAX_CL_NAME_LEN,
  IRC_NICK_AC_CHR)
      || irc_payload_validate_gen2 (pl->user_name, MAX_IRC_USERNAME,
      IRC_USER_AC_CHR)
      || irc_payload_validate_gen (pl->real_name, MAX_IRC_REALNAME,
      IRC_REAL_AC_CHR))
    {
      log (
	  L_WARN "irc_proto_proc_update: %I: EA payload failed string validation checks",
	  n->n.prefix);

      return 1;
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
	      M1_CSTRING(ERR_NICKCOLLISION_TEXT, pl->true_name)
	      irc_send_simple_response (nex->n.pso, _icf_global.hostname,
					_ST(ERR_NICKCOLLISION), pl->true_name,
					_b);
	      nex->n.pso->flags |= F_OPSOCK_TERM;
	    }

	  log (
	  L_ERR "irc_proto_proc_update: nick collision detected: %s | %I / %I",
	       pl->true_name, *ha, n->n.prefix);
	  return 1;
	}
    }

  return 0;

}

int
irc_proto_proc_update (net *n, uint32_t flags)
{
  if (!n)
    {
      log (L_FATAL"irc_proto_proc_update: NULL net");
      abort ();
    }

  if (n->n.kflags & F_FN_LOCORIGIN)
    {
      return 0;
    }

  if (n->n.pxlen != 32)
    {
      return 0;
    }

  if (!n->routes)
    {
      return irc_process_route_withdraw (n, flags);
    }

  if (n->routes->attrs->source != RTS_BGP)
    {
      return 0;
    }

  irc_ea_payload *pl = get_irc_payload (NULL, n);

  if (!pl)
    {
      log (L_ERR "nope");
      //abort ();
      return 0;
    }

  irc_ea_payload *cache = (irc_ea_payload *) &n->n.ea_cache;

  IPA_TO_STR(n->n.prefix)

  if (irc_payload_str_validate_generic (cache->net_name, MAX_CL_NAME_LEN)
      || irc_payload_str_validate_generic (cache->true_name, MAX_CL_NAME_LEN)
      || irc_payload_str_validate_generic (cache->user_name, MAX_IRC_USERNAME)
      || irc_payload_str_validate_generic (cache->real_name,
      MAX_IRC_REALNAME))
    {
      log (
      L_FATAL "irc_proto_proc_update: corrupt cache entry from %I",
	   n->n.prefix);
      abort ();
      //memset (cache, 0x0, sizeof(irc_ea_payload));
    }

  char hostname[1024];
  snprintf (hostname, sizeof(hostname), MSG_IRC_HOSTNAME, pl->true_name,
	    pl->user_name, ip);

  int i, j;
  uint8_t f = 0;

  if (cache->net_name[0])
    {
      if (strncmp (pl->true_name, cache->true_name, sizeof(pl->true_name)))
	{
	  TO_LOWER(pl->true_name, tn_lower, MAX_CL_NAME_LEN)

	  if (strncmp (tn_lower, pl->net_name, MAX_CL_NAME_LEN))
	    {
	      log (L_ERR "Faulty nick update for %I: '%s' != '%s'", n->n.prefix,
		   pl->net_name, pl->true_name);
	      return 0;
	    }

	  log (L_INFO "irc_proto_proc_update: name change: %s to %s",
	       cache->true_name, pl->true_name);

	  char h[1024];
	  snprintf (h, sizeof(h), MSG_IRC_HOSTNAME, cache->true_name,
		    cache->user_name, ip);

	  char *data = irc_assemble_response (h, "NICK", pl->true_name);
	  size_t dlen = strlen (data);

	  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
	    {
	      char *name = pl->joined[i].name;

	      if (!name[0])
		{
		  continue;
		}

	      if (irc_payload_validate_gen2 (name, MAX_CH_NAME_LEN,
	      IRC_CHAN_AC))
		{
		  log (
		  L_WARN "irc_proto_proc_update: %s: invalid channel string",
		       pl->true_name);
		  continue;
		}

	      irc_local_broadcast_to_chan (NULL, name, data, dlen);

	    }

	  free (data);

	  irc_proto_cache_n (n, cache, F_IRC_CACHE_REMOVE);
	  irc_proto_cache_n (n, pl, F_IRC_CACHE_UPDATE);
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

	  //log (L_DEBUG "%s parted %s", pl->true_name, name);

	  char c[MAX_CH_NAME_LEN + 2];
	  snprintf (c, sizeof(c), "#%s", name);

	  char *data = irc_assemble_response (hostname, "PART", c);

	  irc_local_broadcast_to_chan (NULL, name, data, strlen (data));

	  free (data);

	  irc_proto_cache_gch (&n->n.prefix, name, F_IRC_CACHE_REMOVE);

	  end1: ;

	}
    }
  else
    {
      irc_proto_cache_n (n, pl, F_IRC_CACHE_REMOVE);
      irc_proto_cache_n (n, pl, F_IRC_CACHE_UPDATE);
    }

  for (i = 0; i < PAYLOAD_CR_SIZE; i++)
    {

      char *name = pl->joined[i].name;

      if (!name[0])
	{
	  continue;
	}

      if (irc_payload_validate_gen2 (name, MAX_CH_NAME_LEN,
      IRC_CHAN_AC))
	{
	  log (L_WARN "irc_proto_proc_update: %s: invalid channel string",
	       pl->true_name);
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

      //log (L_DEBUG "%s joined %s", pl->true_name, name);

      char c[MAX_CH_NAME_LEN + 1];
      snprintf (c, MAX_CH_NAME_LEN, "#%s", name);

      char *data = irc_assemble_response (hostname, "JOIN", c);

      irc_local_broadcast_to_chan (NULL, name, data, strlen (data));

      free (data);

      irc_proto_cache_gch (&n->n.prefix, name, F_IRC_CACHE_UPDATE);

      end0: ;

    }

  if (!f)
    {
      memcpy (cache, pl, sizeof(irc_ea_payload));
    }

  return 0;
}

static void
irc_deliver_mrl_chan (__sock_o origin, struct proto_irc_rlmsg *msg)
{
  gt_lwrap *lw_g = ht_get (server_ctx.loc_chans.ht,
			   (unsigned char*) &msg->args[1],
			   strlen (msg->args) - 1);
  if (!lw_g)
    {
      log (
	  L_ERR "irc_deliver_rlmsg_chan: could not deliver to %s, channel not found locally",
	  msg->args);
      return;
    }

  proto_irc_chan *pic = lw_g->ptr;

  MD_START(&pic->sockref, _sock_o, dest)
	{
	  if (dest == origin)
	    {
	      continue;
	    }
	  if (irc_send_simple_response (dest, msg->hostname, msg->code,
					msg->args, msg->message))
	    {
	      break;
	    }
	}MD_END

}

static int
irc_deliver_relayed_msg (__sock_o pso, void *data)
{
  mrl_dpkt *pkt = data;

  struct proto_irc_rlmsg *msg = (struct proto_irc_rlmsg *) pkt->data;

  if (irc_payload_validate_gen (msg->args, sizeof(msg->args) - 1,
  IRC_NICK_AC_CHR_C))
    {
      log (
      L_WARN "irc_deliver_relayed_msg: payload from  %I has invalid target",
	   msg->code, pkt->source);
    }

  if (irc_payload_str_validate2 (msg->code, sizeof(msg->code) - 1)
      || irc_payload_str_basevalid (msg->message, sizeof(msg->message) - 1)
      || irc_payload_str_validate2 (msg->hostname, sizeof(msg->hostname) - 1))
    {
      log (L_WARN "irc_deliver_relayed_msg: invalid payload from %I", msg->code,
	   pkt->source.addr);
      return 1;
    }

  /*if (strncmp (msg->code, "PRIVMSG", 8))
   {
   log (L_WARN "irc_deliver_relayed_msg: [%I]: unknown code '%s'",
   pkt->source, msg->code);
   return 0;
   }*/

  log (L_DEBUG "irc_deliver_relayed_msg: [%I]: delivering '%s' to '%s'",
       pkt->source, msg->code, msg->args);

  if (msg->args[0] == 0x23)
    {
      irc_deliver_mrl_chan (pso, msg);
    }
  else
    {
      if (!pso)
	{
	  log (
	      L_ERR "irc_deliver_relayed_msg: [%d]: fixme: local path with no socket",
	      pso->sock);
	  abort ();
	}
      irc_send_simple_response (pso, msg->hostname, msg->code, msg->args,
				msg->message);
    }

  return 0;

}

static int
irc_relay_send_pkt_out (__sock_o origin, mrl_dpkt *pkt, net *n)
{
  struct rte *routes = mrl_baseline_lookup_best_path (n);

  if (!routes)
    {
      log (
      L_ERR "irc_relay_send_pkt_out: [%d]: %I/%d unreachable (upstream down)",
	   origin->sock, pkt->dest.addr, pkt->dest.len);
      return -2;
    }

  struct bgp_proto *p = (struct bgp_proto *) routes->attrs->src->proto;

  log (
  L_DEBUG "irc_relay_send_pkt_out: [%d]: %I/%d sending %u bytes (global)",
       origin->sock, pkt->dest.addr, pkt->dest.len, pkt->head.content_length);

  if (net_send_direct (p->rlink_sock, pkt, pkt->head.content_length))
    {
      return 1;
    }

  return 0;
}

int
irc_relay_message (__sock_o origin, char *code, char *target, char *message)
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
  pkt->source = uirc->net;

  int ret = 0;

  if (target[0] == 0x23)
    {
      irc_deliver_mrl_chan (origin, msg);

      gtable_t *item = ht_get (server_ctx.map_chan_to_ipas.ht,
			       (unsigned char*) &target[1],
			       strlen (msg->args) - 1);
      if (item)
	{
	  hashtable_t *ht = ht_create (128);
	  MD_START(&item->r, ip_addr, dest)
		{
		  net *n = net_find (brc_st_proto->c.proto->table, *dest,
				     (sizeof(ip_addr) * 8));

		  if (!n || !n->routes || !n->routes->attrs)
		    {
		      continue;
		    }

		  ip_addr ipnet =
		      *dest
			  & (((ip_addr) -1
			      << ((sizeof(ip_addr) * 8)
				  - n->n.ea_cache.pnode_pxlen)));

		  if (ht_get (ht, (unsigned char*) &ipnet, sizeof(ipnet)))
		    {
		      continue;
		    }

		  ht_set (ht, (unsigned char*) &ipnet, sizeof(ipnet), (void*) 1,
			  0);

		  n = net_find (brc_st_proto->c.proto->table, ipnet,
				n->n.ea_cache.pnode_pxlen);

		  if (!n || !n->routes || !n->routes->attrs)
		    {
		      continue;
		    }

		  if (n->routes->attrs->source != RTS_BGP)
		    {
		      continue;
		    }

		  pkt->dest.addr = ipnet;
		  pkt->dest.len = (unsigned int) n->n.pxlen;
		  pkt->code = PROT_RELAY_FORWARD;
		  pkt->ttl = 100;

		  irc_relay_send_pkt_out (origin, pkt, n);

		}MD_END
	  ht_destroy (ht);
	}
      else
	{
	  log (L_DEBUG "irc_relay_message: [%d]: %s doesn't exist globally",
	       origin->sock, target);
	}
    }
  else
    {
      ip_addr *ha = ht_get (server_ctx.map_nick_to_ipa.ht, msg->args,
			    strlen (target));

      if (!ha)
	{
	  log (L_ERR "irc_relay_message: [%d]: %s: unreachable (intmap)",
	       origin->sock, target);
	  ret = 1;
	  goto cleanup;
	}

      pkt->dest.addr = *ha;
      pkt->dest.len = sizeof(ip_addr) * 8;
      pkt->code = PROT_RELAY_FORWARD;
      pkt->ttl = 100;

      net *n = net_find (brc_st_proto->c.proto->table, pkt->dest.addr,
			 pkt->dest.len);

      if (!n || !n->routes || !n->routes->attrs || !n->routes->attrs->src)
	{
	  log (L_ERR "irc_relay_message: [%d]: %I/%d unreachable (no path)",
	       origin->sock, pkt->dest.addr, pkt->dest.len);
	  ret = 1;
	  goto cleanup;
	}

      if (n->routes->attrs->source == RTS_STATIC) // deliver locally
	{
	  /*log (L_DEBUG "irc_relay_message: [%d]: %I sending %u bytes (local)",
	   origin->sock, *ha, pkt->head.content_length);*/

	  irc_send_simple_response (n->n.pso, msg->hostname, msg->code,
				    msg->args, msg->message);
	}
      else if (n->routes->attrs->source == RTS_BGP) // send out
	{
	  if (irc_relay_send_pkt_out (origin, pkt, n))
	    {
	      ret = 1;
	      goto cleanup;
	    }
	}
      else
	{
	  log (
	      L_ERR "irc_relay_message: unknown source protocol on route %I/%d, check your configuration",
	      pkt->dest.addr, pkt->dest.len);
	  abort ();
	}

    }

  cleanup: ;

  free (pkt);

  return ret;
}

static int
_irc_create_listening_socket (__sock_ca ca)
{

  struct in_addr a = ipa_to_in4 (*((ip_addr*) ca->ipr00.ip));

  char *o = malloc (64);
  inet_ntop (AF_INET, &a, o, 64);

  char *p = malloc (16);
  snprintf (p, 16, "%hu", ca->ipr00.port);

  ca->host = o;
  ca->port = p;

  ca->policy.mode = ca->mode;
  ca->flags |= F_OPSOCK_LISTEN | F_OPSOCK_INIT_SENDQ;

  if (ca->flags & F_OPSOCK_SSL)
    {
      if (!ca->ssl_key)
	{
	  ca->ssl_key = _icf_global.default_ssl_key;
	}

      if (!ca->ssl_cert)
	{
	  ca->ssl_cert = _icf_global.default_ssl_cert;
	}

      if (!ca->ssl_ca)
	{
	  ca->ssl_ca = _icf_global.default_ssl_ca;
	}

      ca->ssl_cipher_list = _icf_global.default_ssl_cipher_list;
    }

  ca->proc = (_p_sc_cb) net_proto_irc_baseline;
  net_register_task (&ca->c_tasks, irc_rx_translate, NULL, 0);
  net_register_task (&ca->ct_tasks, irc_ping, NULL, 0);

  net_push_rc (&ca->init_rc0, (_t_rcall) net_generic_socket_init1, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_proto_irc_socket_init0, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_socket_init_enforce_policy, 0);
  net_push_rc (&ca->init_rc0, (_t_rcall) net_generic_socket_init0, 0);

  net_push_rc (&ca->shutdown_rc0, (_t_rcall) net_generic_socket_destroy0, 0);
  net_push_rc (&ca->shutdown_rc0, (_t_rcall) net_proto_irc_socket_destroy0, 0);

  ca->policy.ssl_accept_timeout = 30;
  ca->policy.accept_timeout = 30;
  ca->policy.ssl_connect_timeout = 30;
  ca->policy.connect_timeout = 30;
  ca->policy.idle_timeout = 900;
  ca->policy.close_timeout = 30;
  ca->policy.send_timeout = 30;
  ca->policy.max_sim_ip = 5;

  int ret = net_open_listening_socket (ca->host, ca->port, ca);

  if (ret)
    {
      char b[4096];

      if (ret < 0)
	{
	  strerror_r (errno, b, sizeof(b));
	}
      else
	{
	  snprintf (b, sizeof(b), "%d", errno);
	}
      die ("bind to %s:%s failed: %s", ca->host, ca->port, b);

    }

  return 0;
}

static void
_verify_irc_settings (void)
{
  if (_icf_global.netname == NULL)
    {
      die ("missing netname");
    }

  if (_icf_global.hostname == NULL)
    {
      die ("missing hostname");
    }
}

void
_irc_startup (pmda bpca)
{
  _verify_irc_settings ();

  dsp_register (dsp_table, DSP_CODE_IRC_MESSAGE, irc_deliver_relayed_msg,
  NULL);

  md_init (&_ntglobal.r);

  _ntglobal.ht = ht_create (4096);

  md_init (&server_ctx.loc_chans.r);
  server_ctx.loc_chans.ht = ht_create (10000);

  server_ctx.map_nick_to_ipa.ht = ht_create (100000);
  server_ctx.map_chan_to_ipas.ht = ht_create (10000);
  md_init (&server_ctx.map_chan_to_ipas.r);
  server_ctx.map_chan_to_ipas.r.flags |= F_MDA_REFPTR;

  irc_crf_in_table = ht_create (512);

  ht_set (irc_crf_in_table, "USER", 4, irc_c_user, 0);
  ht_set (irc_crf_in_table, "NICK", 4, irc_c_nick, 0);
  ht_set (irc_crf_in_table, "USERHOST", 8, irc_c_userhost, 0);
  ht_set (irc_crf_in_table, "PONG", 4, irc_c_pong, 0);
  ht_set (irc_crf_in_table, "JOIN", 4, irc_c_join, 0);
  ht_set (irc_crf_in_table, "PART", 4, irc_c_part, 0);
  ht_set (irc_crf_in_table, "PRIVMSG", 7, irc_c_privmsg, 0);
  ht_set (irc_crf_in_table, "NOTICE", 6, irc_c_privmsg, 0);
  ht_set (irc_crf_in_table, "MODE", 4, irc_c_cmodeis, 0);
  ht_set (irc_crf_in_table, "WHOIS", 5, irc_c_whois, 0);
  ht_set (irc_crf_in_table, "USERIP", 5, irc_c_userip, 0);
  ht_set (irc_crf_in_table, "LIST", 4, irc_c_list, 0);
  ht_set (irc_crf_in_table, "PING", 4, irc_c_ping, 0);

  ht_set (irc_crf_in_table, "whois", 5, irc_c_whois, 0);
  ht_set (irc_crf_in_table, "userip", 6, irc_c_userip, 0);
  ht_set (irc_crf_in_table, "list", 4, irc_c_list, 0);

  br_routes.ht = ht_create (_icf_global.max_hosts + 32);
  md_init (&br_routes.r);
  br_routes.r.flags |= F_MDA_REFPTR;

  MD_START(&_icf_global.binds, _sock_ca, ca)
	{
	  ca->socket_register = &_ntglobal.r;
	  if (_irc_create_listening_socket (ca))
	    {
	      break;
	    }
	}MD_END

  md_free (&_icf_global.binds);

  //static_add());
}

void
_mrl_startup (__sock_ca ca)
{

  md_init (&msg_relay_socks.r);

  msg_relay_socks.ht = ht_create (4096);

  struct in_addr a = ipa_to_in4 (*((ip_addr*) ca->ipr00.ip));

  char *o = malloc (64);
  inet_ntop (AF_INET, &a, o, 64);
  char *p = malloc (16);

  snprintf (p, 16, "%d", ca->ipr00.port);

  ca->host = o;
  ca->port = p;

  if (ca->flags & F_OPSOCK_SSL)
    {
      if (!ca->ssl_key)
	{
	  ca->ssl_key = _icf_global.default_ssl_key;
	}

      if (!ca->ssl_cert)
	{
	  ca->ssl_cert = _icf_global.default_ssl_cert;
	}

      if (!ca->ssl_ca)
	{
	  ca->ssl_ca = _icf_global.default_ssl_ca;
	}

      ca->ssl_cipher_list = _icf_global.default_ssl_cipher_list;
    }

  mrl_init_ca_default (ca);

  mrl_fill_ca_default (ca);

  net_open_listening_socket (ca->host, ca->port, ca);

}
