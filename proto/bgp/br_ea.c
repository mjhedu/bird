/*
 * br_ea.c
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#include "nest/bird.h"

#include "br_hasht.h"
#include "brc_net_io.h"
#include "bgp.h"
#include "br_proto.h"

#include "br_ea.h"

struct bgp_br_route *
br_route_add (struct proto *p, gtable_t *routes, struct static_route *r,
	      base_ea_payload *pl, size_t pl_size)
{

  if (pl_size >= MAX_PAYLOAD_SIZE)
    {
      return NULL;
    }

  static_add (brc_st_proto->c.proto, brc_st_proto, r);

  if (!r->installed)
    {
      log (L_ERR "irc_c_user: %s: unable to install route", p->name);
      return NULL;
    }

  net *n = net_find (p->table, r->net, r->masklen);

  if (!n->routes)
    {
      log (
	  L_ERR "irc_c_user: %s: unable to verify installed route (net_find failed)",
	  p->name);
      return NULL;
    }

  eattr *e = ea_find (n->routes->attrs->eattrs, EA_CODE(EAP_BGP, BA_COMMUNITY));

  if (e)
    {
      unsigned int o_len = e->u.ptr->length;
      e->u.ptr = mb_realloc (
	  e->u.ptr, sizeof(struct adata) + MAX_PAYLOAD_SIZE + o_len + 1);
      e->u.ptr->length = pl_size;

      if (pl)
	{
	  memcpy (e->u.ptr->data, pl, pl_size);
	}

      struct bgp_br_route * bbr = calloc (1, sizeof(struct bgp_br_route));

      bbr->n = n;
      //bbr->r = r;
      //bbr->rt = n->routes->attrs;
      //bbr->e = e;

      bbr->pfx.addr = r->net;
      bbr->pfx.len = r->masklen;

      n->n.kflags |= F_FN_ALWAYS_PROPAGATE | F_FN_LOCORIGIN;

      rte_update_int (p, n, n->routes);

      return bbr;
    }
  else
    {
      return NULL;
    }

}

void
br_trigger_update_route (struct proto *p, struct prefix *pfx)
{

  net *n = net_find (p->table, pfx->addr, pfx->len);

  if (!n)
    {
      return;
    }

  br_trigger_update (p, n);

}

void
br_trigger_update (struct proto *p, net *n)
{

  if (!n->routes)
    {
      return;
    }

  rte_update_int (p, n, n->routes);

}

base_ea_payload *
br_get_route_payload (struct proto *p, size_t pl_size, struct prefix *pfx)
{
  net *n = net_find (p->table, pfx->addr, pfx->len);

  if (!n)
    {
      return NULL;
    }

  return br_get_net_payload (pl_size, n, n->routes);
}

base_ea_payload *
br_get_net_payload (size_t pl_size, net *n, struct rte *new)
{
  if (!new)
    {
      return NULL;
    }

  eattr *e = ea_find (new->attrs->eattrs, EA_CODE(EAP_BGP, BA_COMMUNITY));

  if (!e)
    {
      return NULL;
    }

  size_t l_size = pl_size + sizeof(base_ea_payload);

  if (!(e->u.ptr->length == l_size
      || e->u.ptr->length == l_size + sizeof(base_ea_head)))
    {
      return NULL;
    }

  /*base_ea_payload* _eap = (base_ea_payload*) e->u.ptr->data;

  if (!(_eap->server_flags.u1 == 255 && _eap->server_flags.u2 == 255))
    {
      return NULL;
    }*/

  base_ea_payload* eap = (base_ea_payload*) (e->u.ptr->data
      + sizeof(base_ea_head));

  return eap;
}

void
br_route_remove (gtable_t *routes, struct bgp_br_route * bbr)
{
  struct proto *p = brc_st_proto->c.proto;

  bbr->n->n.pso = NULL;
  bbr->n->n.kflags = 0;
  memset (&bbr->n->n.ea_cache, 0x0, sizeof(irc_ea_payload));

  rte_update (p, bbr->n, NULL);

}

int
br_net_exists (struct proto *p, ip_addr *ip, int masklen)
{
  net *n = net_find (p->table, *ip, masklen);

  if (!n)
    {
      return 0;
    }
  else
    {
      return 1;
    }

}

int
br_fib_iterator (__sock_o pso, fit_callback call, void *data)
{
  struct proto *p = brc_st_proto->c.proto;
  struct fib *fib = &p->table->fib;
  struct fib_iterator fit =
    { 0 };
  int r;

  FIB_ITERATE_INIT(&fit, fib);

  FIB_ITERATE_START(fib, &fit, f)
	  {
	    net *n = (net *) f;
	    r = call (pso, n, data);
	    if (r == -3)
	      {
		return r;
	      }
	  }
	FIB_ITERATE_END(f);

  return 0;
}

/*

 if (brc_ann_proto)
 {
 struct static_route *sr = calloc (1, sizeof(struct static_route));

 sr->dest = RTD_UNREACHABLE;
 sr->net = 237764608;
 sr->masklen = 16;

 struct proto *p = brc_ann_proto->c.proto;

 static_add (brc_ann_proto->c.proto, brc_ann_proto, sr);

 //eattr *e = ea_find(a->eattrs, EA_CODE(EAP_BGP, BA_ORIGINATOR_ID));
 net *n = net_get (p->table, sr->net, sr->masklen);

 if (n)
 {

 eattr *e = ea_find (n->routes->attrs->eattrs,
 EA_CODE(EAP_BGP, BA_COMMUNITY));

 u32 *gg = (u32*) e->u.ptr->data;

 u16*bb = (u16*) gg;

 printf ("%hu\n", bb[0]);

 //memset (e->u.ptr->data, 0x0, e->u.ptr->length);

 unsigned int o_len = e->u.ptr->length;

 e->u.ptr = mb_realloc (e->u.ptr, sizeof(struct adata) + 1024 + o_len + 1);
 e->u.ptr->length = 1024 + o_len;

 memcpy (&e->u.ptr->data[o_len], net_open_listening_socket , 1024 - o_len);



 rte_update (p, n, n->routes);

 //bb = (u16*) e->u.ptr->data;

 }

 }

 */
