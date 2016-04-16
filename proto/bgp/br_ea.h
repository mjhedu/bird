/*
 * br_ea.h
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BR_EA_H_
#define PROTO_BGP_BR_EA_H_

#include "br_hasht.h"
#include "proto/static/static.h"

#include "brc_net_io.h"
#include "br_proto.h"

struct bgp_br_route *
br_route_add (struct proto *p, gtable_t *routes, struct static_route *r,
	      base_ea_payload *pl, size_t pl_size);
void
br_route_remove (gtable_t *routes, struct bgp_br_route * bbr);
int
br_net_exists (struct proto *p, ip_addr *ip, int masklen);


base_ea_payload *
br_get_route_payload (struct proto *p, struct prefix *pfx);
base_ea_payload *
br_get_net_payload (struct proto *p, net *n);
void
br_trigger_update_route (struct proto *p, struct prefix *pfx);
void
br_trigger_update (struct proto *p, net *n);

#include "nest/route.h"

static inline void
rte_update_int (struct proto *p, net *net, rte *new)
{
  rte_update2 (p->main_ahook, net, new, p->main_source);
}

typedef int
(*fit_callback) (__sock_o pso, net *n, void *data);
int
br_fib_iterator (__sock_o pso, fit_callback call, void *data);

#endif /* PROTO_BGP_BR_EA_H_ */
