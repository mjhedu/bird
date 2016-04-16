/*
 * br_proto.c
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#include <stdio.h>

#include "nest/bird.h"
#include "brc_memory.h"
#include "brc_net_io.h"

#include "br_proto.h"


int
net_proto_br_socket_init0 (__sock_o pso)
{
  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;

    }

  return 0;
}

int
net_proto_br_socket_destroy0 (__sock_o pso)
{

  return 0;
}
