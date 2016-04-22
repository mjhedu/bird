/*
 * br_main.h
 *
 *  Created on: Apr 16, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BR_MAIN_H_
#define PROTO_BGP_BR_MAIN_H_

#include "brc_memory.h"

mda _boot_pca;

int
br_main (void);

void
net_io_handler (int signal);

sigset_t default_set;

#endif /* PROTO_BGP_BR_MAIN_H_ */
