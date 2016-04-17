/*
 * br_string.h
 *
 *  Created on: Apr 10, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BR_STRING_H_
#define PROTO_BGP_BR_STRING_H_

#include "brc_memory.h"

int
string_split (char *line, char dl, pmda output_t);
char *
md_string_join (pmda input_t, char dl, char *out, size_t max);

#endif /* PROTO_BGP_BR_STRING_H_ */