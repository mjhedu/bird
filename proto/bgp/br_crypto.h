/*
 * br_crypto.h
 *
 *  Created on: Apr 11, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BR_CRYPTO_H_
#define PROTO_BGP_BR_CRYPTO_H_

#include <openssl/sha.h>

typedef struct pid_sha1
{
  unsigned char data[SHA_DIGEST_LENGTH];
} pid_sha1;

#endif /* PROTO_BGP_BR_CRYPTO_H_ */
