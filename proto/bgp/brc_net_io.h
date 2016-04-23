/*
 * net_io.h
 *
 *  Created on: Apr 8, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BRC_NET_IO_H_
#define PROTO_BGP_BRC_NET_IO_H_

#define F_OPSOCK_CONNECT                ((uint32_t)1 << 1)
#define F_OPSOCK_LISTEN                 ((uint32_t)1 << 2)
#define F_OPSOCK_TERM                   ((uint32_t)1 << 3)
#define F_OPSOCK_DISCARDED              ((uint32_t)1 << 4)
#define F_OPSOCK_SSL                    ((uint32_t)1 << 5)
#define F_OPSOCK_ACT                    ((uint32_t)1 << 6)
#define F_OPSOCK_ST_SSL_ACCEPT          ((uint32_t)1 << 7)
#define F_OPSOCK_ST_SSL_CONNECT         ((uint32_t)1 << 8)
#define F_OPSOCK_ST_CLEANUP_READY       ((uint32_t)1 << 9)
#define F_OPSOCK_TS_DISCONNECTED        ((uint32_t)1 << 10)
#define F_OPSOCK_ST_HOOKED              ((uint32_t)1 << 11)
#define F_OPSOCK_INIT_SENDQ             ((uint32_t)1 << 12)
#define F_OPSOCK_PROC_READY             ((uint32_t)1 << 13)
#define F_OPSOCK_SD_FIRST_DC            ((uint32_t)1 << 14)
#define F_OPSOCK_HALT_RECV              ((uint32_t)1 << 15)
#define F_OPSOCK_SKIP_SSL_SD            ((uint32_t)1 << 16)
#define F_OPSOCK_SSL_KEYCERT_L          ((uint32_t)1 << 17)
#define F_OPSOCK_IN                     ((uint32_t)1 << 18)
#define F_OPSOCK_PERSIST                ((uint32_t)1 << 19)
#define F_OPSOCK_ORPHANED               ((uint32_t)1 << 20)
#define F_OPSOCK_CS_MONOTHREAD          ((uint32_t)1 << 21)
#define F_OPSOCK_CS_NOASSIGNTHREAD      ((uint32_t)1 << 22)
#define F_OPSOCK_DETACH_THREAD          ((uint32_t)1 << 23)
#define F_OPSOCK_SIGNALING_INIT         ((uint32_t)1 << 24)
#define F_OPSOCK_NOKILL            	((uint32_t)1 << 25)
#define F_OPSOCK_ERROR            	((uint32_t)1 << 26)
#define F_OPSOCK_SDFLUSH            	((uint32_t)1 << 27)
#define F_OPSOCK_BRK            	((uint32_t)1 << 28)
#define F_OPSOCK_ESTABLISHED           	((uint32_t)1 << 29)
#define F_OPSOCK_RETRY           	((uint32_t)1 << 30)
#define F_OPSOCK_BIND           	((uint32_t)1 << 31)

#define F_ST_MISC00_ACT         ((uint32_t)1 << 1)
#define F_ST_MISC02_ACT         ((uint32_t)1 << 3)

#define		F_NW_STATUS_WAITSD	(uint32_t)1 << 1
#define		F_NW_STATUS_SOCKSD	(uint32_t)1 << 2
#define		F_NW_STATUS_READ	(uint32_t)1 << 3
#define		F_NW_STATUS_BRK	(uint32_t)1 << 4

#define SOCKET_OPMODE_LISTENER          0x1
#define SOCKET_OPMODE_RECIEVER          0x2

#define		F_NW_NO_SOCK_KILL	(uint32_t)1 << 1
#define		F_NW_HALT_PROC		(uint32_t)1 << 2
#define		F_NW_HALT_SEND		(uint32_t)1 << 3

#define NET_PUSH_SENDQ_ASSUME_PTR	((uint16_t)1 << 1)

#define F_OPSOCK_OPER_MODE              (F_OPSOCK_CONNECT|F_OPSOCK_LISTEN)
#define F_OPSOCK_STATES                 (F_OPSOCK_ST_SSL_ACCEPT|F_OPSOCK_ST_SSL_CONNECT)

#define SOCK_RECVB_SZ                   32768 + 256

#define SOCKET_STATUS_SKIP_RX_PROC	(uint32_t)1 << 16
#define SOCKET_STATUS_PFAIL		(uint32_t)1 << 18

#define MAX_NET_SENDQ			5000000

#include <stdio.h>

typedef int
(*_p_s_cb) (void *, void *, void *, void *);
typedef int
(*_t_rcall) (void *);
typedef int
(*_p_ssend) (void*, void *, size_t length);

#include <time.h>
#include <stdint.h>

typedef struct __sock_counters
{
  ssize_t b_read, t_read, l_read, session_read, session_write, total_write, con_retries;
} _sock_c;

typedef struct __sock_timers
{
  time_t last_act, last_proc, l_ping, l_rx, l_tx, misc00, misc01, misc02,
      misc03, l_est_try, l_delay_proc;
  uint32_t flags;
} _sock_tm;

typedef struct __sock_timeouts
{
  time_t sock_timeout;
} _sock_to;

typedef struct ___sock_policy
{
  uint32_t max_sim_ip, max_connects, max_connect_retries;
  uint32_t max_bps_in, max_bps_out;
  time_t idle_timeout, listener_idle_timeout, connect_timeout, accept_timeout,
      close_timeout, ssl_accept_timeout, ssl_connect_timeout, send_timeout;
  time_t connect_retries, connect_retry_timeout;
  time_t socket_initproc_delay;
  uint8_t mode;
  int ssl_verify;
} _net_sp, *__net_sp;

typedef struct ___ipr
{
  uint8_t ip[16];
  uint16_t port;
} _ipr, *__ipr;

typedef struct __sock_sendq_payload
{
  size_t size;
  void *data;
} _sock_sqp, *__sock_sqp;

#define SSENDQ_PAYLOAD_SIZE		sizeof(struct __sock_sendq_payload)

#include <openssl/ossl_typ.h>
#include "brc_memory.h"
#include <netdb.h>

typedef struct ___proc_ic_o
{
  _t_rcall call;
  uint32_t flags;
} _proc_ic_o, *__proc_ic_o;

#include <sys/socket.h>

typedef struct ___sock_o
{
  int sock;
  uint32_t flags, ac_flags, opmode;
  _p_s_cb rcv_cb, rcv_cb_t, rcv0, rcv1, rcv1_t;
  uint32_t children;
  mda init_rc0, init_rc1;
  mda init_rc0_ssl;
  mda shutdown_rc0, shutdown_rc1;
  _p_ssend send0;
  _t_rcall pcheck_r;
  struct addrinfo *res;
  void *cc;
  struct ___sock_o *parent;
  pmda host_ctx;
  ssize_t unit_size;
  _sock_c counters;
  uint16_t oper_mode;
  uint8_t mode;
  uint32_t status;
  SSL_CTX *ctx;
  SSL *ssl;
  int s_errno;
  int sslerr;
  _sock_tm timers;
  _sock_to limits;
  void *buffer0;
  size_t buffer0_len;
  mda sendq;
  void *ptr0;
  pthread_mutex_t mutex;
  void *va_p0, *va_p1, *va_p2, *va_p3, *va_p4;
  void *cp0;
  int32_t va_i0, va_i1;
  void *st_p0;
  void *st_p1; // thread-specific buffer
  _net_sp policy;
  void *sock_ca;
  _ipr ipr;
  pthread_t thread;
  mda tasks, c_tasks, t_tasks, ct_tasks, c_pre_tasks;
  mda t_rcv;
  struct in_addr bind_ip;
} _sock_o, *__sock_o;

typedef struct ___net_task
{
  int
  (*net_task_proc) (__sock_o pso, struct ___net_task *task);
  void *data;
  uint16_t flags;
} _net_task, *__net_task;

typedef int
(*_net_task_proc) (__sock_o pso, struct ___net_task *task);

struct ip4_hlim
{
  uint32_t min;
  uint32_t max;
} ip4_hlim;

int
net_register_task (pmda rt, _net_task_proc proc, void *data, uint16_t flags);
int
net_proc_tasks (__sock_o pso, pmda rc);

typedef int
(*_p_enumsr_cb) (__sock_o sock_o, void *arg);
typedef int
(*_p_sc_cb) (__sock_o sock_o);

typedef struct ___sock_cret
{
  __sock_o pso;
  uint32_t ret;
} _sock_cret, *__sock_cret;

#include <limits.h>

#define F_SOCA_PROCED	(uint32_t)1 << 10

typedef struct ___sock_create_args
{
  char *host, *port;
  uint32_t flags, ca_flags, ac_flags;
  _p_sc_cb proc;
  pmda socket_register, socket_register_ac, thread_register;
  char *ssl_cert;
  char *ssl_key;
  char *ssl_ca;
  char *ssl_cipher_list;
  ssize_t unit_size;
  void *st_p0;
  char b0[4096];
  char b1[PATH_MAX];
  char b2[PATH_MAX];
  char b3[PATH_MAX];
  char b4[64];
  char b5[64];
  uint8_t mode;
  _net_sp policy;
  mda init_rc0, init_rc1;
  mda init_rc0_ssl;
  mda shutdown_rc0, shutdown_rc1;
  _nn_2x64 opt0;
  _ipr ipr00;
  struct in_addr bind_ip;
  int ref_id;
  int
  (*scall) (char *addr, char *port, struct ___sock_create_args *args);
  void *va_p3;
  mda tasks, c_tasks, t_tasks, ct_tasks, t_rcv, c_pre_tasks;
} _sock_ca, *__sock_ca;

#include "br_hasht.h"

#include "nest/bird.h"

#ifdef IPV6

#define		IP_BYTE_LEN	16

#else

#define		IP_BYTE_LEN	4

#endif

int
net_socket_proc_delay (__sock_o pso, __net_task task);

void
ssl_init (void);
void
ssl_cleanup (void);
SSL_CTX*
ssl_init_ctx_server (__sock_o pso);
SSL_CTX*
ssl_init_ctx_client (__sock_o pso);
int
ssl_load_server_certs (SSL_CTX* ctx, char* cert_file, char* key_file, char *ca_file);

int
net_open_connection (char *addr, char *port, __sock_ca args);
int
net_conn_establish_async (__sock_o pso, __net_task task);

int
net_open_listening_socket (char *addr, char *port, __sock_ca args);

int
net_push_to_sendq (__sock_o pso, void *data, size_t size, uint16_t flags);
int
net_send_direct (__sock_o pso, const void *data, size_t size);

int
net_pop_rc (__sock_o pso, pmda rc);
int
net_push_rc (pmda rc, _t_rcall call, uint32_t flags);
int
net_socket_init_enforce_policy (__sock_o pso);
int
net_accept (__sock_o spso, pmda base, pmda threadr, void *data);
int
net_recv (__sock_o pso, pmda base, pmda threadr, void *data);
int
net_recv_ssl (__sock_o pso, pmda base, pmda threadr, void *data);
int
net_accept_ssl (__sock_o spso, pmda base, pmda threadr, void *data);
int
net_connect_ssl (__sock_o pso, pmda base, pmda threadr, void *data);
int
net_ssend_b (__sock_o pso, void *data, size_t length);
int
net_ssend_ssl_b (__sock_o pso, void *data, size_t length);
int
net_ssend_ssl (__sock_o pso, void *data, size_t length);
int
net_ssend (__sock_o pso, void *data, size_t length);

void
net_ca_free (__sock_ca ca);
void
net_ca_init (__sock_ca ca);
__sock_ca
net_ca_new (pmda base);

int
net_addr_to_ipr (__sock_o pso, __ipr out);

int
net_generic_socket_init0 (__sock_o pso);
int
net_generic_socket_init1 (__sock_o pso);
int
net_generic_socket_destroy0 (__sock_o pso);

uint16_t
net_get_addrinfo_port (__sock_o pso);
void *
net_get_addrinfo_ip (__sock_o pso);
const char *
net_get_addrinfo_ip_str (__sock_o pso, char *out, socklen_t len);

#include "brc_net_ext.h"

typedef int
(p_s_cb) (__sock_o spso, pmda base, pmda threadr, void *data);


#endif /* PROTO_BGP_BRC_NET_IO_H_ */
