#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <errno.h>

#include <pthread.h>
#include <sys/ioctl.h>

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "brc_memory.h"
#include "proto/static/static.h"

#define __USE_GNU 1

#include <fcntl.h>
#include <unistd.h>

#include "br_ea.h"
#include "br_proto.h"
#include "br_irc.h"

#include "brc_net_io.h"

static pthread_mutex_t *mutex_buf = NULL;

static void
ssl_locking_function (int mode, int n, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    {
      pthread_mutex_lock (&mutex_buf[n]);
    }
  else
    {
      pthread_mutex_unlock (&mutex_buf[n]);
    }
}

static unsigned long
ssl_id_function (void)
{
  return ((unsigned long) pthread_self ());
}

void
ssl_init (void)
{
  int i;

  //CRYPTO_malloc_debug_init();

  CRYPTO_mem_ctrl (CRYPTO_MEM_CHECK_ON);
  /*mutex_buf = calloc (1, CRYPTO_num_locks () * sizeof(pthread_mutex_t));
   if (mutex_buf == NULL)
   {
   log (L_ERR "ssl_init: could not allocate mutex memory");
   abort ();
   }
   for (i = 0; i < CRYPTO_num_locks (); i++)
   {
   pthread_mutex_init (&mutex_buf[i], NULL);
   }*/

  //setenv ("OPENSSL_DEFAULT_ZLIB", "1", 1);
  //CRYPTO_set_locking_callback (ssl_locking_function);
  //CRYPTO_set_id_callback (ssl_id_function);
  SSL_library_init ();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings ();

  if (!RAND_load_file ("/dev/urandom", 4096))
    {
      log (L_ERR "ssl_init: no bytes were added to PRNG from seed source");
      abort ();
    }

  COMP_METHOD *comp_method = COMP_zlib ();

  if (comp_method != NULL)
    {
      SSL_COMP_add_compression_method (1, comp_method);
    }

}

void
ssl_cleanup (void)
{
  int i;

  if (mutex_buf == NULL)
    {
      return;
    }

  /*CRYPTO_set_dynlock_create_callback(NULL);
   CRYPTO_set_dynlock_lock_callback(NULL);
   CRYPTO_set_dynlock_destroy_callback(NULL);*/

  //CRYPTO_set_locking_callback (NULL);
  //CRYPTO_set_id_callback (NULL);
  for (i = 0; i < CRYPTO_num_locks (); i++)
    {
      pthread_mutex_destroy (&mutex_buf[i]);
    }

  free (mutex_buf);
  mutex_buf = NULL;

  FIPS_mode_set (0);

  EVP_cleanup ();
  CRYPTO_cleanup_all_ex_data ();
  ERR_remove_state (0);
  ERR_free_strings ();

}

static void
announce_ssl_connect_event (__sock_o pso, char *ev)
{
  int eb;

  int sb = SSL_CIPHER_get_bits (SSL_get_current_cipher (pso->ssl), &eb);

  char cd[255];

  char *p = SSL_CIPHER_description (SSL_get_current_cipher (pso->ssl), cd,
				    sizeof(cd));
  char *pc;

  if (p && (pc = strchr (p, 0xA)))
    {
      pc[0] = 0x0;
    }

  log (L_DEBUG "%s: %d, %s (%d / %d) - %s", ev, pso->sock,
       SSL_get_cipher(pso->ssl), eb, sb,
       SSL_CIPHER_get_version (SSL_get_current_cipher (pso->ssl)));

  log (L_DEBUG "SSL_CIPHER_description: %d, %s", pso->sock, p);

}

static void
ssl_init_setctx (__sock_o pso)
{
  SSL_CTX_set_options(pso->ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

  __sock_ca ca = pso->sock_ca;

  if (!SSL_CTX_set_cipher_list (
      pso->ctx,
      ca->ssl_cipher_list ? ca->ssl_cipher_list : "-ALL:ALL:-ADH:-aNULL"))
    {
      log (L_ERR "ssl_init_setctx: [%d]: SSL_CTX_set_cipher_list failed: %s",
	   pso->sock, ca->ssl_cipher_list);
      pso->flags |= F_OPSOCK_TERM;
    }

  SSL_CTX_set_verify (pso->ctx, pso->policy.ssl_verify, NULL);

  //SSL_CTX_set_mode(pso->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
}

SSL_CTX*
ssl_init_ctx_server (__sock_o pso)
{
  if ((pso->ctx = SSL_CTX_new (SSLv23_server_method ())) == NULL)
    { /* create new context from method */
      return NULL;
    }

  ssl_init_setctx (pso);

  //SSL_CTX_sess_set_cache_size(pso->ctx, 1024);
  //SSL_CTX_set_session_cache_mode(pso->ctx, SSL_SESS_CACHE_BOTH);

  return pso->ctx;
}

SSL_CTX*
ssl_init_ctx_client (__sock_o pso)
{
  if ((pso->ctx = SSL_CTX_new (SSLv23_client_method ())) == NULL)
    { /* create new context from method */
      return NULL;
    }

  ssl_init_setctx (pso);

  //SSL_CTX_sess_set_cache_size(pso->ctx, 1024);
  //SSL_CTX_set_session_cache_mode(pso->ctx, SSL_SESS_CACHE_SERVER);

  return pso->ctx;
}

int
ssl_load_client_certs (SSL* ssl, char* cert_file, char* key_file)
{
  /* set the local certificate from CertFile */
  if (SSL_use_certificate_file (ssl, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
      return 1;
    }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_use_PrivateKey_file (ssl, key_file, SSL_FILETYPE_PEM) <= 0)
    {
      return 2;
    }

  /* verify private key */
  if (!SSL_check_private_key (ssl))
    {
      log (L_ERR "private key does not match the public certificate");
      return 3;
    }

  return 0;
}

int
ssl_load_server_certs (SSL_CTX* ctx, char* cert_file, char* key_file,
		       char *ca_file)
{
  if (SSL_CTX_load_verify_locations (ctx, cert_file, NULL) != 1)
    {
      return 1;
    }

  if (SSL_CTX_set_default_verify_paths (ctx) != 1)
    {
      return 1;
    }

  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file (ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
      return 1;
    }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file (ctx, key_file, SSL_FILETYPE_PEM) <= 0)
    {
      return 2;
    }

  if (ca_file)
    {
      STACK_OF(X509_NAME) *cert_names;

      cert_names = SSL_load_client_CA_file (ca_file);
      if (cert_names != NULL)
	SSL_CTX_set_client_CA_list (ctx, cert_names);
      else
	return 1;

      if (SSL_CTX_load_verify_locations (ctx, ca_file, NULL) != 1)
	{
	  return 1;
	}
    }

  /* verify private key */
  if (!SSL_CTX_check_private_key (ctx))
    {
      log (L_ERR "private key does not match the public certificate");
      return 3;
    }

  return 0;
}

static void
ssl_show_client_certs (__sock_o pso, SSL* ssl)
{
  X509 *cert;

  cert = SSL_get_peer_certificate (ssl); /* Get certificates (if available) */
  if (cert != NULL)
    {
      char ssl_cb[1024];
      char *line;

      //print_str("NOTICE: Peer certificates:");
      line = X509_NAME_oneline (X509_get_subject_name (cert), ssl_cb,
				sizeof(ssl_cb));
      log (L_INFO "[%d]: subject: %s", pso->sock, line);
      line = X509_NAME_oneline (X509_get_issuer_name (cert), ssl_cb,
				sizeof(ssl_cb));
      log (L_INFO "[%d]: issuer: %s", pso->sock, line);
      X509_free (cert);
    }
  else
    {
      log (L_DEBUG "ssl_show_client_certs: [%d]: no client certs", pso->sock);
    }
}

static int
bind_socket (int fd, struct addrinfo *aip)
{
  int y = 1;

  if (setsockopt (fd, SOL_SOCKET,
  SO_REUSEADDR,
		  &y, sizeof(int)))
    {
      return 100;
    }

  int ret;

  if ((ret = fcntl (fd, F_SETFL, O_NONBLOCK)) == -1)
    {
      close (fd);
      return 101;;
    }

  if (bind (fd, aip->ai_addr, aip->ai_addrlen) == -1)
    {
      return 111;
    }

  if (listen (fd, 5))
    {
      return 122;
    }

  return 0;
}

static int
net_chk_timeout (__sock_o pso)
{
  int r = 0;

  if (pso->policy.idle_timeout /* idle timeout (data recieve)*/
  && (time (NULL) - pso->timers.l_rx) >= pso->policy.idle_timeout)
    {
      log (L_WARN "idle timeout occured on socket %d [%u]", pso->sock,
	   time (NULL) - pso->timers.l_rx);
      if (pso->flags & F_OPSOCK_SSL)
	{
	  //pso->flags |= F_OPSOCK_SKIP_SSL_SD;
	}
      r = 1;
    }

  return r;
}

static int
net_listener_chk_timeout (__sock_o pso)
{
  int r = 0;

  if (pso->policy.listener_idle_timeout)
    {
      time_t last_act = (time (NULL) - pso->timers.last_act);
      if (last_act >= pso->policy.listener_idle_timeout)
	{
	  log (L_WARN
	  "idle timeout occured on listener socket %d [%u]",
	       pso->sock, last_act);
	  r = 1;
	}
      else
	{
	  r = -1;
	}
    }

  return r;

}

static void
net_failclean (__sock_o so)
{
  md_free (&so->sendq);
  md_free (&so->init_rc0);
  md_free (&so->init_rc1);
  md_free (&so->shutdown_rc0);
  md_free (&so->shutdown_rc1);
  md_free (&so->init_rc0_ssl);
  md_free (&so->c_tasks);
  md_free (&so->ct_tasks);
  md_free (&so->t_tasks);
  md_free (&so->tasks);
  md_free (&so->t_rcv);
}

static void
net_open_connection_cleanup (pmda sockr, struct addrinfo *aip, int fd)
{
  close (fd);
  if (aip)
    freeaddrinfo (aip);
  md_unlink (sockr, sockr->pos);
}

#define NET_MSG_FAIL(m) char b[1024]; strerror_r(errno, b, sizeof(b)); log(L_ERR "[%s:%s] %s: %s",addr,port,m, b);

int
net_open_connection (char *addr, char *port, __sock_ca args)
{
  struct addrinfo *aip;
  struct addrinfo hints =
    { 0 };

  int fd;

  hints.ai_flags = AI_ALL | AI_ADDRCONFIG;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo (addr, port, &hints, &aip))
    {
      NET_MSG_FAIL("getaddrinfo")
      return -1;
    }

  if ((fd = socket (aip->ai_family, aip->ai_socktype, aip->ai_protocol)) == -1)
    {
      NET_MSG_FAIL("failed to create socket")
      freeaddrinfo (aip);
      return -2;
    }

  int ret;

  if ((ret = fcntl (fd, F_SETFL, O_NONBLOCK)) == -1)
    {
      NET_MSG_FAIL("fcntl")
      freeaddrinfo (aip);
      close (fd);
      return -4;
    }

  if (args->flags & F_OPSOCK_BIND)
    {
      struct sockaddr_in localaddr;
      localaddr.sin_family = aip->ai_family;
      localaddr.sin_addr = args->bind_ip;
      localaddr.sin_port = 0;

      if (bind (fd, (struct sockaddr *) &localaddr, sizeof(localaddr)) == -1)
	{
	  NET_MSG_FAIL("bind")
	  freeaddrinfo (aip);
	  close (fd);
	  return -5;
	}

    }

  __sock_o pso;

  if (!(pso = md_alloc (args->socket_register, sizeof(_sock_o), 0, NULL)))
    {
      freeaddrinfo (aip);
      close (fd);
      return 9;
    }

  pso->res = aip;

  pso->sock = fd;
  pso->oper_mode = SOCKET_OPMODE_RECIEVER;
  pso->flags = args->flags | F_OPSOCK_CONNECT;
  pso->pcheck_r = (_t_rcall) net_chk_timeout;
  pso->timers.last_act = time (NULL);
  pso->timers.l_rx = pso->timers.last_act;
  pso->st_p0 = args->st_p0;
  pso->policy = args->policy;
  pso->sock_ca = (void*) args;
  pso->bind_ip = args->bind_ip;

  net_addr_to_ipr (pso, &pso->ipr);

  md_copy (&args->init_rc0, &pso->init_rc0, sizeof(_proc_ic_o), NULL);
  md_copy (&args->init_rc1, &pso->init_rc1, sizeof(_proc_ic_o), NULL);
  md_copy (&args->shutdown_rc0, &pso->shutdown_rc0, sizeof(_proc_ic_o),
  NULL);
  md_copy (&args->shutdown_rc1, &pso->shutdown_rc1, sizeof(_proc_ic_o),
  NULL);
  md_copy (&args->init_rc0_ssl, &pso->init_rc0_ssl, sizeof(_proc_ic_o),
  NULL);
  md_copy (&args->tasks, &pso->tasks, sizeof(_net_task),
  NULL);
  md_copy (&args->t_rcv, &pso->t_rcv, sizeof(_net_task),
  NULL);

  md_copy (&args->c_pre_tasks, &pso->c_pre_tasks, sizeof(_net_task),
  NULL);
  md_copy (&args->ct_tasks, &pso->t_tasks, sizeof(_net_task),
  NULL);

  if (!args->unit_size)
    {
      pso->unit_size = SOCK_RECVB_SZ;
    }
  else
    {
      pso->unit_size = args->unit_size;
    }

  pso->buffer0 = calloc (1, pso->unit_size + 2);
  pso->buffer0_len = pso->unit_size;

  pso->host_ctx = args->socket_register;

  if (args->flags & F_OPSOCK_INIT_SENDQ)
    {
      md_init (&pso->sendq);
    }

  int r;

  if (args->flags & F_OPSOCK_SSL)
    {
      if (!ssl_init_ctx_client (pso))
	{
	  net_failclean (pso);
	  net_open_connection_cleanup (args->socket_register, aip, fd);
	  ERR_print_errors_fp (stderr);
	  ERR_clear_error ();
	  return 11;
	}

      if ((pso->ssl = SSL_new (pso->ctx)) == NULL)
	{ /* get new SSL state with context */
	  net_failclean (pso);
	  net_open_connection_cleanup (args->socket_register, aip, fd);
	  ERR_print_errors_fp (stderr);
	  ERR_clear_error ();
	  return 12;
	}

      if (args->ssl_cert && args->ssl_key)
	{
	  if ((r = ssl_load_client_certs (pso->ssl, args->ssl_cert,
					  args->ssl_key)))
	    {
	      net_failclean (pso);
	      net_open_connection_cleanup (args->socket_register, aip, fd);
	      ERR_print_errors_fp (stderr);
	      ERR_clear_error ();
	      log (L_ERR
	      "[%d] could not load SSL certificate/key pair [%d]: %s",
		   fd, r, args->ssl_cert);
	      return 15;
	    }
	  pso->flags |= F_OPSOCK_SSL_KEYCERT_L;
	}

      SSL_set_fd (pso->ssl, pso->sock);

      //pso->flags |= F_OPSOCK_ST_SSL_CONNECT;

      pso->rcv_cb = (_p_s_cb) net_connect_ssl;
      pso->rcv_cb_t = (_p_s_cb) net_recv_ssl;

      pso->send0 = (_p_ssend) net_ssend_ssl_b;

      //log (L_DEBUG "net_open_connection: enabling SSL..");
      //pso->send0 = (_p_ssend) net_ssend_ssl;
    }
  else
    {
      pso->rcv_cb = (_p_s_cb) net_recv;

      pso->send0 = (_p_ssend) net_ssend;

      pso->flags |= F_OPSOCK_PROC_READY;
    }

  pso->rcv1 = (_p_s_cb) args->proc;

  pso->flags |= F_OPSOCK_ACT;

  args->ca_flags |= F_SOCA_PROCED;

  return 0;
}

int
net_conn_establish_async (__sock_o pso, __net_task task)
{
  if (time (NULL) - (time_t) pso->timers.l_est_try
      < pso->policy.connect_retry_timeout)
    {
      return 1;
    }

  int r = connect (pso->sock, pso->res->ai_addr, pso->res->ai_addrlen);

  if (!r)
    {
      log (L_DEBUG "net_conn_establish: [%d]: %I:%d established", pso->sock,
	   *((ip_addr*) pso->ipr.ip), (int) pso->ipr.port);
      pso->flags |= F_OPSOCK_ESTABLISHED;
      net_pop_rc (pso, &pso->init_rc0);

      pso->timers.l_est_try = (time_t) 0;
      return -2;
    }

  if (errno == EINPROGRESS)
    {
      log (L_DEBUG "net_conn_establish_async: [%d]: connecting %I:%d..",
	   pso->sock, *((ip_addr*) pso->ipr.ip), (int) pso->ipr.port);
    }
  else if ( errno == EALREADY)
    {

    }
  else
    {
      char b[1024];
      strerror_r (errno, b, sizeof(b));
      log (
      L_ERR "net_conn_establish_async: [%d]: %s: %I:%d ",
	   pso->sock, b, *((ip_addr*) pso->ipr.ip), (int) pso->ipr.port);

      if ((pso->flags & F_OPSOCK_RETRY)
	  && (!pso->policy.max_connect_retries
	      || pso->counters.con_retries < pso->policy.max_connect_retries))
	{
	  close (pso->sock);
	  if ((pso->sock = socket (pso->res->ai_family, pso->res->ai_socktype,
				   pso->res->ai_protocol)) == -1)
	    {
	      pso->flags |= F_OPSOCK_TERM;
	      return -4;
	    }

	  if (fcntl (pso->sock, F_SETFL, O_NONBLOCK) == -1)
	    {
	      pso->flags |= F_OPSOCK_TERM;
	      return -4;
	    }

	  if (pso->flags & F_OPSOCK_BIND)
	    {
	      struct sockaddr_in localaddr;
	      localaddr.sin_family = pso->res->ai_family;
	      localaddr.sin_addr = pso->bind_ip;
	      localaddr.sin_port = 0;

	      if (bind (pso->sock, (struct sockaddr *) &localaddr,
			sizeof(localaddr)) == -1)
		{
		  return -4;
		}
	    }

	  pso->timers.l_est_try = (time_t) time (NULL);
	  pso->counters.con_retries++;
	}
      else
	{
	  pso->flags |= F_OPSOCK_TERM;

	  return -4;
	}

    }

  return 1;
}

static void
net_open_listening_socket_cleanup (pmda sockr, struct addrinfo *aip, int fd)
{
  close (fd);
  if (aip)
    freeaddrinfo (aip);
  md_unlink (sockr, sockr->pos);
}

int
net_open_listening_socket (char *addr, char *port, __sock_ca args)
{
  struct addrinfo *aip;
  struct addrinfo hints =
    { 0 };

  int fd;

  errno = 0;

  hints.ai_flags = AI_ALL | AI_ADDRCONFIG | AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_family = AF_UNSPEC;

  if (getaddrinfo (addr, port, &hints, &aip))
    {
      return -1;
    }

  if ((fd = socket (aip->ai_family, aip->ai_socktype, aip->ai_protocol)) == -1)
    {
      freeaddrinfo (aip);
      return -2;
    }

  if (bind_socket (fd, aip))
    {
      freeaddrinfo (aip);
      close (fd);
      return -3;
    }

  __sock_o pso;

  if (!(pso = md_alloc (args->socket_register, sizeof(_sock_o), 0, NULL)))
    {
      freeaddrinfo (aip);
      close (fd);
      return 9;
    }

  pso->res = aip;

  pso->sock = fd;
  pso->oper_mode = SOCKET_OPMODE_LISTENER;
  pso->flags = args->flags;
  pso->ac_flags = args->ac_flags;
  pso->pcheck_r = (_t_rcall) net_listener_chk_timeout;
  pso->rcv_cb = (_p_s_cb) net_accept;
  pso->host_ctx = args->socket_register;
  pso->unit_size = args->unit_size;
  pso->st_p0 = args->st_p0;
  pso->policy = args->policy;
  pso->timers.last_act = time (NULL);

  net_addr_to_ipr (pso, &pso->ipr);

  md_copy (&args->init_rc0, &pso->init_rc0, sizeof(_proc_ic_o), NULL);
  md_copy (&args->init_rc1, &pso->init_rc1, sizeof(_proc_ic_o), NULL);
  md_copy (&args->shutdown_rc0, &pso->shutdown_rc0, sizeof(_proc_ic_o),
  NULL);
  md_copy (&args->shutdown_rc1, &pso->shutdown_rc1, sizeof(_proc_ic_o),
  NULL);
  md_copy (&args->init_rc0_ssl, &pso->init_rc0_ssl, sizeof(_proc_ic_o),
  NULL);
  md_copy (&args->tasks, &pso->tasks, sizeof(_net_task),
  NULL);
  md_copy (&args->c_tasks, &pso->c_tasks, sizeof(_net_task),
  NULL);
  md_copy (&args->ct_tasks, &pso->ct_tasks, sizeof(_net_task),
  NULL);
  md_copy (&args->t_tasks, &pso->t_tasks, sizeof(_net_task),
  NULL);
  md_copy (&args->t_rcv, &pso->t_rcv, sizeof(_net_task),
  NULL);
  md_copy (&args->c_pre_tasks, &pso->c_pre_tasks, sizeof(_net_task),
  NULL);

  pso->sock_ca = (void*) args;

  int r;

  if (args->flags & F_OPSOCK_SSL)
    {
      if (!ssl_init_ctx_server (pso))
	{
	  ERR_print_errors_fp (stderr);
	  ERR_clear_error ();
	  net_failclean (pso);
	  net_open_listening_socket_cleanup (args->socket_register, aip, fd);
	  return 11;
	}

      if ((r = ssl_load_server_certs (pso->ctx, args->ssl_cert, args->ssl_key,
				      args->ssl_ca)))
	{
	  ERR_print_errors_fp (stderr);
	  ERR_clear_error ();
	  net_failclean (pso);
	  net_open_listening_socket_cleanup (args->socket_register, aip, fd);
	  log (L_ERR
	  "[%d] could not load SSL certificate/key pair [%d]: %s / %s",
	       fd, r, args->ssl_cert, args->ssl_key);
	  return 12;
	}

      pso->flags |= F_OPSOCK_SSL_KEYCERT_L;

      pso->rcv0 = (_p_s_cb) net_recv_ssl;
    }
  else
    {
      pso->rcv0 = (_p_s_cb) net_recv;
    }

  pso->rcv1_t = (_p_s_cb) args->proc;

  net_pop_rc (pso, &pso->init_rc0);

  pso->flags |= F_OPSOCK_ACT;

  args->ca_flags |= F_SOCA_PROCED;

  return 0;
}

static void
net_destroy_tnsat (__sock_o pso)
{
  if (!(pso->timers.flags & F_ST_MISC02_ACT))
    {
      pso->timers.flags |= F_ST_MISC02_ACT;
      pso->timers.misc02 = time (NULL);
    }
  else
    {
      pso->timers.misc03 = time (NULL);
      time_t pt_diff = (pso->timers.misc03 - pso->timers.misc02);
      if (pt_diff > pso->policy.close_timeout)
	{
	  log (L_WARN
	  "net_destroy_tnsat: [%d] shutdown timed out after %u seconds",
	       pso->sock, pt_diff);
	  pso->flags |= F_OPSOCK_SKIP_SSL_SD;
	}
    }
}

int
net_destroy_connection (__sock_o so)
{
  int ret;

  if (so->flags & F_OPSOCK_DISCARDED)
    {
      return -1;
    }

  if (so->flags & F_OPSOCK_CONNECT)
    {
      /*char b;
       while (recv(so->sock, &b, 1, 0))
       {
       }*/

      if ((so->flags & F_OPSOCK_SSL) && so->ssl)
	{
	  if (SSL_get_shutdown (so->ssl) & SSL_RECEIVED_SHUTDOWN)
	    {
	      log (
		  L_DEBUG
		  "net_destroy_connection: [%d]: SSL_RECEIVED_SHUTDOWN is set, skipping SSL_shutdown",
		  so->sock);
	      goto ssl_cleanup;
	    }
	  else if (so->flags & F_OPSOCK_SKIP_SSL_SD)
	    {
	      log (
		  L_DEBUG
		  "net_destroy_connection: [%d]: F_OPSOCK_SKIP_SSL_SD is set, skipping SSL_shutdown",
		  so->sock);
	      goto ssl_cleanup;
	    }
	  else if (so->flags & F_OPSOCK_TS_DISCONNECTED)
	    {
	      log (
		  L_DEBUG
		  "net_destroy_connection: [%d]: F_OPSOCK_TS_DISCONNECTED is set, skipping SSL_shutdown",
		  so->sock);
	      goto ssl_cleanup;
	    }

	  errno = 0;
	  if ((ret = SSL_shutdown (so->ssl)) < 1)
	    {
	      if (0 == ret)
		{
		  /*print_str(
		   "D5: net_destroy_connection: [%d]: SSL_shutdown not yet finished",
		   so->sock);*/
		  net_destroy_tnsat (so);
		  return 2;
		}

	      int ssl_err = SSL_get_error (so->ssl, ret);
	      ERR_print_errors_fp (stderr);
	      ERR_clear_error ();

	      if ((ssl_err == SSL_ERROR_WANT_READ
		  || ssl_err == SSL_ERROR_WANT_WRITE))
		{
		  /*print_str(
		   "D5: net_destroy_connection: [%d]: SSL_shutdown needs action %d to complete",
		   so->sock, ssl_err);*/
		  net_destroy_tnsat (so);
		  return 2;
		}
	      so->s_errno = ssl_err;
	      so->status = ret;

	      if (ssl_err == 5 && so->status == -1)
		{
		  log (
		      L_DEBUG
		      "SSL_shutdown: socket: [%d] [SSL_ERROR_SYSCALL]: code:[%d] [%s]",
		      so->sock, so->status, "-");
		}
	      else
		{
		  log (L_DEBUG
		  "socket: [%d] SSL_shutdown - code:[%d] sslerr:[%d]",
		       so->sock, so->status, ssl_err);
		}

	    }

	  ssl_cleanup: ;

	  /*if (so->flags & F_OPSOCK_SSL_KEYCERT_L)
	   {
	   SSL_certs_clear (so->ssl);
	   }*/

	  SSL_free (so->ssl);

	  ERR_remove_state (0);
	  ERR_clear_error ();
	}

      if (!(so->flags & F_OPSOCK_TS_DISCONNECTED))
	{
	  if ((ret = shutdown (so->sock, SHUT_RDWR)) == -1)
	    {
	      char err_buffer[1024];
	      if ( errno == ENOTCONN)
		{
		  strerror_r ( errno, err_buffer, sizeof(err_buffer));
		  log (L_DEBUG
		  "socket: [%d] shutdown: code:[%d] errno:[%d] %s",
		       so->sock, ret, errno, err_buffer);
		}
	      else
		{
		  strerror_r ( errno, err_buffer, sizeof(err_buffer));
		  log (L_ERR
		  "socket: [%d] shutdown: code:[%d] errno:[%d] %s",
		       so->sock, ret, errno, err_buffer);
		}
	    }
	  else
	    {
	      while (ret > 0)
		{
		  ret = recv (so->sock, so->buffer0, so->unit_size, 0);
		}
	    }
	}
    }

  if ((so->flags & F_OPSOCK_SSL) && NULL != so->ctx)
    {
      SSL_CTX_free (so->ctx);
    }

  if ((ret = close (so->sock)))
    {
      char err_buffer[1024];
      strerror_r (errno, err_buffer, 1024);
      log (L_ERR
      "[%d] unable to close socket - code:[%d] errno:[%d] %s",
	   so->sock, ret, errno, err_buffer);
      ret = 1;
    }

  if (NULL != so->buffer0)
    {
      free (so->buffer0);
    }

  /*if ( NULL != so->va_p1)
   {
   free(so->va_p1);
   }*/

  md_free (&so->sendq);

  md_free (&so->init_rc0);
  md_free (&so->init_rc1);
  md_free (&so->init_rc0_ssl);
  md_free (&so->tasks);
  md_free (&so->c_tasks);
  md_free (&so->ct_tasks);
  md_free (&so->t_tasks);
  md_free (&so->t_rcv);

  so->flags |= F_OPSOCK_DISCARDED;

  return ret;
}

#define T_NET_WORKER_SD                 (time_t) 45
#define I_NET_WORKER_IDLE_ALERT         (time_t) 30

#define ST_NET_WORKER_ACT               ((uint8_t)1 << 1)
#define ST_NET_WORKER_IDLE_ALERT        ((uint8_t)1 << 2)

int
net_push_to_sendq (__sock_o pso, void *data, size_t size, uint16_t flags)
{

  if (pso->sendq.offset > MAX_NET_SENDQ)
    {
      log (L_ERR "net_push_to_sendq: [%d]: max senq exceeded [%u]", pso->sock,
	   pso->sendq.offset);
      pso->flags |= F_OPSOCK_TERM;
      return 1;
    }

  __sock_sqp ptr;
  if (NULL == (ptr = md_alloc (&pso->sendq, SSENDQ_PAYLOAD_SIZE, 0, NULL)))
    {
      log (L_ERR "net_push_to_sendq: [%d]: out of resources", pso->sock);
      pso->flags |= F_OPSOCK_TERM;
      return -1;
    }

  if (flags & NET_PUSH_SENDQ_ASSUME_PTR)
    {
      ptr->data = data;
    }
  else
    {
      ptr->data = malloc (size);
      memcpy (ptr->data, data, size);
    }

  ptr->size = size;

  DBG("net_push_to_sendq: [%d]: suceeded", pso->sock);

  return 0;
}

int
net_send_direct (__sock_o pso, const void *data, size_t size)
{
  int ret;
  if (0 != (ret = pso->send0 (pso, (void*) data, size)))
    {
      log (L_ERR
      "[%d] [%d %d]: net_send_direct: send data failed, payload size: %d",
	   pso->sock, ret, pso->s_errno, size);
      pso->flags |= F_OPSOCK_TERM;
      return -1;
    }

  return 0;

}

static void *
net_proc_sendq_destroy_item (__sock_sqp psqp, __sock_o pso, p_md_obj ptr)
{
  free (psqp->data);
  return md_unlink (&pso->sendq, ptr);
}

static ssize_t
net_proc_sendq (__sock_o pso)
{
  p_md_obj ptr = pso->sendq.first;

  off_t ok = 0;

  while (ptr)
    {
      __sock_sqp psqp = (__sock_sqp) ptr->ptr;
      if (psqp->size)
	{
	  int ret;
	  switch ((ret = pso->send0(pso, psqp->data, psqp->size)))
	    {
	      case 0:;
	      ptr = net_proc_sendq_destroy_item(psqp, pso, ptr);
	      ok++;
	      continue;
	      case 1:;
	      log (L_ERR "[%d] [%d]: net_proc_sendq: send data failed, payload size: %u", pso->sock, pso->s_errno, psqp->size);
	      //ptr = net_proc_sendq_destroy_item(psqp, pso, ptr);
	      pso->flags |= F_OPSOCK_TERM;
	      goto end;
	      case 2:;// Again: this holds up the queue
	      log (L_WARN "[%d]: socket not ready", pso->sock);
	      goto end;
	      break;
	    }

	}
      ptr = ptr->next;
    }

  DBG("net_proc_sendq: [%d]: OK: %lu", pso->sock, (uint64_t) ok);

  end: ;

  return (ssize_t) pso->sendq.offset;
}

int
net_proc_tasks (__sock_o pso, pmda tasks)
{
  p_md_obj ptr = tasks->first;
  int ret = 0;

  while (ptr)
    {
      __net_task task = (__net_task ) ptr->ptr;
      int r = task->net_task_proc (pso, task);
      if (0 == r)
	{
	  ptr = ptr->next;
	}
      else if (r == -1) // stop processing
	{
	  ret = r;
	  return -1;
	}
      else if (r == -2) // remove task
	{
	  p_md_obj c = ptr;
	  ptr = ptr->next;
	  md_unlink (tasks, c);
	}
      else if (r == -4) // remove task & stop
	{
	  ret = r;
	  md_unlink (tasks, ptr);
	  return -1;
	}
      else
	{
	  ret = 1;
	  ptr = ptr->next;
	}
    }

  return ret;
}

int
net_register_task (pmda rt, _net_task_proc proc, void *data, uint16_t flags)
{
  int ret;

  __net_task task = md_alloc (rt, sizeof(_net_task), 0, NULL);

  if ( NULL == task)
    {
      ret = 1;
      goto exit;
    }

  ret = 0;

  task->data = data;
  task->net_task_proc = proc;

  exit: ;

  return ret;
}

int
net_socket_proc_delay (__sock_o pso, __net_task task)
{
  time_t t = time (NULL);

  if (!pso->timers.l_delay_proc)
    {
      pso->timers.l_delay_proc = t;
    }

  if (t - pso->timers.l_delay_proc >= pso->policy.socket_proc_delay)
    {
      return -2;
    }
  else
    {
      return -1;
    }

}

static p_md_obj
net_worker_process_socket (__sock_o pso, p_md_obj ptr, uint32_t flags,
			   uint32_t *status_flags)
{
  int r;

  if (pso->flags & F_OPSOCK_TERM)
    {
      if (!(pso->flags & F_OPSOCK_SDFLUSH) && pso->sendq.offset > 0
	  && !(flags & F_NW_HALT_SEND))
	{
	  pso->flags |= F_OPSOCK_SDFLUSH;
	  goto send_q;
	}
      errno = 0;

      if (2 == (r = net_destroy_connection (pso)))
	{
	  *status_flags |= F_NW_STATUS_WAITSD;
	  goto e_end;
	}

      if (r == 1)
	{
	  log (L_ERR
	  "bug: net_destroy_connection failed, socket [%d]",
	       pso->sock);
	  abort ();
	}

      /*if (pso->parent && (pso->parent->flags & F_OPSOCK_ST_SSL_ACCEPT))
       {
       pso->parent->flags ^= F_OPSOCK_ST_SSL_ACCEPT;
       pso->parent->rcv_cb = pso->parent->rcv_cb_t;
       }*/

      net_pop_rc (pso, &pso->shutdown_rc0);

      if (pso->res)
	{
	  freeaddrinfo (pso->res);
	}

      md_free (&pso->shutdown_rc0);
      md_free (&pso->shutdown_rc1);

      ptr = md_unlink (pso->host_ctx, ptr);

      *status_flags |= F_NW_STATUS_SOCKSD | F_NW_STATUS_READ;

      return ptr;

    }

  if (net_proc_tasks (pso, &pso->c_pre_tasks))
    {
      goto e_end;
    }

  if ((r = pso->pcheck_r (pso)))
    {
      pso->flags |= F_OPSOCK_TERM;
      *status_flags |= F_NW_STATUS_READ;
    }

  errno = 0;

  if ((pso->flags & F_OPSOCK_HALT_RECV))
    {
      goto process_data;
    }

  switch ((r = pso->rcv_cb (pso, pso->host_ctx, NULL, pso->buffer0)))
    {
    case 2:
      ;
      if (pso->counters.b_read > 0)
	{
	  break;
	}
      else
	{
	  goto send_q;
	}
      break;
    case 0:
      ;
      *status_flags |= F_NW_STATUS_READ;

      break;
    case -3:
      goto send_q;
      break;
    default:
      ;
      char buffer_e[1024];
      strerror_r (errno, (char*) buffer_e, sizeof(buffer_e));
      log (
	  L_ERR
	  "%s: socket:[%d] code:[%d] status:[%d] errno:[%d] %s",
	  pso->oper_mode == SOCKET_OPMODE_LISTENER ? "rx/tx accept" :
	  pso->oper_mode == SOCKET_OPMODE_RECIEVER ?
	      "rx/tx data" : "socket operation",
	  pso->sock, r, pso->status,
	  errno,
	  errno ? buffer_e : "");

      pso->flags |= F_OPSOCK_ERROR | F_OPSOCK_TERM;
      *status_flags |= F_NW_STATUS_READ;

      if (!pso->counters.b_read)
	{
	  goto e_end;
	}

      break;
    }

  process_data: ;

  if (NULL != pso->rcv1 && !(flags & F_NW_HALT_PROC))
    {
      switch ((r = pso->rcv1 (pso, pso->host_ctx, NULL, pso->buffer0)))
	{
	case 0:
	  *status_flags |= F_NW_STATUS_READ;
	  break;
	case -2:
	  break;
	case -3:
	  goto send_q;
	case -4:
	  goto e_end;
	default:
	  log (L_ERR
	  "data processor failed with status %d, socket: [%d]",
	       r, pso->sock);

	  pso->flags |= F_OPSOCK_ERROR | F_OPSOCK_TERM;
	  *status_flags |= F_NW_STATUS_READ;

	  break;
	}
    }

  if (pso->unit_size == pso->counters.b_read)
    {
      pso->counters.b_read = 0;
    }

  send_q: ;

  if (pso->sendq.offset > 0 && !(flags & F_NW_HALT_SEND))
    {
      ssize_t sendq_rem;
      if ((sendq_rem = net_proc_sendq (pso)) != 0)
	{
	  log (L_WARN "sendq: %u items remain, socket:[%d]", pso->sendq.offset,
	       pso->sock);
	}
      *status_flags |= F_NW_STATUS_READ;

    }

  e_end: ;

  if (net_proc_tasks (pso, &pso->t_tasks))
    {
      pso->flags |= F_OPSOCK_TERM;
      *status_flags |= F_NW_STATUS_READ;
    }

  if (pso->flags & F_OPSOCK_BRK)
    {
      pso->flags ^= F_OPSOCK_BRK;
      *status_flags |= F_NW_STATUS_BRK;

    }
  *status_flags |= F_NW_STATUS_READ;
  if ( NULL != ptr)
    {
      return ptr->next;
    }

  return ptr;
}

uint16_t
net_get_addrinfo_port (__sock_o pso)
{
  void *port_data;
  switch (pso->res->ai_family)
    {
    case AF_INET:
      ;
      port_data = &((struct sockaddr_in*) pso->res->ai_addr)->sin_port;
      break;
    case AF_INET6:
      ;
      port_data = &((struct sockaddr_in6*) pso->res->ai_addr)->sin6_port;
      break;
    default:
      ;
      return 0;
      break;
    }

  return ntohs (*((uint16_t*) port_data));
}

void *
net_get_addrinfo_ip (__sock_o pso)
{
  void *ip_data;
  switch (pso->res->ai_family)
    {
    case AF_INET:
      ;
      ip_data = (void*) &((struct sockaddr_in*) pso->res->ai_addr)->sin_addr;
      break;
    case AF_INET6:
      ;
      ip_data = (void*) &((struct sockaddr_in6*) pso->res->ai_addr)->sin6_addr;
      break;
    default:
      ip_data = NULL;
      break;

    }

  return ip_data;
}

const char *
net_get_addrinfo_ip_str (__sock_o pso, char *out, socklen_t len)
{
  const void *ip_data = net_get_addrinfo_ip (pso);
  if ( NULL == ip_data)
    {
      out[0] = 1;
      return out;
    }

  return inet_ntop (pso->res->ai_family, ip_data, out, len);

}

int
net_generic_socket_init1 (__sock_o pso)
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
	  log (L_INFO "[%d] client connected from %s:%hu", pso->sock, ip, port);
	}
      else
	{
	  log (L_INFO "[%d] connected to host %s:%hu", pso->sock, ip, port);
	}
      break;
    case SOCKET_OPMODE_LISTENER:
      ;
      log (L_INFO "[%d]: listening on %s:%hu", pso->sock, ip, port);
      break;
    }

  return 0;
}

int
net_generic_socket_init0 (__sock_o pso)
{
  struct f_owner_ex fown_ex;

  pid_t async = 1;

  if (ioctl (pso->sock, FIOASYNC, &async) == -1)
    {
      char err_buf[1024];
      log (
      L_ERR "net_generic_socket_init0: [%d]: ioctl (FIOASYNC) failed [%d] [%s]",
	   pso->sock, errno, strerror_r (errno, err_buf, sizeof(err_buf)));
      pso->flags |= F_OPSOCK_TERM;
    }

  fown_ex.pid = getpid ();
  fown_ex.type = F_OWNER_PID;

  if (fcntl (pso->sock, F_SETOWN_EX, &fown_ex) == -1)
    {
      char err_buf[1024];
      strerror_r (errno, err_buf, sizeof(err_buf));
      log (
	  L_ERR "net_generic_socket_init0: [%d]: fcntl (F_SETOWN_EX) failed [%d] [%s]",
	  pso->sock, errno, err_buf);
      pso->flags |= F_OPSOCK_TERM;
    }
  else
    {
      DBG("net_generic_socket_init0: fcntl set F_SETOWN_EX on [%d]", pso->sock);
    }

  return 0;
}

int
net_generic_socket_destroy0 (__sock_o pso)
{

  char ip[128];
  uint16_t port = pso->ipr.port;
  net_get_addrinfo_ip_str (pso, (char*) ip, sizeof(ip));

  switch (pso->oper_mode)
    {
    case SOCKET_OPMODE_RECIEVER:
      ;
      if (!(pso->flags & F_OPSOCK_ESTABLISHED))
	{
	  break;
	}
      if (pso->flags & F_OPSOCK_IN)
	{
	  log (L_INFO "[%d] client disconnected %s:%hu", pso->sock, ip, port);

	}
      else
	{
	  log (L_INFO "[%d] disconnected from host %s:%hu", pso->sock, ip,
	       port);
	}
      break;
    case SOCKET_OPMODE_LISTENER:
      ;
      log (L_INFO "[%d]: closed listener %s:%hu", pso->sock, ip, port);
      break;
    }

  return 0;
}

int
net_enum_sockr (pmda base, _p_enumsr_cb p_ensr_cb, void *arg)
{

  int g_ret = 0;

  p_md_obj ptr = base->first;

  while (ptr)
    {
      __sock_o pso = (__sock_o) ptr->ptr;

      int ret = p_ensr_cb(pso, arg);

      if ( ret > 0 )
	{
	  g_ret = ret;
	  break;
	}

      ptr = ptr->next;
    }

  return g_ret;
}

static int
net_search_dupip (__sock_o pso, void *arg)
{
  __sock_cret parg = (__sock_cret) arg;
  if (pso->oper_mode == parg->pso->oper_mode )
    {
      if (!memcmp(
	      &pso->ipr.ip,
	      &parg->pso->ipr.ip,
	      IP_BYTE_LEN))
	{
	  parg->ret++;
	}
    }
  return 0;
}

int
net_socket_init_enforce_policy (__sock_o pso)
{
  switch (pso->flags & F_OPSOCK_OPER_MODE)
    {
    case F_OPSOCK_CONNECT:
      ;

      if (pso->policy.max_sim_ip)
	{
	  _sock_cret sc_ret =
	    { .pso = pso, .ret = 0 };

	  int dip_sr;
	  if ((dip_sr = net_enum_sockr (pso->host_ctx, net_search_dupip,
					(void*) &sc_ret)))
	    {
	      log (
		  L_ERR
		  "net_socket_init_enforce_policy: [%d] net_enum_sockr failed: [%d]",
		  pso->sock, dip_sr);
	      pso->flags |= F_OPSOCK_TERM;
	      return -1;
	    }

	  if (sc_ret.ret > pso->policy.max_sim_ip)
	    {
	      log (
		  L_WARN
		  "net_socket_init_enforce_policy: [%d] max_sim limit reached: [%u/%u] %I",
		  pso->sock, sc_ret.ret, pso->policy.max_sim_ip,
		  *((ip_addr*) &pso->ipr.ip));
	      pso->flags |= F_OPSOCK_TERM;
	      return -1;
	    }
	}

      if (pso->policy.max_connects > 0)
	{
	  if (pso->parent->children >= pso->parent->policy.max_connects)
	    {
	      log (
		  L_WARN
		  "net_socket_init_enforce_policy: [%d] max_connects limit reached: [%u/%u]",
		  pso->sock, pso->parent->children,
		  pso->parent->policy.max_connects);
	      pso->flags |= F_OPSOCK_TERM;
	      return -1;
	    }
	}
      break;

    }

  return 0;
}

int
net_pop_rc (__sock_o pso, pmda rc)
{
  if ( NULL == rc->first)
    {
      return 1;
    }

  p_md_obj ptr = rc->pos;

  int ret = 0;

  while (ptr)
    {
      __proc_ic_o pic = (__proc_ic_o) ptr->ptr;

      if ( NULL != pic->call )
	{
	  if ( pic->call(pso) == -1 )
	    {
	      ret = 1;
	      break;
	    }
	}

      ptr = ptr->prev;
    }

  return ret;
}

int
net_push_rc (pmda rc, _t_rcall call, uint32_t flags)
{
  __proc_ic_o pic = md_alloc (rc, sizeof(_proc_ic_o), 0, NULL);

  if ( NULL == pic)
    {
      log (L_ERR "net_push_rc: could not allocate memory");
      return 1;
    }

  pic->call = call;
  pic->flags = flags;

  return 0;
}

void
net_poll (pmda socks, uint8_t rc)
{
  p_md_obj ptr = socks->first;
  uint32_t status = 0;

  while (ptr)
    {
      __sock_o pso = (__sock_o ) ptr->ptr;

      if (NULL == pso)
	{
	  log (L_ERR "net_poll: empty socket data reference");
	  abort ();
	}

      ptr = net_worker_process_socket (pso, ptr, 0, &status);

      if (status & F_NW_STATUS_BRK)
	{
	  return;
	}
    }

  if (rc < 4 && (status & F_NW_STATUS_READ))
    {
      rc++;
      net_poll (socks, rc);
    }

}

int
net_addr_to_ipr (__sock_o pso, __ipr out)
{
  uint16_t *port_data;
  uint8_t *ip_data;
  int len;
  switch (pso->res->ai_family)
    {
    case AF_INET:
      ;
      ip_data = (uint8_t*) &((struct sockaddr_in*) pso->res->ai_addr)->sin_addr;
      port_data =
	  (uint16_t*) &((struct sockaddr_in*) pso->res->ai_addr)->sin_port;
      len = sizeof(struct in_addr);
      break;
    case AF_INET6:
      ;
      ip_data =
	  (uint8_t*) &((struct sockaddr_in6*) pso->res->ai_addr)->sin6_addr;
      port_data =
	  (uint16_t*) &((struct sockaddr_in6*) pso->res->ai_addr)->sin6_port;
      len = sizeof(struct in6_addr);
      break;
    default:
      ;
      return 1;
    }

  out->port = ntohs (*port_data);

  union
  {
    ip_addr v;
    uint8_t d[len];
  } u1, u2;

  u1.v = *((ip_addr*) ip_data);

  int i, j;

  for (i = 0, j = len - 1; i < len; i++, j--)
    {
      u2.d[j] = (u1.d[i]);
    }

  memcpy (out->ip, &u2.v, len);

  return 0;

}

static __sock_o
net_prep_acsock (pmda base, pmda threadr, __sock_o spso, int fd,
		 struct sockaddr *sa)
{

  __sock_o pso;

  if (NULL == (pso = md_alloc (base, sizeof(_sock_o), 0, NULL)))
    {
      log (L_ERR "net_prep_acsock: out of resources [%llu]",
	   (unsigned long long int) base->offset);
      spso->status = 23;
      close (fd);
      return NULL;
    }

  pso->sock = fd;
  pso->rcv0 = spso->rcv1;
  pso->rcv1 = spso->rcv1_t;
  pso->parent = (void *) spso;
  pso->st_p0 = spso->st_p0;
  pso->oper_mode = SOCKET_OPMODE_RECIEVER;
  pso->flags |= spso->ac_flags | F_OPSOCK_CONNECT | F_OPSOCK_IN
      | (spso->flags & (F_OPSOCK_SSL | F_OPSOCK_INIT_SENDQ));
  pso->pcheck_r = (_t_rcall) net_chk_timeout;
  pso->policy = spso->policy;
  //pso->limits.sock_timeout = spso->policy.idle_timeout;
  pso->timers.last_act = time (NULL);
  pso->timers.l_rx = pso->timers.last_act;
  spso->timers.last_act = time (NULL);

  pso->sock_ca = spso->sock_ca;

  pso->res = calloc (1, sizeof(struct addrinfo));
  *pso->res = *spso->res;
  pso->res->ai_addr = malloc (sizeof(struct sockaddr));
  memcpy (pso->res->ai_addr, sa, sizeof(struct sockaddr));

  net_addr_to_ipr (pso, &pso->ipr);

  md_copy (&spso->init_rc0, &pso->init_rc0, sizeof(_proc_ic_o), NULL);
  md_copy (&spso->init_rc1, &pso->init_rc1, sizeof(_proc_ic_o), NULL);
  md_copy (&spso->shutdown_rc0, &pso->shutdown_rc0, sizeof(_proc_ic_o),
  NULL);
  md_copy (&spso->shutdown_rc1, &pso->shutdown_rc1, sizeof(_proc_ic_o),
  NULL);
  md_copy (&spso->init_rc0_ssl, &pso->init_rc0_ssl, sizeof(_proc_ic_o),
  NULL);
  md_copy (&spso->c_tasks, &pso->tasks, sizeof(_net_task),
  NULL);
  md_copy (&spso->ct_tasks, &pso->t_tasks, sizeof(_net_task),
  NULL);
  md_copy (&spso->t_rcv, &pso->t_rcv, sizeof(_net_task),
  NULL);
  md_copy (&spso->c_pre_tasks, &pso->c_pre_tasks, sizeof(_net_task),
  NULL);

  if (!spso->unit_size)
    {
      pso->unit_size = SOCK_RECVB_SZ;
    }
  else
    {
      pso->unit_size = spso->unit_size;
    }

  pso->buffer0 = calloc (1, pso->unit_size + 2);
  pso->buffer0_len = pso->unit_size;

  pso->host_ctx = base;

  if (pso->flags & F_OPSOCK_INIT_SENDQ)
    {
      md_init (&pso->sendq);
    }

  p_md_obj pso_ptr = base->pos;

  if ((pso->flags & F_OPSOCK_SSL))
    {
      if ((pso->ssl = SSL_new (spso->ctx)) == NULL)
	{
	  ERR_print_errors_fp (stderr);
	  ERR_clear_error ();
	  spso->s_errno = 0;
	  spso->status = 5;
	  shutdown (fd, SHUT_RDWR);
	  close (fd);
	  net_failclean (pso);
	  md_unlink (base, pso_ptr);
	  return NULL;
	}

      SSL_set_fd (pso->ssl, pso->sock);
      SSL_set_accept_state (pso->ssl);
      SSL_set_read_ahead (pso->ssl, 1);

      pso->rcv_cb_t = spso->rcv0;
      pso->rcv_cb = (_p_s_cb) net_accept_ssl;
      pso->flags |= F_OPSOCK_ST_SSL_ACCEPT;
      //pso->flags |= F_OPSOCK_SSL_ACIP;

      //pso->rcv_cb_t = spso->rcv0;

      pso->send0 = (_p_ssend) net_ssend_ssl_b;

    }
  else
    {
      pso->rcv_cb = spso->rcv0;

      pso->send0 = (_p_ssend) net_ssend_b;

    }

  net_pop_rc (pso, &pso->init_rc0);

  pso->flags |= F_OPSOCK_ESTABLISHED;

  return pso;
}

static int
net_assign_sock (pmda base, __sock_o pso, __sock_o spso)
{

  //net_pop_rc (pso, &pso->init_rc1);

  pso->flags |= F_OPSOCK_ACT | F_OPSOCK_PROC_READY;

  return 0;

}

int
net_accept (__sock_o spso, pmda base, pmda threadr, void *data)
{
  int fd;
  socklen_t sin_size = sizeof(struct sockaddr_storage);
  struct sockaddr_storage a;

  spso->s_errno = 0;

  if ((fd = accept (spso->sock, (struct sockaddr *) &a, &sin_size)) == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
	{

	  return 2;
	}
      spso->status = -1;

      char err_buf[1024];
      log (L_ERR "net_accept: [%d]: accept: [%d]: [%s]", spso->sock,
      errno,
	   strerror_r (errno, err_buf, sizeof(err_buf)));

      //f_term: ;

      return 0;
    }

  int ret;

  if ((ret = fcntl (fd, F_SETFL, O_NONBLOCK)) == -1)
    {
      close (fd);
      spso->status = -2;

      char err_buf[1024];
      log (L_ERR
      "net_accept: [%d]: fcntl F_SETFL(O_NONBLOCK): [%d]: [%s]",
	   spso->sock,
	   errno,
	   strerror_r (errno, err_buf, sizeof(err_buf)));

      return 0;
    }

  __sock_o pso;

  pso = net_prep_acsock (base, threadr, spso, fd, (struct sockaddr *) &a);

  if ( NULL == pso)
    {
      /*
       if (spso->status == 23)
       {
       spso->status = 0;
       }
       else
       {
       spso->status = -3;
       }*/
      log (L_ERR "net_accept: [%d]: net_prep_acsock failed: [%d]", spso->sock,
	   spso->status);

      return 0;
    }

  spso->cc = (void*) pso;

  uint32_t spso_flags = spso->flags;

  if (!(spso_flags & F_OPSOCK_SSL))
    {
      ret = net_assign_sock (base, pso, spso);

      if (0 == ret)
	{
	  spso->children++;
	}
      else
	{
	  return 2;
	}
    }

  return 0;
}

int
net_recv (__sock_o pso, pmda base, pmda threadr, void *data)
{

  ssize_t rcv_limit = pso->unit_size - pso->counters.b_read;

  if (rcv_limit <= 0)
    {
      return 0;
    }

  ssize_t rcvd = recv (pso->sock, (data + pso->counters.b_read), rcv_limit, 0);

  if (rcvd == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
	{
	  return 2;
	}

      pso->s_errno = errno;
      pso->status = -1;
      pso->flags |= F_OPSOCK_TERM;
      return 1;
    }
  else if (0 == rcvd)
    {
      pso->timers.last_act = time (NULL);
      pso->flags |= F_OPSOCK_TERM | F_OPSOCK_TS_DISCONNECTED;
      goto fin;
    }

  pso->timers.last_act = time (NULL);
  pso->timers.l_rx = pso->timers.last_act;
  pso->counters.b_read += rcvd;
  pso->counters.t_read += rcvd;

  uint8_t *end = data + pso->counters.b_read;

  if (end[0] != 0x0)
    {
      end[0] = 0x0;
    }

  fin: ;

  if (net_proc_tasks (pso, &pso->t_rcv))
    {
      return 7;
    }

  return 0;
}

int
net_recv_ssl (__sock_o pso, pmda base, pmda threadr, void *data)
{
  ssize_t rcv_limit = pso->unit_size - pso->counters.b_read;

  if (rcv_limit <= 0)
    {
      return 0;
    }

  int rcvd;
  ssize_t session_rcvd = 0;

  while (rcv_limit > 0
      && (rcvd = SSL_read (pso->ssl, (data + pso->counters.b_read),
			   (int) rcv_limit)) > 0)
    {
      pso->counters.b_read += (ssize_t) rcvd;
      pso->counters.t_read += (ssize_t) rcvd;
      rcv_limit = pso->unit_size - pso->counters.b_read;
      session_rcvd += (ssize_t) rcvd;
    }

  if (rcvd < 1)
    {
      if (session_rcvd)
	{
	  pso->timers.last_act = time (NULL);
	  pso->timers.l_rx = pso->timers.last_act;
	}

      pso->s_errno = SSL_get_error (pso->ssl, rcvd);

      ERR_print_errors_fp (stderr);
      ERR_clear_error ();

      if (pso->s_errno == SSL_ERROR_WANT_READ
	  || pso->s_errno == SSL_ERROR_WANT_WRITE)
	{
	  return 2;
	}

      pso->status = rcvd;

      if ((pso->s_errno == SSL_ERROR_WANT_CONNECT
	  || pso->s_errno == SSL_ERROR_WANT_ACCEPT
	  || pso->s_errno == SSL_ERROR_WANT_X509_LOOKUP))
	{
	  return 2;
	}

      int ret;

      pso->flags |= F_OPSOCK_TERM;

      if (rcvd == 0)
	{
	  if (pso->s_errno == (SSL_ERROR_ZERO_RETURN))
	    {
	      pso->flags |= F_OPSOCK_TS_DISCONNECTED;
	    }

	  if (pso->counters.b_read)
	    {
	      ret = 2;
	    }
	  else
	    {
	      ret = 0;
	    }
	}
      else
	{
	  ret = 1;
	}

      return ret;

    }

  pso->timers.last_act = time (NULL);
  pso->timers.l_rx = pso->timers.last_act;

  uint8_t *end = data + pso->counters.b_read;

  if (end[0] != 0x0)
    {
      end[0] = 0x0;
    }

  if (net_proc_tasks (pso, &pso->t_rcv))
    {
      return 7;
    }

  return 0;
}

#define T_NET_ACCEPT_SSL        (time_t) 4

int
net_accept_ssl (__sock_o pso, pmda base, pmda threadr, void *data)
{

  int ret;

  if ((ret = SSL_accept (pso->ssl)) != 1)
    {
      int ssl_err = SSL_get_error (pso->ssl, ret);
      ERR_print_errors_fp (stderr);
      ERR_clear_error ();

      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
	{

	  if (!(pso->timers.flags & F_ST_MISC00_ACT))
	    {
	      pso->timers.flags |= F_ST_MISC00_ACT;
	      pso->timers.misc00 = time (NULL);
	    }
	  else
	    {
	      pso->timers.misc01 = time (NULL);
	      time_t pt_diff = (pso->timers.misc01 - pso->timers.misc00);
	      if (pt_diff > pso->policy.ssl_accept_timeout)
		{
		  log (L_WARN
		  "SSL_accept: [%d] timed out after %u seconds",
		       pso->sock, pt_diff);
		  ret = 0;
		  goto f_term;
		}
	    }

	  return -3;
	}

      if (ssl_err == SSL_ERROR_SYSCALL && ret == -1)
	{
	  char err_buf[1024];
	  log (L_ERR "SSL_accept: [%d]: accept: [%d]: [%s]", pso->sock,
	  errno,
	       strerror_r (errno, err_buf, sizeof(err_buf)));
	}
      else
	{
	  log (L_ERR
	  "SSL_accept: socket: [%d] code: [%d] sslerr: [%d] [%d]",
	       pso->sock, ret, ssl_err, ret);
	}

      pso->flags |= F_OPSOCK_ERROR;
      pso->sslerr = ssl_err;

      f_term: ;

      pso->flags |= F_OPSOCK_TERM | F_OPSOCK_SKIP_SSL_SD;

      return 4;

    }

  if (pso->timers.flags & F_ST_MISC00_ACT)
    {
      pso->timers.flags ^= F_ST_MISC00_ACT;
    }

  pso->timers.misc00 = (time_t) 0;
  pso->timers.last_act = time (NULL);
  pso->timers.l_rx = pso->timers.last_act;
  //spso->timers.last_act = time (NULL);
  //pso->rcv_cb = pso->rcv_cb_t;

  //pso->limits.sock_timeout = spso->policy.idle_timeout;

  if (pso->flags & F_OPSOCK_ST_SSL_ACCEPT)
    {
      pso->flags ^= F_OPSOCK_ST_SSL_ACCEPT;
    }

  pso->rcv_cb = pso->rcv_cb_t;

  BIO_set_buffer_size(SSL_get_rbio (pso->ssl), 16384);
  BIO_set_buffer_size(SSL_get_wbio (pso->ssl), 16384);

  announce_ssl_connect_event (pso, "SSL_accept");
  ssl_show_client_certs (pso, pso->ssl);

  //pso->flags |= F_OPSOCK_ACT;
  //pso->flags ^= pso->flags & F_OPSOCK_SSL_ACIP;

  net_pop_rc (pso, &pso->init_rc0_ssl);

  __sock_o spso = pso->parent;

  ret = net_assign_sock (base, pso, spso);

  if (0 == ret)
    {
      spso->children++;
    }

  return 0;
}

int
net_connect_ssl (__sock_o pso, pmda base, pmda threadr, void *data)
{

  int ret, f_ret = 0;

  if ((ret = SSL_connect (pso->ssl)) != 1)
    {
      int ssl_err = SSL_get_error (pso->ssl, ret);
      ERR_print_errors_fp (stderr);
      ERR_clear_error ();

      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
	{

	  if (!(pso->timers.flags & F_ST_MISC00_ACT))
	    {
	      pso->timers.flags |= F_ST_MISC00_ACT;
	      pso->timers.misc00 = time (NULL);
	    }
	  else
	    {
	      pso->timers.misc01 = time (NULL);
	      time_t pt_diff = (pso->timers.misc01 - pso->timers.misc00);
	      if (pt_diff > pso->policy.ssl_connect_timeout)
		{
		  log (L_WARN
		  "SSL_connect: [%d] timed out after %u seconds",
		       pso->sock, pt_diff);
		  f_ret = 2;
		  goto f_term;
		}

	    }

	  return -3;
	}

      pso->status = ret;
      pso->s_errno = ssl_err;

      log (L_ERR "SSL_connect: socket:[%d] code:[%d] sslerr:[%d]", pso->sock,
	   ret, ssl_err);

      f_term: ;

      pso->flags |= F_OPSOCK_TERM | F_OPSOCK_SKIP_SSL_SD;

      return 4;

    }

  if (pso->timers.flags & F_ST_MISC00_ACT)
    {
      pso->timers.flags ^= F_ST_MISC00_ACT;
    }

  pso->timers.last_act = time (NULL);
  pso->timers.l_rx = pso->timers.last_act;
  pso->rcv_cb = pso->rcv_cb_t;
  //pso->limits.sock_timeout = SOCK_DEFAULT_IDLE_TIMEOUT;

  BIO_set_buffer_size(SSL_get_rbio (pso->ssl), 16384);
  BIO_set_buffer_size(SSL_get_wbio (pso->ssl), 16384);

  announce_ssl_connect_event (pso, "SSL_connect");
  ssl_show_client_certs (pso, pso->ssl);

  pso->flags |= F_OPSOCK_PROC_READY;

  return f_ret;
}

int
net_ssend_b (__sock_o pso, void *data, size_t length)
{

  if (0 == length)
    {
      log (L_ERR "net_ssend_b: [%d]: zero length input", pso->sock);
      abort ();
    }

  if (pso->flags & F_OPSOCK_ORPHANED)
    {
      return 1;
    }

  int ret = 0;
  ssize_t s_ret;
  uint32_t i = 1;

  unsigned char *in_data = (unsigned char*) data;

  time_t t00, t01;

  nssb_start: ;

  t00 = time (NULL);

  while ((s_ret = send (pso->sock, in_data, length,
  MSG_WAITALL | MSG_NOSIGNAL)) == -1)
    {
      if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
	{
	  char e_buffer[1024];
	  log (L_ERR "net_ssend_b: send failed: %s",
	       strerror_r (errno, e_buffer, sizeof(e_buffer)));
	  pso->s_errno = errno;
	  ret = 1;
	  break;
	}
      else
	{
	  char err_buf[1024];
	  strerror_r (errno, err_buf, 1024);

	  log (L_ERR "net_ssend_b: [%d] [%d]: %s", pso->sock, errno, err_buf);
	}

      t01 = time (NULL);
      time_t pt_diff = (t01 - t00);

      if (pt_diff > pso->policy.send_timeout)
	{
	  log (L_WARN
	  "net_ssend_ssl_b: [%d] timed out after %u seconds",
	       pso->sock, pt_diff);
	  return 1;
	}

      usleep (25000);
    }

  if (!ret)
    {
      pso->counters.session_write = (ssize_t) s_ret;
      pso->counters.total_write += (ssize_t) s_ret;

      if (s_ret < (ssize_t) length)
	{
	  log (L_DEBUG
	  "net_ssend_b: [%d] partial send occured: %zu / %zu [%u]",
	       pso->sock, s_ret, length, i);

	  in_data = (in_data + s_ret);
	  length = (length - s_ret);
	  i++;

	  goto nssb_start;

	}
    }

  return ret;
}

int
net_ssend_ssl_b (__sock_o pso, void *data, size_t length)
{

  if (0 == length)
    {
      log (L_ERR "net_ssend_ssl_b: [%d]: zero length input", pso->sock);
      abort ();
    }

  if (pso->flags & F_OPSOCK_ORPHANED)
    {
      return 1;
    }

  int ret, f_ret;

  time_t t00 = time (NULL), t01;

  while ((ret = SSL_write (pso->ssl, data, length)) < 1)
    {
      pso->s_errno = SSL_get_error (pso->ssl, ret);
      ERR_print_errors_fp (stderr);
      ERR_clear_error ();

      if (!(pso->s_errno == SSL_ERROR_WANT_READ
	  || pso->s_errno == SSL_ERROR_WANT_WRITE))
	{
	  pso->status = ret;

	  if (!(pso->s_errno == SSL_ERROR_WANT_CONNECT
	      || pso->s_errno == SSL_ERROR_WANT_ACCEPT
	      || pso->s_errno == SSL_ERROR_WANT_X509_LOOKUP))
	    {
	      pso->flags |= F_OPSOCK_TERM;

	      if (ret == 0)
		{
		  if (pso->s_errno == (SSL_ERROR_ZERO_RETURN))
		    {
		      pso->flags |= F_OPSOCK_TS_DISCONNECTED;
		      log (L_WARN
		      "net_ssend_ssl_b: [%d] socket disconnected",
			   pso->sock);
		    }
		  else
		    {
		      log (L_DEBUG
		      "net_ssend_ssl_b: [%d] SSL_write returned 0",
			   pso->sock);
		    }
		}

	      pthread_mutex_unlock (&pso->mutex);
	      return 1;
	    }
	}

      t01 = time (NULL);
      time_t pt_diff = (t01 - t00);

      if (pt_diff > pso->policy.send_timeout)
	{
	  log (L_WARN
	  "net_ssend_ssl_b: [%d] SSL_write timed out after %u seconds",
	       pso->sock, pt_diff);
	  return 1;
	}

      usleep (25000);
    }

  if (ret > 0 && ret < length)
    {
      log (L_ERR
      "net_ssend_ssl_b: [%d] partial SSL_write occured on socket",
	   pso->sock);
      pso->flags |= F_OPSOCK_TERM;
      f_ret = 1;
    }
  else
    {
      f_ret = 0;
    }

  pso->counters.session_write = (ssize_t) ret;
  pso->counters.total_write += (ssize_t) ret;

  return f_ret;
}

int
net_ssend_ssl (__sock_o pso, void *data, size_t length)
{
  if (!length)
    {
      return -2;
    }

  int ret;

  if ((ret = SSL_write (pso->ssl, data, length)) < 1)
    {
      pso->s_errno = SSL_get_error (pso->ssl, ret);
      ERR_print_errors_fp (stderr);
      ERR_clear_error ();

      if (pso->s_errno == SSL_ERROR_WANT_READ
	  || pso->s_errno == SSL_ERROR_WANT_WRITE)
	{
	  return 2;
	}

      pso->status = ret;

      if ((pso->s_errno == SSL_ERROR_WANT_CONNECT
	  || pso->s_errno == SSL_ERROR_WANT_ACCEPT
	  || pso->s_errno == SSL_ERROR_WANT_X509_LOOKUP))
	{
	  return 2;
	}

      pso->flags |= F_OPSOCK_TERM;

      if (ret == 0)
	{
	  pso->flags |= F_OPSOCK_TS_DISCONNECTED;
	}

      return 1;
    }

  if (ret > 0 && ret < length)
    {
      log (L_ERR
      "net_ssend_ssl: [%d] partial SSL_write occured on socket",
	   pso->sock);
      pso->flags |= F_OPSOCK_TERM;
    }

  return 0;
}

int
net_ssend (__sock_o pso, void *data, size_t length)
{
  int ret;

  if ((ret = send (pso->sock, data, length, MSG_WAITALL | MSG_NOSIGNAL)) == -1)
    {
      if ((errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
	{
	  return 2;
	}
      pso->status = -1;
      pso->s_errno = errno;
      return 1;
    }
  else if (ret != length)
    {
      pso->status = 11;
      return 1;
    }

  return 0;
}

#include <signal.h>

/*
 static void
 net_io_sched (pid_t pid)
 {
 for (;;)
 {
 kill (pid, SIGUSR2);
 sleep (1);
 }
 }

 */

void
net_ca_free (__sock_ca ca)
{
  md_free (&ca->init_rc0);
  md_free (&ca->init_rc1);
  md_free (&ca->shutdown_rc0);
  md_free (&ca->shutdown_rc1);
  md_free (&ca->c_tasks);
  md_free (&ca->ct_tasks);
  md_free (&ca->t_tasks);
  md_free (&ca->t_rcv);
  md_free (&ca->c_pre_tasks);
}

void
net_ca_init (__sock_ca ca)
{
  md_init (&ca->init_rc0);
  md_init (&ca->init_rc1);
  md_init (&ca->shutdown_rc0);
  md_init (&ca->shutdown_rc1);
  md_init (&ca->c_tasks);
  md_init (&ca->ct_tasks);
  md_init (&ca->t_tasks);
  md_init (&ca->t_rcv);
  md_init (&ca->c_pre_tasks);
}

__sock_ca
net_ca_new (pmda base)
{
  __sock_ca ca = md_alloc (base, sizeof(_sock_ca), 0, 0);
  net_ca_init (ca);
  return ca;
}
