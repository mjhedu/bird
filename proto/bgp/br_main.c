/*
 * br_main.c
 *
 *  Created on: Apr 16, 2016
 *      Author: reboot
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "brc_net_io.h"
#include "br_proto.h"
#include "br_net_proto.h"
#include "msg_relay.h"
#include "br_irc.h"

#include "br_main.h"

mda _boot_pca =
  { 0 };

void
net_io_handler (int signal)
{
  net_poll (&_ntglobal.r, 0);
  net_poll (&msg_relay_socks.r, 0);
}

static void
net_io_sched (pid_t pid)
{
  for (;;)
    {
      kill (pid, SIGUSR2);
      sleep (1);
    }
}

int
br_main (void)
{

  signal (SIGIO, net_io_handler);
  signal (SIGUSR2, net_io_handler);

  ssl_init ();

  md_init (&_boot_pca, 4096);
  md_init (&pc_a, 64);

  __sock_ca ca;

  if (NULL == (ca = md_alloc (&_boot_pca, sizeof(_sock_ca), 0, NULL)))
    {
      return 1;
    }

  _mrl_startup (ca);

  if (NULL == (ca = md_alloc (&_boot_pca, sizeof(_sock_ca), 0, NULL)))
    {
      return 1;
    }

  _irc_startup (ca);

  pid_t c_pid, p_pid = getpid ();

  if ((c_pid = fork ()) == (pid_t) -1)
    {
      abort ();
    }

  if (0 == c_pid)
    {
      net_io_sched (p_pid);
    }

  return 0;

}
