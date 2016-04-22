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
sigset_t default_set =
  {
    { 0 } };

void
net_io_handler_dummy (int signal)
{

}

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
  _exit (0);
}

int
br_main (void)
{
  sigset_t sigset;
  sigemptyset (&sigset);
  sigaddset (&sigset, SIGIO);
  sigaddset (&sigset, SIGUSR2);
  sigprocmask (SIG_BLOCK, &sigset, &default_set);

  sigemptyset (&sigset);
  sigaddset (&sigset, SIGPIPE);
  sigprocmask (SIG_BLOCK, &sigset, NULL);

  log (L_INFO "br_main: %ub", sizeof(irc_ea_payload));

  signal (SIGIO, net_io_handler_dummy);
  signal (SIGUSR2, net_io_handler_dummy);

  ssl_init ();

  md_init (&_boot_pca);

  _mrl_startup (&_icf_global.ca_relay);

  _irc_startup (&_boot_pca);

  /*pid_t c_pid, p_pid = getpid ();

  if ((c_pid = fork ()) == (pid_t) -1)
    {
      abort ();
    }

  if (0 == c_pid)
    {
      net_io_sched (p_pid);
    }
*/
  return 0;

}
