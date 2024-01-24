/*********************************************************************
 *        _       _         _
 *  _ __ | |_  _ | |  __ _ | |__   ___
 * | '__|| __|(_)| | / _` || '_ \ / __|
 * | |   | |_  _ | || (_| || |_) |\__ \
 * |_|    \__|(_)|_| \__,_||_.__/ |___/
 *
 * www.rt-labs.com
 * Copyright 2018 rt-labs AB, Sweden.
 *
 * This software is dual-licensed under GPLv3 and a commercial
 * license. See the file LICENSE.md distributed with this software for
 * full license information.
 ********************************************************************/

/**
 * @file
 * @brief Linux Ethernet related functions that use \a pnal_eth_handle_t
 */

#include "pnal.h"
#include "osal.h"
#include "osal_log.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <linux/filter.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct pnal_eth_handle
{
   pnal_eth_callback_t * callback;
   void * arg;
   int socket;
   os_thread_t * thread;
   int stop;
   os_mutex_t * stop_mutex;
};

static void pnal_eth_set_stop (pnal_eth_handle_t * handle)
{
   os_mutex_lock (handle->stop_mutex);
   handle->stop = 1;
   os_mutex_unlock (handle->stop_mutex);
}

static int pnal_eth_get_stop (pnal_eth_handle_t * handle)
{
   int result = 0;
   os_mutex_lock (handle->stop_mutex);
   result = handle->stop;
   os_mutex_unlock (handle->stop_mutex);
   return result;
}

/**
 * @internal
 * Run a thread that listens to incoming raw Ethernet sockets.
 * Delegate the actual work to thread_arg->callback
 *
 * This is a function to be passed into os_thread_create()
 * Do not change the argument types.
 *
 * @param thread_arg     InOut: Will be converted to pnal_eth_handle_t
 */
static void os_eth_task (void * thread_arg)
{
   pnal_eth_handle_t * eth_handle = thread_arg;
   ssize_t readlen;
   int handled = 0;

   pnal_buf_t * p = pnal_buf_alloc (PNAL_BUF_MAX_SIZE);
   assert (p != NULL);

   while (!pnal_eth_get_stop (eth_handle))
   {
      readlen = recv (eth_handle->socket, p->payload, PNAL_BUF_MAX_SIZE, 0);
      if (readlen == -1)
         continue;
      p->len = readlen;

      if (eth_handle->callback != NULL)
      {
         handled = eth_handle->callback (eth_handle, eth_handle->arg, p);
      }
      else
      {
         handled = 0; /* Message not handled */
      }

      if (handled == 1)
      {
         p = pnal_buf_alloc (PNAL_BUF_MAX_SIZE);
         assert (p != NULL);
      }
   }
   pnal_buf_free (p);
}

/*
Current code base has only 1 place that calls pnal_eth_init, and the callback
that is used there only cares about 2 ethertypes (possibly within any number
of VLAN tags).  As such, we can apply a kernel-side filter here.
This is essentially the system used by (e.g.) libpcap
(see also https://www.kernel.org/doc/html/latest/networking/filter.html).

In particular, the code dump is obtained by
tcpdump -i enp0s31f6 -dd '( ether proto 0x8892 or ether proto 0x88cc ) or (
vlan and ( ( ether proto 0x8892 or ether proto 0x88cc ) or ( vlan and ( ether
proto 0x8892 or ether proto 0x88cc or vlan ) ) ) )'
Note that e.g. netsniff-ng can also produce such programs
(with a more convential bpf asm output).

Note that libpcap compiler/optimizer does not always produce the right program.
In particular, "equivalent re-arranging" of the above expression can lead to a
different (wrong) program.  As such, check the output of -d (iso -dd) to make
sure it does as intended.  In this case, the output is as follows, which
indeed comes down to accepting the desired ether types with up 2 preceding
VLAN tags (or also accept anything as of 3 nested VLAN tag, though unlikely).
Note that ldb [-4048] uses a special extension; see also e.g.
https://andreaskaris.github.io/blog/networking/bpf-and-tcpdump/

(000) ldh      [12]
(001) jeq      #0x8892          jt 20   jf 2
(002) jeq      #0x88cc          jt 20   jf 3
(003) jeq      #0x8100          jt 8    jf 4
(004) jeq      #0x88a8          jt 8    jf 5
(005) jeq      #0x9100          jt 8    jf 6
(006) ldb      [-4048]
(007) jeq      #0x1             jt 8    jf 21
(008) ldh      [16]
(009) jeq      #0x8892          jt 20   jf 10
(010) jeq      #0x88cc          jt 20   jf 11
(011) jeq      #0x8100          jt 14   jf 12
(012) jeq      #0x88a8          jt 14   jf 13
(013) jeq      #0x9100          jt 14   jf 21
(014) ldh      [20]
(015) jeq      #0x8892          jt 20   jf 16
(016) jeq      #0x88cc          jt 20   jf 17
(017) jeq      #0x8100          jt 20   jf 18
(018) jeq      #0x88a8          jt 20   jf 19
(019) jeq      #0x9100          jt 20   jf 21
(020) ret      #262144
(021) ret      #0
 */

// clang-format off
struct sock_filter code[] = {
  { 0x28, 0, 0, 0x0000000c },
  { 0x15, 18, 0, 0x00008892 },
  { 0x15, 17, 0, 0x000088cc },
  { 0x15, 4, 0, 0x00008100 },
  { 0x15, 3, 0, 0x000088a8 },
  { 0x15, 2, 0, 0x00009100 },
  { 0x30, 0, 0, 0xfffff030 },
  { 0x15, 0, 13, 0x00000001 },
  { 0x28, 0, 0, 0x00000010 },
  { 0x15, 10, 0, 0x00008892 },
  { 0x15, 9, 0, 0x000088cc },
  { 0x15, 2, 0, 0x00008100 },
  { 0x15, 1, 0, 0x000088a8 },
  { 0x15, 0, 7, 0x00009100 },
  { 0x28, 0, 0, 0x00000014 },
  { 0x15, 4, 0, 0x00008892 },
  { 0x15, 3, 0, 0x000088cc },
  { 0x15, 2, 0, 0x00008100 },
  { 0x15, 1, 0, 0x000088a8 },
  { 0x15, 0, 1, 0x00009100 },
  { 0x6, 0, 0, 0x00040000 },
  { 0x6, 0, 0, 0x00000000 },
};
// clang-format on

pnal_eth_handle_t * pnal_eth_init (
   const char * if_name,
   pnal_ethertype_t receive_type,
   const pnal_cfg_t * pnal_cfg,
   pnal_eth_callback_t * callback,
   void * arg)
{
   pnal_eth_handle_t * handle;
   int i;
   struct ifreq ifr = {0};
   struct sockaddr_ll sll = {0};
   int ifindex;
   struct timeval timeout_snd;
   struct timeval timeout_rcv;
   const uint16_t linux_receive_type =
      (receive_type == PNAL_ETHTYPE_ALL) ? ETH_P_ALL : receive_type;
   char * envvar = NULL;

   handle = malloc (sizeof (pnal_eth_handle_t));
   if (handle == NULL)
   {
      return NULL;
   }

   handle->stop_mutex = os_mutex_create();
   if (handle->stop_mutex == NULL)
   {
      free (handle);
      return NULL;
   }
   handle->stop = 0;
   handle->arg = arg;
   handle->callback = callback;
   handle->socket = socket (PF_PACKET, SOCK_RAW, htons (linux_receive_type));

   /* Attach filter */
   envvar = getenv ("P_NET_USE_FILTER");
   if (!envvar || atoi (envvar))
   {
      struct sock_fprog bpf = {
         .len = sizeof (code) / sizeof (code[0]),
         .filter = code,
      };
      setsockopt (
         handle->socket,
         SOL_SOCKET,
         SO_ATTACH_FILTER,
         &bpf,
         sizeof (bpf));
   }

   /* Adjust send timeout */
   timeout_snd.tv_sec = 0;
   timeout_snd.tv_usec = 1;
   setsockopt (
      handle->socket,
      SOL_SOCKET,
      SO_SNDTIMEO,
      &timeout_snd,
      sizeof (timeout_snd));

   /* Adjust recv timeout. This is required to be able to stop the thread
    * with pnal_eth_get_stop */
   /* Do avoid going in and out of the system call too often. */
   envvar = getenv ("P_NET_RCV_TIMEOUT_MS");
   timeout_rcv.tv_sec = 0;
   timeout_rcv.tv_usec = (envvar ? atoi (envvar) : 50) * 1000;
   setsockopt (
      handle->socket,
      SOL_SOCKET,
      SO_RCVTIMEO,
      &timeout_rcv,
      sizeof (timeout_rcv));

   /* Send outgoing messages directly to the interface, without using Linux
    * routing */
   i = 1;
   setsockopt (handle->socket, SOL_SOCKET, SO_DONTROUTE, &i, sizeof (i));

   /* Read interface index */
   strcpy (ifr.ifr_name, if_name);
   ioctl (handle->socket, SIOCGIFINDEX, &ifr);
   ifindex = ifr.ifr_ifindex;

   /* Set flags of NIC interface */
   strcpy (ifr.ifr_name, if_name);
   ifr.ifr_flags = 0;
   ioctl (handle->socket, SIOCGIFFLAGS, &ifr);
   ifr.ifr_flags = ifr.ifr_flags | IFF_MULTICAST | IFF_BROADCAST;
   if (receive_type == PNAL_ETHTYPE_ALL)
   {
      ifr.ifr_flags |= IFF_ALLMULTI; /* Receive all multicasts */
   }
   if (ioctl (handle->socket, SIOCSIFFLAGS, &ifr) < 0)
   {
      LOG_ERROR (
         PNET_LOG,
         "BGW(%d): Could not set IFF_ALLMULTI flag (%d)\n",
         __LINE__, errno);
   }

   /* Bind socket to relevant protocol */
   sll.sll_family = AF_PACKET;
   sll.sll_ifindex = ifindex;
   sll.sll_protocol = htons (linux_receive_type);
   bind (handle->socket, (struct sockaddr *)&sll, sizeof (sll));

   if (handle->socket > -1)
   {
      handle->thread = os_thread_create (
         "os_eth_task",
         pnal_cfg->eth_recv_thread.prio,
         pnal_cfg->eth_recv_thread.stack_size,
         os_eth_task,
         handle);
      return handle;
   }
   else
   {
      os_mutex_destroy (handle->stop_mutex);
      free (handle);
      return NULL;
   }
}

void pnal_eth_exit (pnal_eth_handle_t * handle)
{
   // stop the thread, wait for it to join
   pnal_eth_set_stop (handle);
   int ret = os_thread_join (handle->thread);
   if (ret != 0)
   {
      LOG_ERROR (
         PNET_LOG,
         "BGW(%d): Could not join with eth thread (%d)\n",
         __LINE__,
         ret);
   }
   os_mutex_destroy (handle->stop_mutex);

   // and afterwards close the socket (this is all in the same thread, hopefully)
   close (handle->socket);
   handle->socket = -1;

   if (handle->thread != NULL)
   {
      free (handle->thread);
   }
   if (handle != NULL)
   {
      free (handle);
   }
}

int pnal_eth_send (pnal_eth_handle_t * handle, pnal_buf_t * buf)
{
   int ret = send (handle->socket, buf->payload, buf->len, 0);
   return ret;
}
