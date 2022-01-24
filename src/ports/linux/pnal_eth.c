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

#include <errno.h>
#include <stdlib.h>
#include <string.h>


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
   timeout_rcv.tv_sec = 0;
   timeout_rcv.tv_usec = 1000;
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
