
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

#include "pf_includes.h"

#include <inttypes.h>
#include <stdlib.h>

/* Events handled by bg worker task */

#define BG_JOB_EVENT_UPDATE_PORTS_STATUS  BIT (0)
#define BG_JOB_EVENT_SAVE_ASE_NVM_DATA    BIT (1)
#define BG_JOB_EVENT_SAVE_IM_NVM_DATA     BIT (2)
#define BG_JOB_EVENT_SAVE_PDPORT_NVM_DATA BIT (3)
#define BG_JOB_EVENT_STOP                 BIT (4)

static void bg_worker_task (void * arg);

void pf_bg_worker_init (pnet_t * net)
{
   net->pf_bg_worker.events = os_event_create();
   CC_ASSERT (net->pf_bg_worker.events != NULL);

   net->pf_bg_worker_thread = os_thread_create (
      "p-net_bg_worker",
      net->fspm_cfg.pnal_cfg.bg_worker_thread.prio,
      net->fspm_cfg.pnal_cfg.bg_worker_thread.stack_size,
      bg_worker_task,
      (void *)net);
}

void pf_bg_worker_exit (pnet_t * net)
{
   pf_bg_worker_start_job (net, PF_BGJOB_STOP);
   int ret = os_thread_join (net->pf_bg_worker_thread);
   if (ret != 0)
   {
      LOG_ERROR (
         PNET_LOG,
         "BGW(%d): Could not join with bg worker thread (%d)\n",
         __LINE__,
         ret);
   }
   if (net->pf_bg_worker.events != NULL)
   {
      os_event_destroy (net->pf_bg_worker.events);
      net->pf_bg_worker.events = NULL;
   }
   if (net->pf_bg_worker_thread != NULL)
   {
      os_thread_destroy (net->pf_bg_worker_thread);
      net->pf_bg_worker_thread = NULL;
   }
}

int pf_bg_worker_start_job (pnet_t * net, pf_bg_job_t job_id)
{
   if (net == NULL)
   {
      return -1;
   }

   switch (job_id)
   {
   case PF_BGJOB_UPDATE_PORTS_STATUS:
      os_event_set (net->pf_bg_worker.events, BG_JOB_EVENT_UPDATE_PORTS_STATUS);
      break;
   case PF_BGJOB_SAVE_ASE_NVM_DATA:
      os_event_set (net->pf_bg_worker.events, BG_JOB_EVENT_SAVE_ASE_NVM_DATA);
      break;
   case PF_BGJOB_SAVE_IM_NVM_DATA:
      os_event_set (net->pf_bg_worker.events, BG_JOB_EVENT_SAVE_IM_NVM_DATA);
      break;
   case PF_BGJOB_SAVE_PDPORT_NVM_DATA:
      os_event_set (net->pf_bg_worker.events, BG_JOB_EVENT_SAVE_PDPORT_NVM_DATA);
      break;
   case PF_BGJOB_STOP:
      os_event_set (net->pf_bg_worker.events, BG_JOB_EVENT_STOP);
      break;
   default:
      LOG_ERROR (
         PNET_LOG,
         "BGW(%d): Unsupported job %d\n",
         __LINE__,
         (int)job_id);
      return -1;
   }

   return 0;
}

/**
 * Event handling loop for background thread
 *
 * @param arg              InOut: Thread argument, must be of type pnet_t *
 */
static void bg_worker_task (void * arg)
{
   pnet_t * net = (pnet_t *)arg;
   uint32_t mask = BG_JOB_EVENT_UPDATE_PORTS_STATUS |
                   BG_JOB_EVENT_SAVE_ASE_NVM_DATA |
                   BG_JOB_EVENT_SAVE_IM_NVM_DATA |
                   BG_JOB_EVENT_SAVE_PDPORT_NVM_DATA | BG_JOB_EVENT_STOP;
   uint32_t flags = 0;

   for (;;)
   {
      os_event_wait (net->pf_bg_worker.events, mask, &flags, OS_WAIT_FOREVER);

      if (flags & BG_JOB_EVENT_SAVE_ASE_NVM_DATA)
      {
         os_event_clr (net->pf_bg_worker.events, BG_JOB_EVENT_SAVE_ASE_NVM_DATA);

         pf_cmina_save_ase (net, &net->cmina_nonvolatile_dcp_ase);
      }
      if (flags & BG_JOB_EVENT_SAVE_IM_NVM_DATA)
      {
         os_event_clr (net->pf_bg_worker.events, BG_JOB_EVENT_SAVE_IM_NVM_DATA);

         pf_fspm_save_im (net);
      }
      if (flags & BG_JOB_EVENT_SAVE_PDPORT_NVM_DATA)
      {
         os_event_clr (
            net->pf_bg_worker.events,
            BG_JOB_EVENT_SAVE_PDPORT_NVM_DATA);

         (void)pf_pdport_save_all (net);
      }
      if (flags & BG_JOB_EVENT_UPDATE_PORTS_STATUS)
      {
         os_event_clr (
            net->pf_bg_worker.events,
            BG_JOB_EVENT_UPDATE_PORTS_STATUS);

         pf_pdport_update_eth_status (net);
      }
      if (flags & BG_JOB_EVENT_STOP)
      {
         os_event_clr (net->pf_bg_worker.events, BG_JOB_EVENT_STOP);

         break;
      }
   }
}
