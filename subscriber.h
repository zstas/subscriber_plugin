
/*
 * subscriber.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_subscriber_h__
#define __included_subscriber_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* on/off switch for the periodic function */
    u8 periodic_timer_enabled;
    /* Node index, non-zero if the periodic process has been created */
    u32 periodic_node_index;

      /**
   * Hash mapping parent sw_if_index and client mac address to p2p_ethernet sub-interface
   */
  uword * p2p_ethernet_by_key;

  u32 *p2p_ethernet_by_sw_if_index;

  // Pool of p2p subifs;
  subint_config_t *p2p_subif_pool;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;
} subscriber_main_t;

extern subscriber_main_t subscriber_main;

/**
 * @brief Key struct for Subscriber
 * all fields in NET byte order
 */

typedef struct {
  u8 mac[6];
  u16 pad1;         // padding for u64 mac address
  u32 hw_if_index;
  u16 outer_vlan;
  u16 inner_vlan;
} p2p_key_t;

extern vlib_node_registration_t subscriber_node;
extern vlib_node_registration_t subscriber_periodic_node;

/* Periodic function events */
#define SUBSCRIBER_EVENT1 1
#define SUBSCRIBER_EVENT2 2
#define SUBSCRIBER_EVENT_PERIODIC_ENABLE_DISABLE 3

void subscriber_create_periodic_process (subscriber_main_t *);

#endif /* __included_subscriber_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

