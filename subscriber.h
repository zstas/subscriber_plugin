
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

#define foreach_subscriber_input_next  \
_(DROP, "error-drop")                  \
_(IP4_INPUT, "ip4-input")              \
_(IP6_INPUT, "ip6-input")              \
_(ARP_INPUT, "arp-input")              \
_(INTERFACE, "interface-output" )      \
//_(CP_INPUT, "cp-input")              

typedef enum 
{
  #define _(s,n) SUBSCRIBER_INPUT_NEXT_##s,
  foreach_subscriber_input_next
  #undef _
  SUBSCRIBER_N_NEXT,
} subscriber_next_t;


typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 session_id;

  /* session client addresses */
  ip46_address_t client_ip;

  /* the index of tx interface for pppoe encaped packet */
  u32 encap_if_index;

  /** FIB indices - inner IP packet lookup here */
  u32 decap_fib_index;

  u8 local_mac[6];
  u8 client_mac[6];

  u16 outer_vlan;
  u16 inner_vlan;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  dpo_id_t dpo;

} subscriber_session_t;

/* *INDENT-OFF* */
typedef struct
{
  union
  {
    struct
    {
      u8 mac[6];
      u16 outer_vlan;
      u16 inner_vlan;
    } fields;
    u64 raw;
  };
} subscriber_entry_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef struct
{
  union
  {
    struct
    {
      u32 sw_if_index;
      u32 session_index;
    } fields;
    u64 raw;
  };
}  subscriber_entry_result_t;
/* *INDENT-ON* */


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
  u32 *subscriber_by_key;

  u32 *subscriber_by_sw_if_index;

  // Pool of p2p subifs;
  subscriber_session_t *sessions;

  /* Free vlib hw_if_indices */
  u32 *free_subscriber_session_hw_if_indices;

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
} subscriber_key_t;

extern vlib_node_registration_t subscriber_node;
extern vlib_node_registration_t subscriber_periodic_node;

/* Periodic function events */
#define SUBSCRIBER_EVENT1 1
#define SUBSCRIBER_EVENT2 2
#define SUBSCRIBER_EVENT_PERIODIC_ENABLE_DISABLE 3

void subscriber_create_periodic_process (subscriber_main_t *);
subscriber_entry_result_t* subscriber_lookup (u32 parent_if_index, u8 * client_mac, u16 outer_vlan, u16 inner_vlan);

u8 * format_subscriber_header_with_length (u8 * s, va_list * args);
u8 * subscriber_build_rewrite (vnet_main_t * vnm,u32 sw_if_index,vnet_link_t link_type, const void *dst_address);
void subscriber_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai);

#endif /* __included_subscriber_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

