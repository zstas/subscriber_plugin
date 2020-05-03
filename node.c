/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <subscriber/subscriber.h>

typedef struct 
{
  u32 next_index;
  u32 sw_if_index;
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} subscriber_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
my_format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* packet trace format function */
static u8 * format_subscriber_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  subscriber_trace_t * t = va_arg (*args, subscriber_trace_t *);
  
  s = format (s, "SUBSCRIBER: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);
  s = format (s, "  new src %U -> new dst %U",
              my_format_mac_address, t->new_src_mac, 
              my_format_mac_address, t->new_dst_mac);
  return s;
}

vlib_node_registration_t subscriber_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_subscriber_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum {
#define _(sym,str) SUBSCRIBER_ERROR_##sym,
  foreach_subscriber_error
#undef _
  SUBSCRIBER_N_ERROR,
} subscriber_error_t;

#ifndef CLIB_MARCH_VARIANT
static char * subscriber_error_strings[] = 
{
#define _(sym,string) string,
  foreach_subscriber_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */


typedef enum
{
#define subscriber_error(n,s) SUBSCRIBER_ERROR_##n,
#include <subscriber/subscriber_error.def>
#undef subscriber_error
  PPPOE_N_ERROR,
} subscriber_input_error_t;

// static char * subcsriber_error_strings[] = {
// #define subscriber_error(n,s) s,
// #include <subscriber/subscriber_error.def>
// #undef subscriber_error
// #undef _
// };

#define foreach_mac_address_offset              \
_(0)                                            \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)


VLIB_NODE_FN (subscriber_node) (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  subscriber_main_t * sm = &subscriber_main;
  vnet_main_t * vnm = sm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_decapsulated = 0;
  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  // subscriber_entry_key_t cached_key;
  // subscriber_entry_result_t cached_result;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  /* Clear the one-entry cache in case session table was updated */
  // cached_key.raw = ~0;
  // cached_result.raw = ~0;	/* warning be gone */

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0;
	  ethernet_header_t *h0;
    subscriber_session_t * t0;
    u32 error0;
	  u32 sw_if_index0, len0;
	  u32 result0;
    u16 outer_vlan = ~0;
    u16 inner_vlan = ~0;
    u16 type0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  error0 = 0;

    h0 = vlib_buffer_get_current (b0);
    type0 = clib_net_to_host_u16(h0->type);
    vnet_buffer (b0)->l2_hdr_offset = b0->current_data;

    sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

    if (type0 == ETHERNET_TYPE_VLAN){
		  u16 *vlan_tag = (u16 *) (h0 + 1);
		  outer_vlan = 0xFF0F & (*vlan_tag); // vlan id in nbo
      u16 *outer_type = (u16 *) (vlan_tag + 1);
      type0 = clib_net_to_host_u16( *outer_type );
		  if( type0 == ETHERNET_TYPE_VLAN ) {
			  u16 *inner_vlan_tag = (u16 *) (vlan_tag + 2);
			  inner_vlan = 0xFF0F & (*inner_vlan_tag);
        u16 *inner_type = (u16 *) (inner_vlan_tag + 1);
        type0 = clib_net_to_host_u16( *inner_type );
		  }
	  }

    result0 = subscriber_lookup (sw_if_index0, h0->src_address, outer_vlan, inner_vlan);

    if (PREDICT_FALSE (result0 == ~0))
	    {
	      error0 = SUBSCRIBER_ERROR_NO_SUCH_SESSION;
	      next0 = SUBSCRIBER_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  t0 = pool_elt_at_index (sm->sessions, result0);

    sw_if_index0 = t0->sw_if_index;
    vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;

    vlib_buffer_advance(b0, sizeof(*h0));
    if( outer_vlan != (u16)~0 )
      vlib_buffer_advance(b0, 4);
    if( inner_vlan != (u16)~0 )
      vlib_buffer_advance(b0, 4);

    switch( type0 ) {
    case ETHERNET_TYPE_IP4:
      next0 = SUBSCRIBER_INPUT_NEXT_IP4_INPUT;
      break;
    case ETHERNET_TYPE_IP6:
      next0 = SUBSCRIBER_INPUT_NEXT_IP6_INPUT;
      break;
    case ETHERNET_TYPE_ARP:
      next0 = SUBSCRIBER_INPUT_NEXT_ARP_INPUT;
      // u32 eth_start = vnet_buffer (b0)->l2_hdr_offset;
      // vnet_buffer (b0)->l2.l2_len = b0->current_data - eth_start;
      
      break;
    default:
      next0 = SUBSCRIBER_INPUT_NEXT_DROP;
      goto trace00;
    }

	  
	  len0 = vlib_buffer_length_in_chain (vm, b0);

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;
    
	  /* Batch stats increment on the same pppoe session so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              subscriber_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->sw_if_index = sw_if_index0;
              clib_memcpy (tr->new_src_mac, h0->src_address, 6);
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that session tx stats is kept? */
  vlib_node_increment_counter (vm, subscriber_node.index,
                               SUBSCRIBER_ERROR_DECAPSULATED,
                               pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter
	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (subscriber_node) = 
{
  .name = "subscriber",
  .vector_size = sizeof (u32),
  .format_trace = format_subscriber_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = SUBSCRIBER_N_ERROR,
  .error_strings = subscriber_error_strings,

  .n_next_nodes = SUBSCRIBER_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
  #define _(s,n) [SUBSCRIBER_INPUT_NEXT_##s] = n,
    foreach_subscriber_input_next
  #undef _
  },
};
#endif /* CLIB_MARCH_VARIANT */