/*
 * subscriber.c - skeleton vpp engine plug-in
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <subscriber/subscriber.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/interface_funcs.h>


#include <subscriber/subscriber.api_enum.h>
#include <subscriber/subscriber.api_types.h>

#define REPLY_MSG_ID_BASE smp->msg_id_base
#include <vlibapi/api_helper_macros.h>
#include <vnet/api_errno.h>

subscriber_main_t subscriber_main;
static fib_source_t subscriber_fib_src;

static u8 *
format_subscriber (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ipsession%d", dev_instance);
}

static clib_error_t *
susbcriber_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  u32 n_left_from, next_index, * from, * to_next;

  subscriber_main_t *sub_main = &subscriber_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
      vlib_buffer_t *b0;
      u32 bi0;

      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;
      u32 sw_if_index0;
      ethernet_header_t *h0;
      u16 type0;
      u8 l2hdr[12];


      b0 = vlib_get_buffer (vm, bi0);
      h0 = vlib_buffer_get_current (b0);
      type0 = h0->type;
      clib_memcpy( l2hdr, h0->dst_address, 12 );

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      subscriber_session_t *sess;
      u32 session_id;

      session_id = sub_main->subscriber_by_sw_if_index[sw_if_index0];
      sess = pool_elt_at_index (sub_main->sessions, session_id);

      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sess->encap_if_index;
      //vnet_buffer (b0)->ip.adj_index[VLIB_TX] = sess->dpo.dpoi_index;
      if( sess->outer_vlan != (u16)~0) {
        word offset = -4;
        if( sess->inner_vlan != (u16)~0) {
          offset = -8;
        }
        vlib_buffer_advance (b0, offset );

        h0 = vlib_buffer_get_current (b0);
        clib_memcpy( h0->dst_address, l2hdr, 12 );
        h0->type = 0x0081;
        ethernet_vlan_header_t *vlan_hdr = (ethernet_vlan_header_t*)( h0 + 1 );
        vlan_hdr->priority_cfi_and_id = sess->outer_vlan;
        if( sess->inner_vlan == (u16)~0) {
          vlan_hdr->type = type0;
        } else {
          vlan_hdr->type = 0x0081;
          vlan_hdr += 1;
          vlan_hdr->type = type0;
          vlan_hdr->priority_cfi_and_id = sess->inner_vlan;
        }
      }

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                       n_left_to_next, bi0,
                                       sess->out_slot);
  }
         vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (subscriber_device_class,static) = {
  .name = "ipsubscriber",
  .format_device_name = format_subscriber,
  .admin_up_down_function = susbcriber_interface_admin_up_down,
  .tx_function = dummy_interface_tx,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (subscriber_hw_class) =
{
  .name = "ipsubscriber",
  .format_header = format_subscriber_header_with_length,
  .build_rewrite = subscriber_build_rewrite,
  .update_adjacency = subscriber_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static void
create_subscriber_key (subscriber_key_t * p2pe_key, u32 parent_if_index, u8 * client_mac, u16 outer_vlan, u16 inner_vlan)
{
  clib_memcpy (p2pe_key->mac, client_mac, 6);
  p2pe_key->pad1 = 0;
  p2pe_key->hw_if_index = parent_if_index;
  p2pe_key->inner_vlan = inner_vlan;
  p2pe_key->outer_vlan = outer_vlan;
}

subscriber_entry_result_t*
subscriber_lookup (u32 parent_if_index, u8 * client_mac, u16 outer_vlan, u16 inner_vlan)
{
  subscriber_main_t *sub_main = &subscriber_main;
  subscriber_key_t subs_key;
  subscriber_entry_result_t *p;

  create_subscriber_key (&subs_key, parent_if_index, client_mac, outer_vlan, inner_vlan);
  p = (subscriber_entry_result_t*)hash_get (sub_main->subscriber_by_key, &subs_key);
  if (p)
    return p;

  return NULL;
}

int subscriber_enable_disable (subscriber_main_t * smp, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (smp->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (smp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  subscriber_create_periodic_process (smp);

  vnet_feature_enable_disable ("device-input", "subscriber",
                               sw_if_index, enable_disable, 0, 0);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (smp->vlib_main,
                             smp->periodic_node_index,
                             SUBSCRIBER_EVENT_PERIODIC_ENABLE_DISABLE,
                            (uword)enable_disable);
  return rv;
}

int
susbcriber_add_del (u32 parent_if_index, u8 * client_mac, 
                    ip46_address_t client_ip, 
                    int is_add, u16 outer_vlan, u16 inner_vlan)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main();
  subscriber_main_t *sm = &subscriber_main;
  //vnet_interface_main_t *im = &vnm->interface_main;
  subscriber_session_t *t = 0;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hi;

  hi = vnet_get_hw_interface (vnm, parent_if_index);

  // u32 subscriber_if_index = ~0;
  // subscriber_if_index = subscriber_lookup (parent_if_index, client_mac, outer_vlan, inner_vlan);

  // actually adding a new session
  pool_get_aligned (sm->sessions, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));
  clib_memcpy (t->local_mac, hi->hw_address, 6);
  clib_memcpy (t->client_mac, client_mac, 6);
  t->outer_vlan = clib_host_to_net_u16( outer_vlan );
  t->inner_vlan = clib_host_to_net_u16( inner_vlan );
  t->encap_if_index = parent_if_index;
  t->session_id = t - sm->sessions;
  t->client_ip = client_ip;

  if (vec_len (sm->free_subscriber_session_hw_if_indices) > 0) {
    // TODO
  } else {
    hw_if_index = vnet_register_interface
	    (vnm, subscriber_device_class.index, t - sm->sessions,
	     subscriber_hw_class.index, t - sm->sessions);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);

    u32 slot;
    slot = vlib_node_add_named_next_with_slot (vm, hi->tx_node_index,
					     "interface-output", 0);
    if( slot == ~0 )
      return ~0;
    t->out_slot = slot;
  }
  t->sw_if_index = sw_if_index = hi->sw_if_index;
  vec_add (hi->hw_address, t->local_mac, 6);

  vec_validate_init_empty (sm->subscriber_by_sw_if_index, sw_if_index, ~0);
  sm->subscriber_by_sw_if_index[sw_if_index] = t - sm->sessions;

  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  subscriber_key_t *sub_key;
	sub_key = clib_mem_alloc (sizeof (*sub_key));
	create_subscriber_key (sub_key, t->encap_if_index, t->client_mac, t->outer_vlan, t->inner_vlan);
	hash_set_mem (sm->subscriber_by_key, sub_key, sw_if_index);

  fib_prefix_t pfx;
  pfx.fp_addr.as_u64[ 0 ] = 0;
  pfx.fp_addr.as_u64[ 1 ] = 0;
  pfx.fp_addr.ip4.as_u32 = client_ip.ip4.as_u32;
  pfx.fp_len = 32;
  pfx.fp_proto = FIB_PROTOCOL_IP4;

  fib_table_entry_path_add (0, &pfx, // TODO fib
				subscriber_fib_src, FIB_ENTRY_FLAG_CONNECTED,
				fib_proto_to_dpo (pfx.fp_proto),
				&pfx.fp_addr, sw_if_index, ~0,
				1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

  return 0;
}

static clib_error_t *
subscriber_enable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  subscriber_main_t * smp = &subscriber_main;
  u32 sw_if_index = ~0;
  int add = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
                         smp->vnet_main, &sw_if_index))
        ;
      if (unformat (input, "del"))
        add = 0 ;
      else 
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = subscriber_enable_disable (smp, sw_if_index, add);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "subscriber_enable_disable returned %d",
                              rv);
    }
  return 0;
}

static clib_error_t *
subscriber_create_delete_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  subscriber_main_t *sm = &subscriber_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t client_ip;
  u8 is_add = 1;
  u8 ipv4_set = 0;
  u32 decap_fib_index = 0;
  u8 client_mac[6] = { 0 };
  u8 client_mac_set = 0;
  u32 sw_if_index = ~0;
  int rv;
  u32 tmp;
  u32 session_sw_if_index = ~0;
  clib_error_t *error = NULL;
  u32 outer_vlan = ~0;
  u32 inner_vlan = ~0;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&client_ip, 0, sizeof client_ip);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, sm->vnet_main, &sw_if_index))
        ;
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "client-ip %U",
			 unformat_ip4_address, &client_ip.ip4))
	{
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "decap-vrf-id %d", &tmp))
	{
	    //decap_fib_index = fib_table_find (FIB_PROTOCOL_IP4, tmp);
	  if (decap_fib_index == ~0)
	    {
	      error =
		clib_error_return (0, "nonexistent decap fib id %d", tmp);
	      goto done;
	    }
	}
      else if (unformat
	    (line_input, "client-mac %U", unformat_ethernet_address,
	     client_mac))
	client_mac_set = 1;
    else if (unformat (line_input, "vlan %d", &outer_vlan))
    ;
    else if (unformat (line_input, "inner-vlan %d", &inner_vlan))
    ;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!ipv4_set)
    {
      error = clib_error_return (0, "You should specify ipv4 address");
      goto done;
    }

  if (client_mac_set == 0)
    {
      error = clib_error_return (0, "session client mac not specified");
      goto done;
    }

  rv = susbcriber_add_del( sw_if_index, client_mac, client_ip, is_add, outer_vlan, inner_vlan );

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
			 sm->vnet_main, session_sw_if_index);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "session already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "session does not exist...");
      goto done;

    default:
      error = clib_error_return
	(0, "vnet_pppoe_add_del_session returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (subscriber_enable_command, static) =
{
  .path = "enable subscriber",
  .short_help =
  "enable subscriber <interface-name> [del]",
  .function = subscriber_enable_command_fn,
};

VLIB_CLI_COMMAND (subscriber_create_delete_command, static) =
{
  .path = "create subscriber",
  .short_help =
  "create subscriber <interface-name> client-mac <mac> client-ip <ip-address> [vlan <id>] [inner-vlan <id>]",
  .function = subscriber_create_delete_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_subscriber_enable_disable_t_handler
(vl_api_subscriber_enable_disable_t * mp)
{
  vl_api_subscriber_enable_disable_reply_t * rmp;
  subscriber_main_t * smp = &subscriber_main;
  int rv;

  rv = subscriber_enable_disable (smp, ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_SUBSCRIBER_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <subscriber/subscriber.api.c>

/* *INDENT-OFF* */
VNET_FEATURE_INIT (subscriber, static) =
{
  .arc_name = "device-input",
  .node_name = "subscriber",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

u8 *
format_subscriber_session (u8 * s, va_list * args)
{
  subscriber_session_t *t = va_arg (*args, subscriber_session_t *);
  subscriber_main_t *sm = &subscriber_main;

  s = format (s, "ipsession%d\n", t - sm->sessions);
  s = format (s, "\tSubscriber ifindex %d\n", t->sw_if_index );
  s = format (s, "\tClient MAC: %U\n", format_ethernet_address, t->client_mac);
  s = format (s, "\tIP Address: %U\n", format_ip46_address, &t->client_ip, IP46_TYPE_ANY );
  s = format (s, "\tRouting table: %d\n", t->decap_fib_index );
  s = format (s, "\tHW Interface index %d\n", t->encap_if_index );
  s = format (s, "\tLocal MAC: %U\n", format_ethernet_address, t->local_mac);
  s = format (s, "\tEncapsulation: " );
  if( t->outer_vlan == ~0 ) {
    s = format (s, "untagged");
  } else {
    s = format (s, "vlan %d", clib_net_to_host_u16( t->outer_vlan ));
    if( t->inner_vlan != (u16)~0 ) {
      s = format (s, ":%d", clib_net_to_host_u16( t->inner_vlan ));
    }
  }
  s = format (s, "\n");

  return s;
}

/* *INDENT-OFF* */
static clib_error_t *
show_subscribers_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  subscriber_main_t *sm = &subscriber_main;
  subscriber_session_t *t;

  if (pool_elts (sm->sessions) == 0)
    vlib_cli_output (vm, "No susbcribers configured...");

  pool_foreach (t, sm->sessions,
		({
		    vlib_cli_output (vm, "%U",format_subscriber_session, t);
		}));

  return 0;
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_pppoe_session_command, static) = {
    .path = "show subscribers",
    .short_help = "show subscribers TODO help",
    .function = show_subscribers_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "vBNG Subscriber plugin",
};
/* *INDENT-ON* */

u8 *
format_subscriber_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

u8 *
subscriber_build_rewrite (vnet_main_t * vnm,
		     u32 sw_if_index,
		     vnet_link_t link_type, const void *dst_address)
{
  subscriber_main_t *sub_main = &subscriber_main;
  subscriber_session_t *sess;
  u32 session_id;
  u8 *rw = 0;

  session_id = sub_main->subscriber_by_sw_if_index[sw_if_index];
  sess = pool_elt_at_index (sub_main->sessions, session_id);

  int len = sizeof (ethernet_header_t);
  if( sess->outer_vlan != (u16)~0) {
    len += sizeof( ethernet_vlan_header_t);
    if( sess->inner_vlan != (u16)~0) 
      len += sizeof( ethernet_vlan_header_t);
  }
  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ethernet_header_t *eth_hdr = (ethernet_header_t *) rw;
  clib_memcpy (eth_hdr->dst_address, sess->client_mac, 6);
  clib_memcpy (eth_hdr->src_address, sess->local_mac, 6);
  u16 *type = &eth_hdr->type;

  if( sess->outer_vlan != (u16)~0){
    ethernet_vlan_header_t *vlan_hdr = (ethernet_vlan_header_t*)( eth_hdr + 1 );
    eth_hdr->type = 0x0081;
    type = &vlan_hdr->type;
    vlan_hdr->priority_cfi_and_id = sess->outer_vlan;
    if( sess->inner_vlan != (u16)~0) {
      vlan_hdr->type = 0x0081;
      vlan_hdr+=1;
      type = &vlan_hdr->type;
      vlan_hdr->priority_cfi_and_id = sess->inner_vlan;
    }
  }

  switch (link_type)
    {
    case VNET_LINK_IP4:
      *type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
      break;
    case VNET_LINK_IP6:
      *type = clib_host_to_net_u16 (ETHERNET_TYPE_IP6);
      break;
    default:
      break;
    }

  return rw;
}

/**
 * @brief Fixup the adj rewrite post encap. Insert the packet's length
 */
static void
subscriber_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  // do nothing
}

void
subscriber_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  subscriber_main_t *sub_main = &subscriber_main;
  dpo_id_t dpo = DPO_INVALID;
  ip_adjacency_t *adj;
  subscriber_session_t *sess;
  u32 session_id;

  ASSERT (ADJ_INDEX_INVALID != ai);

  adj = adj_get (ai);

  session_id = sub_main->subscriber_by_sw_if_index[sw_if_index];
  sess = pool_elt_at_index (sub_main->sessions, session_id);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_BCAST:
      adj_nbr_midchain_update_rewrite (ai, subscriber_fixup, sess,
				       ADJ_FLAG_NONE,
				       subscriber_build_rewrite (vnm,
							    sw_if_index,
							    adj->ia_link,
							    NULL));
      break;
    case IP_LOOKUP_NEXT_MCAST:
      /*
       * Construct a partial rewrite from the known ethernet mcast dest MAC
       * There's no MAC fixup, so the last 2 parameters are 0
       */
      adj_mcast_midchain_update_rewrite (ai, subscriber_fixup, sess,
					 ADJ_FLAG_NONE,
					 subscriber_build_rewrite (vnm,
							      sw_if_index,
							      adj->ia_link,
							      NULL), 0, 0);
      break;

    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      ASSERT (0);
      break;
    }

  interface_tx_dpo_add_or_lock (vnet_link_to_dpo_proto (adj->ia_link),
				sess->encap_if_index, &dpo);

  adj_nbr_midchain_stack (ai, &dpo);

  dpo_reset (&dpo);
}


static clib_error_t *
subscriber_init (vlib_main_t * vm)
{
  subscriber_main_t *sm = &subscriber_main;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();
  sm->subscriber_by_key = hash_create_mem (0, sizeof (subscriber_key_t), sizeof (subscriber_entry_result_t));

  /* Add our API messages to the global name_crc hash table */
  sm->msg_id_base = setup_message_id_table ();

  subscriber_fib_src = fib_source_allocate ("ipsession",
				       FIB_SOURCE_PRIORITY_HI,
				       FIB_SOURCE_BH_API);

  return 0;
}

VLIB_INIT_FUNCTION (subscriber_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
