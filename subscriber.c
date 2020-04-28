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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <subscriber/subscriber.api_enum.h>
#include <subscriber/subscriber.api_types.h>

#define REPLY_MSG_ID_BASE smp->msg_id_base
#include <vlibapi/api_helper_macros.h>

subscriber_main_t subscriber_main;

/* Action function shared between message handler and debug CLI */

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
susbcriber_add_del (vlib_main_t * vm, u32 parent_if_index,
		      u8 * client_mac, u32 p2pe_subif_id, int is_add,
		      u16 outer_vlan, u16 inner_vlan)
{
  vnet_main_t *vnm = vnet_get_main ();
  subscriber_main_t *p2pm = &subscriber_main;
  vnet_interface_main_t *im = &vnm->interface_main;

  u32 p2pe_sw_if_index = ~0;
  p2pe_sw_if_index = p2p_ethernet_lookup (parent_if_index, client_mac, outer_vlan, inner_vlan);

  if (is_add)
    {
      if (p2pe_sw_if_index != ~0)
            return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
    else 
	{
	  vnet_hw_interface_t *hi;

	  hi = vnet_get_hw_interface (vnm, parent_if_index);
	  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
	    return VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED;

	  u64 sup_and_sub_key =
	    ((u64) (hi->sw_if_index) << 32) | (u64) p2pe_subif_id;
	  uword *p;
	  p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
	  if (p)
	    {
	      if (CLIB_DEBUG > 0)
		clib_warning
		  ("p2p ethernet sub-interface on sw_if_index %d with sub id %d already exists\n",
		   hi->sw_if_index, p2pe_subif_id);
	      return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
	    }
	  vnet_sw_interface_t template = {
	    .type = VNET_SW_INTERFACE_TYPE_P2P,
	    .flood_class = VNET_FLOOD_CLASS_NORMAL,
	    .sup_sw_if_index = hi->sw_if_index,
	    .sub.id = p2pe_subif_id,
		.sub.eth.flags.one_tag = 1,
		.sub.eth.outer_vlan_id = clib_net_to_host_u16( outer_vlan ),
		.sub.eth.inner_vlan_id = clib_net_to_host_u16( inner_vlan ),
		.p2p.outer_vlan = outer_vlan,
		.p2p.inner_vlan = inner_vlan
	  };

	  clib_memcpy (template.p2p.client_mac, client_mac,
		       sizeof (template.p2p.client_mac));

	  if (vnet_create_sw_interface (vnm, &template, &p2pe_sw_if_index))
	    return VNET_API_ERROR_SUBIF_CREATE_FAILED;

	  /* Allocate counters for this interface. */
	  {
	    u32 i;

	    vnet_interface_counter_lock (im);

	    for (i = 0; i < vec_len (im->sw_if_counters); i++)
	      {
		vlib_validate_simple_counter (&im->sw_if_counters[i],
					      p2pe_sw_if_index);
		vlib_zero_simple_counter (&im->sw_if_counters[i],
					  p2pe_sw_if_index);
	      }

	    for (i = 0; i < vec_len (im->combined_sw_if_counters); i++)
	      {
		vlib_validate_combined_counter (&im->combined_sw_if_counters
						[i], p2pe_sw_if_index);
		vlib_zero_combined_counter (&im->combined_sw_if_counters[i],
					    p2pe_sw_if_index);
	      }

	    vnet_interface_counter_unlock (im);
	  }

	  vnet_interface_main_t *im = &vnm->interface_main;
	  sup_and_sub_key =
	    ((u64) (hi->sw_if_index) << 32) | (u64) p2pe_subif_id;
	  u64 *kp = clib_mem_alloc (sizeof (*kp));

	  *kp = sup_and_sub_key;
	  hash_set (hi->sub_interface_sw_if_index_by_id, p2pe_subif_id,
		    p2pe_sw_if_index);
	  hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, p2pe_sw_if_index);

	  p2p_key_t *p_p2pe_key;
	  p_p2pe_key = clib_mem_alloc (sizeof (*p_p2pe_key));
	  create_p2pe_key (p_p2pe_key, parent_if_index, client_mac, outer_vlan, inner_vlan);
	  hash_set_mem (p2pm->p2p_ethernet_by_key, p_p2pe_key,
			p2pe_sw_if_index);

	  if (p2pe_if_index)
	    *p2pe_if_index = p2pe_sw_if_index;

	  vec_validate (p2pm->p2p_ethernet_by_sw_if_index, parent_if_index);
	  if (p2pm->p2p_ethernet_by_sw_if_index[parent_if_index] == 0)
	    {
	      vnet_feature_enable_disable ("device-input",
					   "p2p-ethernet-input",
					   parent_if_index, 1, 0, 0);
	      /* Set promiscuous mode on the l2 interface */
	      ethernet_set_flags (vnm, parent_if_index,
				  ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);

	    }
	  p2pm->p2p_ethernet_by_sw_if_index[parent_if_index]++;
	  /* set the interface mode */
	  set_int_l2_mode (vm, vnm, MODE_L3, p2pe_sw_if_index, 0,
			   L2_BD_PORT_TYPE_NORMAL, 0, 0);
	  return 0;
	}
  else
    {
      if (p2pe_sw_if_index == ~0)
	return VNET_API_ERROR_SUBIF_DOESNT_EXIST;
      else
	{
	  int rv = 0;
	  rv = vnet_delete_sub_interface (p2pe_sw_if_index);
	  if (!rv)
	    {
	      vec_validate (p2pm->p2p_ethernet_by_sw_if_index,
			    parent_if_index);
	      if (p2pm->p2p_ethernet_by_sw_if_index[parent_if_index] == 1)
		{
		  vnet_feature_enable_disable ("device-input",
					       "p2p-ethernet-input",
					       parent_if_index, 0, 0, 0);
		  /* Disable promiscuous mode on the l2 interface */
		  ethernet_set_flags (vnm, parent_if_index, 0);
		}
	      p2pm->p2p_ethernet_by_sw_if_index[parent_if_index]--;

	      /* Remove p2p_ethernet from hash map */
	      p2p_key_t *p_p2pe_key;
	      p_p2pe_key = clib_mem_alloc (sizeof (*p_p2pe_key));
	      create_p2pe_key (p_p2pe_key, parent_if_index, client_mac, outer_vlan, inner_vlan);
	      hash_unset_mem (p2pm->p2p_ethernet_by_key, p_p2pe_key);
	    }
	  return rv;
	}
    }
}

static clib_error_t *
subscriber_enable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  subscriber_main_t * smp = &subscriber_main;
  u32 sw_if_index = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
                         smp->vnet_main, &sw_if_index))
        ;
      else 
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = subscriber_enable_disable (smp, sw_if_index, 1);

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
subscriber_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  subscriber_main_t * smp = &subscriber_main;
  u32 sw_if_index = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
                         smp->vnet_main, &sw_if_index))
        ;
      else 
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = subscriber_enable_disable (smp, sw_if_index, 0);

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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (subscriber_enable_command, static) =
{
  .path = "enable subscriber",
  .short_help =
  "enable subscriber <interface-name>",
  .function = subscriber_enable_command_fn,
};

VLIB_CLI_COMMAND (subscriber_disable_command, static) =
{
  .path = "disable subscriber",
  .short_help =
  "disable subscriber <interface-name>",
  .function = subscriber_disable_command_fn,
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

static clib_error_t * subscriber_init (vlib_main_t * vm)
{
  subscriber_main_t * smp = &subscriber_main;
  clib_error_t * error = 0;

  smp->vlib_main = vm;
  smp->vnet_main = vnet_get_main();

  /* Add our API messages to the global name_crc hash table */
  smp->msg_id_base = setup_message_id_table ();

  return error;
}

VLIB_INIT_FUNCTION (subscriber_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (subscriber, static) =
{
  .arc_name = "device-input",
  .node_name = "subscriber",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "vBNG Subscriber plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
