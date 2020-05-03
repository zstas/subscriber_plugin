/*
 *------------------------------------------------------------------
 * subscriber_api.c - subscriber api
 *
 * Copyright (c) 2017 Stanislav Zaikin and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>


#include <subscriber/subscriber.h>

#include <vnet/format_fns.h>
#include <subscriber/subscriber.api_enum.h>
#include <subscriber/subscriber.api_types.h>

#define REPLY_MSG_ID_BASE pem->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void send_subscriber_session_details
  (subscriber_session_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_subscriber_session_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->client_ip);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SUBSCRIBER_SESSION_DETAILS);
  ip_address_encode (&t->client_ip, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->client_ip);

  if (is_ipv6)
    {
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
    }
  rmp->session_id = htons (t->session_id);
  rmp->encap_if_index = htonl (t->encap_if_index);
  clib_memcpy (rmp->local_mac, t->local_mac, 6);
  clib_memcpy (rmp->client_mac, t->client_mac, 6);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;
  rmp->outer_vlan = htons( t->outer_vlan );
  rmp->inner_vlan = htons( t->inner_vlan );

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_subscriber_session_dump_t_handler (vl_api_subscriber_session_dump_t * mp)
{
  vl_api_registration_t *reg;
  subscriber_main_t *sm = &subscriber_main;
  subscriber_session_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, sm->sessions,
      ({
        send_subscriber_session_details(t, reg, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (sm->subscriber_by_sw_if_index)) ||
	  (~0 == sm->subscriber_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &sm->sessions[sm->subscriber_by_sw_if_index[sw_if_index]];
      send_subscriber_session_details (t, reg, mp->context);
    }
}

#include <subscriber/subscriber.api.c>
static clib_error_t *
susbcriber_api_hookup (vlib_main_t * vm)
{
  subscriber_main_t *sm = &subscriber_main;

  sm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (susbcriber_api_hookup);