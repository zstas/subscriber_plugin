/*
 * Copyright (c) 2017 Intel and/or its affiliates.
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <pppoe/pppoe.h>
#include <vnet/format_fns.h>

#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base subscriber_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>


uword unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat(input, "%U", unformat_ip4_address, &ip46->ip4)) {
    ip46_address_mask_ip4(ip46);
    return 1;
  } else if ((type != IP46_TYPE_IP4) &&
      unformat(input, "%U", unformat_ip6_address, &ip46->ip6)) {
    return 1;
  }
  return 0;
}
uword unformat_ip46_prefix (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u8 *len = va_arg (*args, u8 *);
  ip46_type_t type = va_arg (*args, ip46_type_t);

  u32 l;
  if ((type != IP46_TYPE_IP6) && unformat(input, "%U/%u", unformat_ip4_address, &ip46->ip4, &l)) {
    if (l > 32)
      return 0;
    *len = l + 96;
    ip46->pad[0] = ip46->pad[1] = ip46->pad[2] = 0;
  } else if ((type != IP46_TYPE_IP4) && unformat(input, "%U/%u", unformat_ip6_address, &ip46->ip6, &l)) {
    if (l > 128)
      return 0;
    *len = l;
  } else {
    return 0;
  }
  return 1;
}
/////////////////////////

#include <subscriber/subscriber.api_enum.h>
#include <subscriber/subscriber.api_types.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} subscriber_test_main_t;

subscriber_test_main_t subscriber_test_main;

static void vl_api_subscriber_session_details_t_handler
  (vl_api_subscriber_session_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t client_ip;
  ip_address_decode(&mp->client_ip, &client_ip);
  print (vam->ofp, "%11d%14d%24U%14d%14d%30U%30U",
       ntohl (mp->sw_if_index), ntohl (mp->session_id),
       format_ip46_address, &client_ip, IP46_TYPE_ANY,
       ntohl (mp->encap_if_index), ntohl (mp->decap_vrf_id),
       format_ethernet_address, mp->local_mac,
       format_ethernet_address, mp->client_mac);
}

static int
api_subscriber_session_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_subscriber_session_dump_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
      sw_if_index_set = 1;
      else
      break;
    }

  if (sw_if_index_set == 0)
    {
      sw_if_index = ~0;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%11s%24s%14s%14s%14s",
	   "sw_if_index", "client_ip", "session_id",
	   "encap_if_index", "decap_fib_index",
	   "local-mac", "client-mac");
    }

  /* Get list of subscriber-session interfaces */
  M (SUBSCRIBER_SESSION_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  W (ret);
  return ret;
}

#include <subscriber/subscriber.api_test.c>
