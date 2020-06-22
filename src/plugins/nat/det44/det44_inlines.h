/*
 * det44.h - deterministic NAT definitions
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief Deterministic NAT (CGN) inlines
 */

#ifndef __included_det44_inlines_h__
#define __included_det44_inlines_h__

static_always_inline int
det44_is_interface_addr (vlib_node_runtime_t * node,
		         u32 sw_if_index0, u32 ip4_addr)
{
  det44_runtime_t *rt = (det44_runtime_t *) node->runtime_data;
  det44_main_t *dm = &det44_main_t;
  ip4_address_t *first_int_addr;

  if (PREDICT_FALSE (rt->cached_sw_if_index != sw_if_index0))
    {
      first_int_addr = ip4_interface_first_address (dm->ip4_main,
                                                    sw_if_index0, 0);
      rt->cached_sw_if_index = sw_if_index0;
      if (first_int_addr)
	rt->cached_ip4_address = first_int_addr->as_u32;
      else
	rt->cached_ip4_address = 0;
    }
  if (PREDICT_FALSE (rt->cached_ip4_address == ip4_addr))
    return 0;
  return 1;
}

#endif /* __included_det44_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
