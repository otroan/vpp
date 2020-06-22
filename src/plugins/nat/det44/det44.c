/*
 * det44.c - deterministic NAT
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
 * @brief deterministic NAT (CGN)
 */

#include <nat/det44/det44.h>

det44_main_t det44_main;

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_det44_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "det44-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_det44_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "det44-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_det44_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "det44-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature"),
};
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Deterministic NAT (CGN)",
};
/* *INDENT-ON* */

void
det44_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			   int is_add)
{
  fib_prefix_t prefix = {
    .fp_len = p_len,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr = {
		.ip4.as_u32 = addr->as_u32,
		},
  };
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add)
    {
      fib_table_entry_update_one_path (fib_index,
				       &prefix,
				       nat_fib_src_low,
				       (FIB_ENTRY_FLAG_CONNECTED |
				       FIB_ENTRY_FLAG_LOCAL |
				       FIB_ENTRY_FLAG_EXCLUSIVE),
				       DPO_PROTO_IP4,
				       NULL,
				       sw_if_index,
  			               ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_table_entry_delete (fib_index, &prefix, nat_fib_src_low);
    }
}

/**
 * @brief Add/delete deterministic NAT mapping.
 *
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling deterministic NAT to reduce logging in
 * CGN deployments.
 *
 * @param in_addr  Inside network address.
 * @param in_plen  Inside network prefix length.
 * @param out_addr Outside network address.
 * @param out_plen Outside network prefix length.
 * @param is_add   If 0 delete, otherwise add.
 */
int
snat_det_add_map (ip4_address_t * in_addr, u8 in_plen,
		  ip4_address_t * out_addr, u8 out_plen, int is_add)
{
  static snat_det_session_t empty_snat_det_session = { 0 };
  det44_main_t *dm = &det44_main;
  ip4_address_t in_cmp, out_cmp;
  det44_interface_t *i;
  snat_det_map_t *mp;
  u8 found = 0;

  in_cmp.as_u32 = in_addr->as_u32 & ip4_main.fib_masks[in_plen];
  out_cmp.as_u32 = out_addr->as_u32 & ip4_main.fib_masks[out_plen];
  vec_foreach (mp, dm->det_maps)
  {
    /* Checking for overlapping addresses to be added here */
    if (mp->in_addr.as_u32 == in_cmp.as_u32 &&
	mp->in_plen == in_plen &&
	mp->out_addr.as_u32 == out_cmp.as_u32 &&
	mp->out_plen == out_plen)
      {
	found = 1;
	break;
      }
  }

  /* If found, don't add again */
  if (found && is_add)
    return VNET_API_ERROR_VALUE_EXIST;

  /* If not found, don't delete */
  if (!found && !is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (is_add)
    {
      pool_get (dm->det_maps, mp);
      clib_memset (mp, 0, sizeof (*mp));
      mp->in_addr.as_u32 = in_cmp.as_u32;
      mp->in_plen = in_plen;
      mp->out_addr.as_u32 = out_cmp.as_u32;
      mp->out_plen = out_plen;
      mp->sharing_ratio = (1 << (32 - in_plen)) / (1 << (32 - out_plen));
      mp->ports_per_host = (65535 - 1023) / mp->sharing_ratio;

      vec_validate_init_empty (mp->sessions,
			       DET44_SES_PER_USER * (1 << (32 - in_plen)) -
			       1, empty_snat_det_session);
    }
  else
    {
      vec_free (mp->sessions);
      vec_del1 (dm->det_maps, mp - dm->det_maps);
    }

  /* Add/del external address range to FIB */
  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces, ({
    if (det44_interface_is_inside(i))
      continue;
    // we support only one outside fib, find first outside interface break
    det44_add_del_addr_to_fib(out_addr, out_plen, i->sw_if_index, is_add);
    break;
  }));
  /* *INDENT-ON* */
  return 0;
}

int
det44_set_timeouts (nat_timeouts_t * timeouts)
{
  det44_main_t *dm = &det44_main;
  if (timeouts->udp)
    dm->timeouts.udp = timeouts->udp;
  if (timeouts->tcp.established)
    dm->timeouts.tcp.established = timeouts->tcp.established;
  if (timeouts->tcp.transitory)
    dm->timeouts.tcp.transitory = timeouts->tcp.transitory;
  if (timeouts->icmp);
    dm->timeouts.icmp = timeouts->icmp;
  return 0;
}

nat_timeout_t timeouts
det44_get_timeouts ()
{
  det44_main_t *dm = &det44_main;
  return dm->timeouts;
}

void
det44_reset_timeouts ()
{
  det44_main_t *dm = &det44_main;
  nat_timeouts_t timeouts;
  timeouts.udp = 300;
  timeouts.tcp.established = 7440;
  timeouts.tcp.transitory = 240;
  timeouts.icmp = 60;
  dm->timeouts = timeouts;
}

int
det44_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del)
{
  det44_main_t *dm = &det44_main;
  const char *feature_name;
  u8 found;
  int rv;

  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces, ({
    if (i->sw_if_index != sw_if_index)
      continue;
    found = 1;
    break;
  }));
  /* *INDENT-ON* */

  feature_name = is_inside ? "det44-in2out" : "det44-out2in";

  if (is_del)
    {
      if (!found)
        {
          det44_log_err ("det44 is not enabled on this interface");
          return VNET_API_ERROR_INVALID_VALUE;
        }
      
      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	return rv;

      if (det44_interface_is_inside (i) && det44_interface_is_outside (i))
        {
          rv = vnet_feature_enable_disable ("ip4-unicast",
                                            "det44-classify",
                                            sw_if_index, 0, 0, 0);
          if (rv)
            return rv;

          feature_name = is_inside ? "det44-out2in" : "det44-in2out";
          rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                            sw_if_index, 1, 0, 0);
          if (rv)
            return rv; 

          if (is_inside)
            i->flags &= ~DET44_INTERFACE_FLAG_IS_INSIDE;
          else
            i->flags &= ~DET44_INTERFACE_FLAG_IS_OUTSIDE;
        }
      else
        {
          rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                            sw_if_index, 1, 0, 0);
          if (rv)
            return rv;

          pool_put (dm->interfaces, i);
        }
    }
  else
    {
      if (found)
        {
          if ((det44_interface_is_inside (i) && is_inside) ||
              (det44_interface_is_outside (i) && !is_inside))
            {
              det44_log_err ("det44 is already enabled on this interface");
              return VNET_API_ERROR_INVALID_VALUE;
            }
        }

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	return rv;

      if (found)
        {
          feature_name = is_inside ?  "det44-out2in" : "det44-in2out";
          rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                            sw_if_index, 0, 0, 0);
          if (rv)
            return rv;

          rv = vnet_feature_enable_disable ("ip4-unicast",
                                            "det44-classify",
                                            sw_if_index, 1, 0, 0);
          if (rv)
            return rv;
        }
      else
        {
          rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                            sw_if_index, 1, 0, 0);
          if (rv)
            return rv;

          pool_get (dm->interfaces, i);
          clib_memset (i, 0, sizeof (*i));

          i->sw_if_index = sw_if_index;
        }

      if (is_inside)
        i->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
      else
        i->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;
    }
  
  if (!is_inside)
    {
      // add/del outside interface fib to registry
      found = 0;
      det44_fib_t *outside_fib;
      /* *INDENT-OFF* */
      vec_foreach (outside_fib, sm->outside_fibs)
        {
          if (outside_fib->fib_index == fib_index)
            {
              if (!is_del)
                {
                  outside_fib->refcount++;
                }
              else
                {
                  outside_fib->refcount--;
                  if (!outside_fib->refcount)
                    {
                      vec_del1 (dm->outside_fibs,
                                outside_fib - dm->outside_fibs);
                    }
                }
              found = 1;
              break;
            }
        }
      /* *INDENT-ON* */
      if (!is_del && !found)
	{
	  vec_add2 (dm->outside_fibs, outside_fib, 1);
          outside_fib->fib_index = fib_index;
	  outside_fib->refcount = 1;
	}
      // add/del outside address to FIB
      snat_det_map_t *mp;
      /* *INDENT-OFF* */
      pool_foreach (mp, dm->det_maps, ({
        snat_add_del_addr_to_fib(&mp->out_addr,
                                 mp->out_plen, sw_if_index, !is_del);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

int
det44_plugin_enable (det44_config_t c)
{
  det44_main_t *dm = &det44_main;

  if (dm->enabled)
    {
      det44_log_err ("det44 plugin already enabled");
      return 1;
    }

  dm->outside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
							     c.outside_vrf_id,
							     dm->fib_src_hi);
  dm->inside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
							    c.inside_vrf_id,
							    dm->fib_src_hi);
  dm->config = c;
  dm->mss_clamping = 0;
  return 0;
} 

int
det44_plugin_disable ()
{
  det44_main_t *dm = &det44_main;

  if (!dm->enabled)
    {
      det44_log_err ("det44 plugin already disabled");
      return 1;
    }

  // TODO: (basically cleanup deterministic nat)
  // 1) remove all interfaces
  // 2) remove all deterministic maps

  det44_reset_timeouts ();
  return 0;
} 

static clib_error_t *
snat_init (vlib_main_t * vm)
{
  det44_main_t *dm = &det44_main;
  clib_error_t *error = 0;
  vlib_node_t *node;

  node = vlib_get_node_by_name (vm, (u8 *) "det44-in2out");
  dm->in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "det44-out2in");
  dm->out2in_node_index = node->index;

  dm->fib_src_hi = fib_source_allocate ("det44-hi",
					FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);

  // TODO: (are these required) ??
  // 1) vec_add1 (im->add_del_interface_address_callbacks, cb4);
  // 2) vec_add1 (ip4_main.table_bind_callbacks, cbt4);
  // TODO:
  // refactoring of in2out and out2in will show us !!

  det44_reset_timeouts ();
  return det44_api_hookup (vm);
}

VLIB_INIT_FUNCTION (det44_init);

u8 *
format_session_state (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, N, str) case DET44_SESSION_##N: t = (u8 *) str; break;
      foreach_det44_session_state
#undef _
    default:
      t = format (t, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

u8 *
format_det_map_ses (u8 * s, va_list * args)
{
  snat_det_map_t *det_map = va_arg (*args, snat_det_map_t *);
  ip4_address_t in_addr, out_addr;
  u32 in_offset, out_offset;
  snat_det_session_t *ses = va_arg (*args, snat_det_session_t *);
  u32 *i = va_arg (*args, u32 *);

  u32 user_index = *i / DET44_SES_PER_USER;
  in_addr.as_u32 =
    clib_host_to_net_u32 (clib_net_to_host_u32 (det_map->in_addr.as_u32) +
			  user_index);
  in_offset =
    clib_net_to_host_u32 (in_addr.as_u32) -
    clib_net_to_host_u32 (det_map->in_addr.as_u32);
  out_offset = in_offset / det_map->sharing_ratio;
  out_addr.as_u32 =
    clib_host_to_net_u32 (clib_net_to_host_u32 (det_map->out_addr.as_u32) +
			  out_offset);
  s =
    format (s,
	    "in %U:%d out %U:%d external host %U:%d state: %U expire: %d\n",
	    format_ip4_address, &in_addr, clib_net_to_host_u16 (ses->in_port),
	    format_ip4_address, &out_addr,
	    clib_net_to_host_u16 (ses->out.out_port), format_ip4_address,
	    &ses->out.ext_host_addr,
	    clib_net_to_host_u16 (ses->out.ext_host_port),
	    format_session_state, ses->state, ses->expire);

  return s;
}

/**
 * @brief The 'nat-det-expire-walk' process's main loop.
 *
 * Check expire time for active sessions.
 */
static uword
det44_expire_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
			 vlib_frame_t * f)
{
  det44_main_t *dm = &det44_main;
  snat_det_session_t *ses;
  snat_det_map_t *mp;

  vlib_process_wait_for_event_or_clock (vm, 10.0);
  vlib_process_get_events (vm, NULL);
  u32 now = (u32) vlib_time_now (vm);
  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps, ({
    vec_foreach(ses, mp->sessions)
      {
        /* Delete if session expired */
        if (ses->in_port && (ses->expire < now))
          snat_det_ses_close (mp, ses);
      }
  }));
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (det44_expire_walk_node, static) = {
    .function = det44_expire_walk_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "det44-expire-walk",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
