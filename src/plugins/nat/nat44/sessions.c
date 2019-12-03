/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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


static_always_inline
nat44_user_t *
nat44_user_get (nat44_database_t * db, u64 key)
{
  nat44_user_t *u;
  clib_bihash_kv_8_8_t v;

  if (clib_bihash_search_8_8 (db->user_hash, (clib_bihash_kv_8_8_t *) & key,
                              & v))
    {
      return 0;
    }

  return pool_elt_at_index (db->users, v.value);
}

static_always_inline
nat44_user_t *
nat44_user_add (nat44_database_t * db, u64 key)
{
  nat44_user_t *u;
  clib_bihash_kv_8_8_t kv;
  u32 user_sessions_index;
  dlist_elt_t *user_sessions_elt;

  // create new user sessions doubly-linked list head
  // element, get it's index and initialize it
  pool_get (db->user_sessions, user_sessions_elt);
  user_sessions_index = user_sessions_elt -
	db->user_sessions;
  clib_dlist_init (db->user_sessions, user_sessions_index);
  
  // create new user
  pool_get (db->users, u);
  clib_memset (u, 0, sizeof (*u));

  // add user sessions doubly-linked list head index
  u->user_sessions_index = user_sessions_index;

  kv.key = key;
  kv.value = u - db->users;

  if (clib_bihash_add_del_8_8 (&db->user_hash, &kv, 1))
    {
      pool_put (db->user_sessions, user_sessions_elt);
      pool_put (db->users, u);

      nat_elog_warn ("nat44 user add failed");

      return 0;
    }

  return u; 
}

// delete all user sessions ? ?
// there is a logic behind this one
// TODO:
// consider this:
// user can have a counter that will meassure
// when he was last heard ?
// session + user have this kind of counter
// based on those we can do a cleanup of whole
// user and all of his sessions
int
nat44_user_del (nat44_database_t * db, u64 key)
{
  nat44_user_t *u;
  u32 user_sessions_index;

  u = nat44_user_get (db, key);

  if (u)
    {
      // get user sessions doubly-linked list head index
      user_sessions_index = u->user_sessions_index;

      // delete user 
      pool_put (db->users, u);
      
      // traverse over all user sessions and delete
      // session and the element in doubly-linked list ?
      pool_put (db->user_sessions, user_sessions_index);
      
    }

  if (clib_bihash_add_del_8_8 (&db->user_hash, &kv, 0))
    {

    }

  return 1; 
}

snat_user_t *
nat_user_get_or_create (snat_main_t * sm, ip4_address_t * addr, u32 fib_index,
			u32 thread_index)
{
  snat_user_t *u = 0;
  snat_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  dlist_elt_t *per_user_list_head_elt;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  if (clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
    {
      // create new user
      pool_get (tsm->users, u);
      clib_memset (u, 0, sizeof (*u));
      u->addr.as_u32 = addr->as_u32;
      u->fib_index = fib_index;

      pool_get (tsm->list_pool, per_user_list_head_elt);

      u->sessions_per_user_list_head_index = per_user_list_head_elt -
	tsm->list_pool;

      clib_dlist_init (tsm->list_pool, u->sessions_per_user_list_head_index);

      kv.value = u - tsm->users;

      // add user
      if (clib_bihash_add_del_8_8 (&tsm->user_hash, &kv, 1))
	nat_elog_warn ("user_hash keay add failed");

      vlib_set_simple_counter (&sm->total_users, thread_index, 0,
			       pool_elts (tsm->users));
    }
  else
    {
      u = pool_elt_at_index (tsm->users, value.value);
    }

  return u;
}

snat_session_t *
nat_session_alloc_or_recycle (snat_main_t * sm, snat_user_t * u,
			      u32 thread_index, f64 now)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 oldest_per_user_translation_list_index, session_index;
  dlist_elt_t *oldest_per_user_translation_list_elt;
  dlist_elt_t *per_user_translation_list_elt;

  /* Over quota? Recycle the least recently used translation */
  if ((u->nsessions + u->nstaticsessions) >= sm->max_translations_per_user)
    {
      oldest_per_user_translation_list_index =
	clib_dlist_remove_head (tsm->list_pool,
				u->sessions_per_user_list_head_index);

      ASSERT (oldest_per_user_translation_list_index != ~0);

      /* Add it back to the end of the LRU list */
      clib_dlist_addtail (tsm->list_pool,
			  u->sessions_per_user_list_head_index,
			  oldest_per_user_translation_list_index);
      /* Get the list element */
      oldest_per_user_translation_list_elt =
	pool_elt_at_index (tsm->list_pool,
			   oldest_per_user_translation_list_index);

      /* Get the session index from the list element */
      session_index = oldest_per_user_translation_list_elt->value;

      /* Get the session */
      s = pool_elt_at_index (tsm->sessions, session_index);
      nat_free_session_data (sm, s, thread_index, 0);
      if (snat_is_session_static (s))
	u->nstaticsessions--;
      else
	u->nsessions--;
      s->flags = 0;
      s->total_bytes = 0;
      s->total_pkts = 0;
      s->state = 0;
      s->ext_host_addr.as_u32 = 0;
      s->ext_host_port = 0;
      s->ext_host_nat_addr.as_u32 = 0;
      s->ext_host_nat_port = 0;
    }
  else
    {
      pool_get (tsm->sessions, s);
      clib_memset (s, 0, sizeof (*s));

      /* Create list elts */
      pool_get (tsm->list_pool, per_user_translation_list_elt);
      clib_dlist_init (tsm->list_pool,
		       per_user_translation_list_elt - tsm->list_pool);

      per_user_translation_list_elt->value = s - tsm->sessions;
      s->per_user_index = per_user_translation_list_elt - tsm->list_pool;
      s->per_user_list_head_index = u->sessions_per_user_list_head_index;

      clib_dlist_addtail (tsm->list_pool,
			  s->per_user_list_head_index,
			  per_user_translation_list_elt - tsm->list_pool);

      s->user_index = u - tsm->users;
      vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			       pool_elts (tsm->sessions));
    }

  s->ha_last_refreshed = now;

  return s;
}

snat_session_t *
nat_ed_session_alloc (snat_main_t * sm, snat_user_t * u, u32 thread_index,
		      f64 now)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  dlist_elt_t *per_user_translation_list_elt, *oldest_elt;
  u32 oldest_index;
  u64 sess_timeout_time;

  if (PREDICT_FALSE (!(u->nsessions) && !(u->nstaticsessions)))
    goto alloc_new;

  oldest_index =
    clib_dlist_remove_head (tsm->list_pool,
			    u->sessions_per_user_list_head_index);
  oldest_elt = pool_elt_at_index (tsm->list_pool, oldest_index);
  s = pool_elt_at_index (tsm->sessions, oldest_elt->value);

  sess_timeout_time = s->last_heard + (f64) nat44_session_get_timeout (sm, s);
  if (now >= sess_timeout_time)
    {
      clib_dlist_addtail (tsm->list_pool,
			  u->sessions_per_user_list_head_index, oldest_index);
      nat_free_session_data (sm, s, thread_index, 0);
      if (snat_is_session_static (s))
	u->nstaticsessions--;
      else
	u->nsessions--;
      s->flags = 0;
      s->total_bytes = 0;
      s->total_pkts = 0;
      s->state = 0;
      s->ext_host_addr.as_u32 = 0;
      s->ext_host_port = 0;
      s->ext_host_nat_addr.as_u32 = 0;
      s->ext_host_nat_port = 0;
    }
  else
    {
      clib_dlist_addhead (tsm->list_pool,
			  u->sessions_per_user_list_head_index, oldest_index);
      if ((u->nsessions + u->nstaticsessions) >=
	  sm->max_translations_per_user)
	{
	  nat_elog_addr (SNAT_LOG_WARNING, "[warn] max translations per user",
			 clib_net_to_host_u32 (u->addr.as_u32));
	  snat_ipfix_logging_max_entries_per_user
	    (thread_index, sm->max_translations_per_user, u->addr.as_u32);
	  return 0;
	}
      else
	{
	alloc_new:
	  pool_get (tsm->sessions, s);
	  clib_memset (s, 0, sizeof (*s));

	  /* Create list elts */
	  pool_get (tsm->list_pool, per_user_translation_list_elt);
	  clib_dlist_init (tsm->list_pool,
			   per_user_translation_list_elt - tsm->list_pool);

	  per_user_translation_list_elt->value = s - tsm->sessions;
	  s->per_user_index = per_user_translation_list_elt - tsm->list_pool;
	  s->per_user_list_head_index = u->sessions_per_user_list_head_index;

	  clib_dlist_addtail (tsm->list_pool,
			      s->per_user_list_head_index,
			      per_user_translation_list_elt - tsm->list_pool);
	}

      vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			       pool_elts (tsm->sessions));
    }

  s->ha_last_refreshed = now;

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
