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
/**
 * @brief NAT IPv4 user and session management
 */
#ifndef __included_sessions_h__
#define __included_sessions_h__

/*
  TODO:
  - what do we need ?
  - we need in2out and out2in lookups for sessions
  - we need user and session table
  - we need to know how and when are both accessed

  user
   - user key; (src address + fib_index)
   - sessions; // if we hold all user session this could slow down
               // creation and manamgent of session data
   - sessions_n;
   - static_sessions_n;

  users
   - user_hash
   - users
   - sessions - all sessions for all users ?
    - we don't really need this do we ?
    - why don't we use pointers ? (they should have the same address no?)
      - but we use offsets
    - we could hold in in2out value containing pointer to session directly
    in user structure, or we can hold all of these values in a kind of
    user_session datastructure ?
    - but the keys should be generic size.

  no ipv6 generic stuff here only ipv4
    - all session and session data are large enough to hold ED nat data
    structures

  session
    - simple / endpoint dependent difference in structure
    - using template structures for different types ??
  
  sessions
    - user_hash
    - in2out_hash
    - out2in_hash
    - user_vec
    - session_vec

  tsm->list_pool
    - per thread data list_pool containing, users
    - Pool of doubly-linked list element

    snat_alloc_outside_address_and_port
      - endpoint-dependent/simple nat
      - callback for different types of allocation
      - sm->alloc_addr_and_port

slow path:
  (nat44_sessions_cleanup(sessions, src_address, time_now))
    - we need time now to be able to determine how much time did
    pass between the state of session
  nat44_session_try_cleanup
    1) free sessions for requested user
    2) free sessions
      (be carefull these two are mutually dependent)
      - free sessions & free sessions for requested user
    3) successfull cleanup for requested user
    4) successfull cleanup
      - if there is no such user but sessions are full we need to
      do cleanup of any session for any user

    - all of these states mean we can create a new session
    -
      nat44_session_del
      nat44_user_session_try_cleanup
      nat44_sessions_cleanup

  maximum_sessions_exceeded
    - this is obsolete and should be removed

  nat_user_get_or_create
    - split (nat44_user_get/nat44_user_add)
  nat_ed_session_alloc
    - (nat44_session_add)


CONCEPT (new session creation (in slow path)):

  nat44_sessions_cleanup_expired()
    nat44_user_get()/nat44_user_foreach()
    nat44_user_sessions_cleanup_expired()
      nat44_session_del()

  nat44_session_new()
    - nat44_sessions_cleanup_expired()
      - we could call it directly from here ...
      - we could ofc. have a parameter that wouldd say
      if we wanna do a cleanup or not

    nat44_user_get()
    nat44_user_add()
    nat44_user_session_add()
      nat44_session_add()

what should API look like ?

  - unfirom structure
  nat44_database_t
    - contains users and sessions
    - all data required for user session manipulation
  nat44_database_init()
    - returns pointer to the database

  users_t
  nat44_users_init()
  nat44_user_get()
  nat44_user_add()
  nat44_user_del()

  sessions_t
  nat44_sessions_init()
  nat44_sessions_cleanup_expired()
    - cleanup all expired sessions
    - does require access to users
  nat44_session_get()
  nat44_session_add()
  nat44_session_del()

  users_t, sessions_t (association)
  nat44_user_sessions_cleanup_expired()
    - cleanup sessions for the specified user
  nat44_user_session_add()
  nat44_user_session_del()

what type of sessions do we have ?
 a) dynamic sessions
 b) static sessions
 c) unknown protocol sessions
  - for some reason they use fib index of resolving interface,
  based on destination address
    - for all of these user and a session is created
    - i guess all of them are looked up the same way

 */

// obsolete
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t src_addr;
      u32 fib_index;
    };
    u64 as_u64;
  };
} nat44_user_key_t;

// source 23322 patch
static_always_inline u64
nat44_user_create_key (ip4_address_t src_addr, u32 fib_index)
{
  // TODO: upgrade
  nat44_user_key_t key;
  /*u64 key;
  key = src_addr.as_u32;
  key |= (u64) fib_index << 32;*/
  key.src_addr = src_addr;
  key.fib_index = fib_index;
  return (u64) key;
}

// obsolete
/* simple session key (4-tuple) */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u16 protocol:3, fib_index:13;
    };
    u64 as_u64;
  };
} nat44_session_key_t;

static_always_inline u64
nat44_session_create_key (ip4_address_t addr, u16 port, u16 protocol, u16 fib_index)
{
  // TODO: upgrade
  nat44_session_key_t key;
  /*u64 key;
  key = addr.as_u32;
  key |= (u64) port << 32;
  key |= ((u64) protocol & 0x7) << 48;
  key |= ((u64) fib_index & 0x1fff) << 51;*/
  key.addr = addr;
  key.port = port;
  key.protocol = protocol;
  key.fib_index = fib_index;
  return (u64) key;
}

// obsolete
/* endpoint-dependent session key (6-tuple) */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t l_addr;
      ip4_address_t r_addr;
      u32 proto:8, fib_index:24;
      u16 l_port;
      u16 r_port;
    };
    u64 as_u64[2];
  };
} nat44_session_ed_key_t;


static_always_inline u128
nat44_session_ed_create_key (ip4_address_t l_addr, ip4_address_t r_addr, u16 l_port, u16 r_port, u16 protocol, u16 fib_index)
{
  // TODO: upgrade
  nat44_session_ed_key_t key;
  /*u128 key;*/
  key.l_addr = l_addr;
  key.r_addr = r_addr;
  key.l_port = l_port;
  key.r_port = r_port;
  key.protocol = protocol;
  key.fib_index = fib_index;
  return (u128) key;
}

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  // User sessions doubly-linked list head element index
  u32 user_sessions_index;

  ip4_address_t addr;
  u32 fib_index;

  // last heared off ?
  // this would require each time we get a session in fast path
  // to get user and update this statistic counter
  // if we have a index in session record this should not
  // be that hard.
  // if last heard off per user is greater than any of the max
  // counters do whole user cleanup
  
  u32 nsessions;
  u32 nstaticsessions;

}) nat44_user_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  // used all over this place also used in combo
  // with endpoint dependent to store addr and port
  // all data structures inside this type are used
  // interchangablly and it isn't really nice !!!
  /* Network keys */
  nat44_session_key_t in2out;
  nat44_session_key_t out2in;

  /* Flags */
  u32 flags;

  /* Per-user translations */
  u32 per_user_index;
  u32 per_user_list_head_index;

  /* Last heard timer */
  f64 last_heard;

  /* Last HA refresh */
  f64 ha_last_refreshed;

  /* Counters */
  u64 total_bytes;
  u32 total_pkts;

  /* External host address and port */
  ip4_address_t ext_host_addr;
  u16 ext_host_port;

  /* External host address and port after translation */
  ip4_address_t ext_host_nat_addr;
  u16 ext_host_nat_port;

  /* TCP session state */
  u8 state;
  u32 i2o_fin_seq;
  u32 o2i_fin_seq;

  /* user index */
  u32 user_index;

}) nat44_session_t;
/* *INDENT-ON* */

typedef struct
{
  /* User pool */
  nat44_user_t *users;

  /* Session pool */
  nat44_session_t *sessions;

  /* User sessions doubly-linked list pool */
  dlist_elt_t * user_sessions;

  /* User lookup table */
  clib_bihash_8_8_t user_table;

  /* Simple sessions lookup tables */
  clib_bihash_8_8_t i2o_session_table;
  clib_bihash_8_8_t o2i_session_table;
  
  /* Endpoint dependent sessions lookup tables */
  clib_bihash_16_8_t i2o_ed_session_table;
  clib_bihash_16_8_t o2i_ed_session_table;

} nat44_database_t;

#endif /* __included_sessions_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
