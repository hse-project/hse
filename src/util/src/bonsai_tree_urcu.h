/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_BONSAI_TREE_URCU_H
#define HSE_BONSAI_TREE_URCU_H

#define BONSAI_RCU_DEREF_POINTER(ptr) rcu_dereference(ptr)
#define BONSAI_RCU_ASSIGN_POINTER(ptr, val) rcu_assign_pointer(ptr, val)
#ifdef BONSAI_SYNC_GARBAGE_RELEASE
#define BONSAI_SYNCHRONIZE_RCU() synchronize_rcu()
#else
#define BONSAI_SYNCHRONIZE_RCU()
#endif
#define BONSAI_RCU_REGISTER() rcu_register_thread()
#define BONSAI_RCU_UNREGISTER() rcu_unregister_thread()
#define BONSAI_RCU_QUIESCE() rcu_quiescent_state()
#define BONSAI_RCU_READ_LOCK() rcu_read_lock()
#define BONSAI_RCU_READ_UNLOCK() rcu_read_unlock()
#define BONSAI_CALL_RCU(ptr, func) call_rcu(ptr, func)
#define BONSAI_DEFER_RCU(ptr, func) defer_rcu(func, ptr)
#define BONSAI_RCU_HEAD struct rcu_head
#define BONSAI_RCU_INIT()
#define BONSAI_RCU_EXIT()
#define BONSAI_RCU_ATOMIC_INC(addr) uatomic_inc(addr)
#define BONSAI_RCU_ATOMIC_DEC(addr) uatomic_dec(addr)
#define BONSAI_RCU_BARRIER() rcu_barrier()
#endif
