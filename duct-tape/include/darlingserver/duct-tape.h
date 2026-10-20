#ifndef _DARLINGSERVER_DUCT_TAPE_H_
#define _DARLINGSERVER_DUCT_TAPE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <libsimple/lock.h>
#include <darlingserver/rpc.internal.h>
#include <darlingserver/rpc-supplement.h>
#include <darlingserver/rpc.h>

#include <darlingserver/duct-tape/types.h>
#include <darlingserver/duct-tape/hooks.h>

#ifdef __cplusplus
extern "C" {
#endif

void dtape_init(const dtape_hooks_t* hooks);
void dtape_init_in_thread(void);
void dtape_deinit(void);

uint32_t dtape_task_self_trap(void);
uint32_t dtape_host_self_trap(void);
uint32_t dtape_thread_self_trap(void);
uint32_t dtape_mach_reply_port(void);
uint32_t dtape_thread_get_special_reply_port(void);
uint32_t dtape_mk_timer_create(void);

DSERVER_DTAPE_DECLS;

typedef void (*dtape_kqchan_mach_port_notification_callback_f)(void* context);

/**
 * The threshold beyond which thread IDs are considered IDs for kernel threads.
 * Thread IDs lower than this value are reserved for userspace threads.
 * Thread IDs greater than or equal to this value are reserved for kernelspace threads.
 *
 * This should NOT be used to differentiate kernelspace threads from userspace ones.
 * This is simply used as a convenient cutoff beyond which we do not expect Linux to actually assign
 * thread IDs within our namespace. In practice, there should be no difference between the way userspace
 * and kernelspace threads are handled in the duct-tape code.
 *
 * This is used as the starting offset for thread IDs for kernelspace threads (which do not have a "real" managed Darling thread backing them).
 */
#define DTAPE_KERNEL_THREAD_ID_THRESHOLD (1ULL << 22)

/**
 * Creates a new duct-tape task. The caller receives a reference on the new task.
 *
 * An @p nsid value of `0` indicates the task being created is the kernel task.
 */
dtape_task_t* dtape_task_create(dtape_task_t* parent_task, uint32_t nsid, void* context, dserver_rpc_architecture_t architecture);
dtape_thread_t* dtape_thread_create(dtape_task_t* task, uint64_t nsid, void* context);
dtape_kqchan_mach_port_t* dtape_kqchan_mach_port_create(dtape_task_t* owning_task, uint32_t port, uint64_t receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags, dtape_kqchan_mach_port_notification_callback_f notification_callback, void* context);
dtape_semaphore_t* dtape_semaphore_create(dtape_task_t* owning_task, int initial_value);

void dtape_kqchan_mach_port_destroy(dtape_kqchan_mach_port_t* kqchan);
void dtape_semaphore_destroy(dtape_semaphore_t* semaphore);

void dtape_thread_entering(dtape_thread_t* thread);
void dtape_thread_exiting(dtape_thread_t* thread);
void dtape_thread_set_handles(dtape_thread_t* thread, uintptr_t pthread_handle, uintptr_t dispatch_qaddr);
/**
 * Returns the thread corresponding to the given thread port.
 *
 * @warning It is VERY important that the caller ensures the thread cannot die while we're looking it up.
 *          This can be accomplished, for example, by locking the global thread list before the call.
 */
dtape_thread_t* dtape_thread_for_port(uint32_t thread_port);
void* dtape_thread_context(dtape_thread_t* thread);
int dtape_thread_load_state_from_user(dtape_thread_t* thread, uintptr_t thread_state_address, uintptr_t float_state_address);
int dtape_thread_save_state_to_user(dtape_thread_t* thread, uintptr_t thread_state_address, uintptr_t float_state_address);
void dtape_thread_process_signal(dtape_thread_t* thread, int bsd_signal_number, int linux_signal_number, int code, uintptr_t signal_address);
void dtape_thread_wait_while_user_suspended(dtape_thread_t* thread);
void dtape_thread_retain(dtape_thread_t* thread);
void dtape_thread_release(dtape_thread_t* thread);
void dtape_thread_sigexc_enter(dtape_thread_t* thread);
void dtape_thread_sigexc_exit(dtape_thread_t* thread);
void dtape_thread_sigexc_enter2(dtape_thread_t* thread);
void dtape_thread_dying(dtape_thread_t* thread);

void dtape_task_uidgid(dtape_task_t* task, int new_uid, int new_gid, int* old_uid, int* old_gid);
// the process's unique ID and its parent's (eternal IDs, like XNU's p_uniqueid and p_puniqueid), and the task's
// pidversion (audit_token.val[7], like XNU's p_idversion)
void dtape_task_identity(dtape_task_t* task, uint64_t* unique_id, uint64_t* parent_unique_id, uint32_t* pidversion);
// sets the process's unique ID (XNU's p_uniqueid), which the process registry assigns only after the task exists, in
// the task and its bank context
void dtape_task_set_eternal_id(dtape_task_t* task, uint64_t eid);

/**
 * Makes a fileport for the given descriptor in the given task and returns its name in `out_name`. The fileport owns
 * the descriptor from then on, even when this fails. Returns 0 or a negative errno.
 */
int dtape_fileport_makeport(dtape_task_t* task, int fd, uint32_t* out_name);

/**
 * Returns a new descriptor (of darlingserver's) for the file the given task's fileport stands for, or a negative errno.
 */
int dtape_fileport_makefd(dtape_task_t* task, uint32_t name);

/**
 * Sets the given task's bootstrap port to a send right for the given name in its space, as posix_spawn() applies a
 * PSPA_SPECIAL port action (exec_handle_port_actions() in XNU's bsd/kern/kern_exec.c); posix_spawn() lends it to the
 * child this way, and no other special port can be lent (KERN_INVALID_ARGUMENT). Unlike task_set_special_port(), this
 * takes ports whose rights are immovable: launchd gives its jobs such bootstrap ports. Returns a kern_return_t.
 */
int dtape_task_set_special_port_for_spawn(dtape_task_t* task, int which, uint32_t name);
void dtape_task_retain(dtape_task_t* task);
void dtape_task_release(dtape_task_t* task);
void dtape_task_dying(dtape_task_t* task);
void dtape_task_set_dyld_info(dtape_task_t* task, uint64_t address, uint64_t length);
void dtape_task_set_sigexc_enabled(dtape_task_t* task, bool enabled);
bool dtape_task_try_resume(dtape_task_t* task);

/**
 * Invoked when a timer armed by an earlier call to the timer_arm hook expires.
 *
 * It is allowed to be invoked spuriously.
 */
void dtape_timer_fired(void);

void dtape_kqchan_mach_port_modify(dtape_kqchan_mach_port_t* kqchan, uint64_t receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags);
void dtape_kqchan_mach_port_disable_notifications(dtape_kqchan_mach_port_t* kqchan);
bool dtape_kqchan_mach_port_fill(dtape_kqchan_mach_port_t* kqchan, dserver_kqchan_reply_mach_port_read_t* reply, uint64_t default_buffer, uint64_t default_buffer_size);
bool dtape_kqchan_mach_port_has_events(dtape_kqchan_mach_port_t* kqchan);

void dtape_semaphore_up(dtape_semaphore_t* semaphore);
dtape_semaphore_wait_result_t dtape_semaphore_down(dtape_semaphore_t* semaphore);
bool dtape_semaphore_down_simple(dtape_semaphore_t* semaphore);
dtape_semaphore_wait_result_t dtape_semaphore_down_timed(dtape_semaphore_t* semaphore, uint64_t timeout_ns);
/**
 * Keeps a semaphore usable by a waiter that got it from somewhere it may be destroyed meanwhile: a wait on a
 * destroyed semaphore then fails instead of reading freed memory. Each retain needs a release.
 */
void dtape_semaphore_retain(dtape_semaphore_t* semaphore);
void dtape_semaphore_release(dtape_semaphore_t* semaphore);

uint64_t dtape_debug_task_port_count(dtape_task_t* task);
uint64_t dtape_debug_task_list_ports(dtape_task_t* task, dtape_debug_task_list_ports_iterator_f iterator, void* context);
uint64_t dtape_debug_portset_list_members(dtape_task_t* task, uint32_t portset, dtape_debug_portset_list_members_iterator_f iterator, void* context);
uint64_t dtape_debug_port_list_messages(dtape_task_t* task, uint32_t port, dtape_debug_port_list_messages_iterator_f iterator, void* context);

#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_DUCT_TAPE_H_
