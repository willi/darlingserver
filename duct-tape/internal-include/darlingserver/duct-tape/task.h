#ifndef _DARLINGSERVER_DUCT_TAPE_TASK_H_
#define _DARLINGSERVER_DUCT_TAPE_TASK_H_

#include <kern/task.h>

#include <darlingserver/rpc.h>
#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/condvar.h>
#include <darlingserver/duct-tape/types.h>

typedef struct dtape_task dtape_task_t;

struct proc_ident {
	dtape_eternal_id_t eid;
};

struct dtape_task {
	void* context;
	uint32_t saved_pid;
	dserver_rpc_architecture_t architecture;
	bool has_sigexc;
	void* p_pthhash;
	uint64_t dyld_info_addr;
	uint64_t dyld_info_length;
	dtape_mutex_t dyld_info_lock;
	dtape_condvar_t dyld_info_condvar;
	struct proc_ident p_ident;
	// like XNU's p_puniqueid: the eternal ID of the process that forked this one
	dtape_eternal_id_t parent_eid;
	// the audit session; its auid and asid are also in xnu_task.audit_token (val[0], val[6]); both written under the task lock
	dtape_audit_session_t audit_session;
	struct task xnu_task;
};

__attribute__((always_inline))
static dtape_task_t* dtape_task_for_xnu_task(task_t xnu_task) {
	if (!xnu_task) {
		return NULL;
	}
	return (dtape_task_t*)((char*)xnu_task - offsetof(dtape_task_t, xnu_task));
};

void dtape_task_init(void);

// the bank context's copy of the process's unique ID (bank.c), for the kernel task, whose ID comes after its context
void dtape_bank_task_set_unique_pid(task_t task, uint64_t unique_pid);

#endif // _DARLINGSERVER_DUCT_TAPE_TASK_H_
