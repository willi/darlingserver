#include <darlingserver/duct-tape/semaphore.h>
#include <darlingserver/duct-tape/task.h>

#include <mach/semaphore.h>
#include <mach/task.h>

#include <stdlib.h>

dtape_semaphore_t* dtape_semaphore_create(dtape_task_t* owning_task, int initial_value) {
	dtape_semaphore_t* semaphore = malloc(sizeof(dtape_semaphore_t));
	if (!semaphore) {
		return NULL;
	}

	semaphore->owning_task = owning_task;

	if (semaphore_create(&semaphore->owning_task->xnu_task, &semaphore->xnu_semaphore, 0, initial_value) != KERN_SUCCESS) {
		free(semaphore);
		return NULL;
	}

	return semaphore;
};

void dtape_semaphore_destroy(dtape_semaphore_t* semaphore) {
	if (semaphore_destroy(&semaphore->owning_task->xnu_task, semaphore->xnu_semaphore) != KERN_SUCCESS) {
		panic("Failed to destroy duct-taped XNU semaphore");
	}

	free(semaphore);
};

void dtape_semaphore_up(dtape_semaphore_t* semaphore) {
	if (semaphore_signal(semaphore->xnu_semaphore) != KERN_SUCCESS) {
		panic("Failed to raise up-count of duct-taped XNU semaphore");
	}
};

dtape_semaphore_wait_result_t dtape_semaphore_down(dtape_semaphore_t* semaphore) {
	kern_return_t kr = semaphore_wait(semaphore->xnu_semaphore);
	switch (kr) {
		case KERN_SUCCESS:
			return dtape_semaphore_wait_result_ok;
		case KERN_ABORTED:
			return dtape_semaphore_wait_result_interrupted;
		default:
			return dtape_semaphore_wait_result_error;
	}
};

dtape_semaphore_wait_result_t dtape_semaphore_down_timed(dtape_semaphore_t* semaphore, uint64_t timeout_ns) {
	mach_timespec_t timeout = { (unsigned int)(timeout_ns / NSEC_PER_SEC), (clock_res_t)(timeout_ns % NSEC_PER_SEC) };
	kern_return_t kr = semaphore_timedwait(semaphore->xnu_semaphore, timeout);
	switch (kr) {
		case KERN_SUCCESS:
			return dtape_semaphore_wait_result_ok;
		case KERN_ABORTED:
			return dtape_semaphore_wait_result_interrupted;
		case KERN_OPERATION_TIMED_OUT:
			return dtape_semaphore_wait_result_timed_out;
		default:
			return dtape_semaphore_wait_result_error;
	}
};

bool dtape_semaphore_down_simple(dtape_semaphore_t* semaphore) {
	kern_return_t kr = semaphore_wait(semaphore->xnu_semaphore);
	switch (kr) {
		case KERN_SUCCESS:
			return true;
		case KERN_ABORTED:
			return false;
		default:
			panic("Failed to lower up-count of duct-taped XNU semaphore: %d", kr);
	}
};
