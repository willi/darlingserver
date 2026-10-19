#ifndef _DARLINGSERVER_MEMORYSTATUS_HPP_
#define _DARLINGSERVER_MEMORYSTATUS_HPP_

#include <cstdint>
#include <sys/types.h>

namespace DarlingServer {
	class Process;

	/**
	 * memorystatus_control(), as macOS's XNU (bsd/kern/kern_memorystatus.c) answers it: CONFIG_MEMORYSTATUS without
	 * CONFIG_JETSAM or CONFIG_FREEZE, the configuration a simulator runs on. It keeps what a process's jetsam priority,
	 * user data, memory limits and flags are set to, so they read back, and nothing acts on them: there's no jetsam,
	 * and the limits aren't enforced. Memory pressure is always normal.
	 */
	namespace Memorystatus {
		/**
		 * A process's state: what XNU keeps in its proc (p_memstat_*), as forkproc() sets it up. Guarded by the
		 * memorystatus lock (see memorystatus.cpp), as XNU's by proc_list_lock.
		 */
		struct State {
			int32_t effectivePriority;
			int32_t requestedPriority;
			int32_t assertionPriority = 0;
			uint64_t userData = 0;
			// MB; 0 or -1 for none
			int32_t memlimitActive = 0;
			int32_t memlimitInactive = 0;
			bool memlimitActiveFatal = false;
			bool memlimitInactiveFatal = false;
			bool managed = false;
			bool priorityAssertion = false;
			bool useElevatedInactiveBand = false;
			// the process's place in its priority band (XNU's bucket lists): bands list their processes in the order
			// they came in, the ones that went to the head first
			int64_t bandOrder;

			State();
		};

		/**
		 * `caller` called memorystatus_control(command, pid, flags, buffer, bufferSize). Returns 0 or an errno (Linux's,
		 * which the client converts), and sets `retval` to what the syscall returns on success.
		 */
		int control(Process& caller, int32_t command, pid_t pid, uint32_t flags, uint64_t buffer, uint64_t bufferSize, int32_t& retval);

		/**
		 * `process` has exec'd: its state starts again, as XNU's exec makes a new proc (cloneproc(), whose forkproc()
		 * sets up every p_memstat_* field) and puts it at its band's tail.
		 */
		void resetForExec(Process& process);
	};
};

#endif // _DARLINGSERVER_MEMORYSTATUS_HPP_
