#include <darlingserver/memorystatus.hpp>
#include <darlingserver/process.hpp>
#include <darlingserver/logging.hpp>

#include <algorithm>
#include <cerrno>
#include <mutex>
#include <vector>

//
// copied from XNU's bsd/sys/kern_memorystatus.h (xnu-10002.1.13)
//

#define JETSAM_PRIORITY_IDLE_HEAD                -2
#define JETSAM_PRIORITY_IDLE                      0
#define JETSAM_PRIORITY_ELEVATED_INACTIVE        40
#define JETSAM_PRIORITY_MAX                      210
#define JETSAM_PRIORITY_DEFAULT                  180
#define MEMSTAT_BUCKET_COUNT (JETSAM_PRIORITY_MAX + 1)

#define kMemorystatusAssertion        0x40

typedef struct memorystatus_priority_entry {
	pid_t pid;
	int32_t priority;
	uint64_t user_data;
	int32_t limit;  /* MB */
	uint32_t state;
} memorystatus_priority_entry_t;

#define MEMORYSTATUS_BUFFERSIZE_MAX 65536

#define MEMORYSTATUS_CMD_GET_PRIORITY_LIST            1
#define MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES      2
#define MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT          3
#define MEMORYSTATUS_CMD_GET_PRESSURE_STATUS          4
#define MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES      7
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES      8
#define MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE   9
#define MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE  10
#define MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_ENABLE  11
#define MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_DISABLE 12
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_EXCESS          13
#define MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE         14
#define MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE        15
#define MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED       16
#define MEMORYSTATUS_CMD_GET_PROCESS_IS_MANAGED       17
#define MEMORYSTATUS_CMD_GET_AGGRESSIVE_JETSAM_LENIENT_MODE      21
#define MEMORYSTATUS_CMD_GRP_SET_PROPERTIES           100

typedef struct memorystatus_priority_properties {
	int32_t  priority;
	uint64_t user_data;
} memorystatus_priority_properties_t;

#define MEMORYSTATUS_SET_PRIORITY_ASSERTION     0x1

typedef struct memorystatus_memlimit_properties {
	int32_t memlimit_active;                /* jetsam memory limit (in MB) when process is active */
	uint32_t memlimit_active_attr;
	int32_t memlimit_inactive;              /* jetsam memory limit (in MB) when process is inactive */
	uint32_t memlimit_inactive_attr;
} memorystatus_memlimit_properties_t;

typedef struct memorystatus_memlimit_properties2 {
	memorystatus_memlimit_properties_t v1;
	uint32_t memlimit_increase;             /* jetsam memory limit increase (in MB) for active and inactive states */
	uint32_t memlimit_increase_bytes;       /* bytes used to determine the jetsam memory limit increase, for active and inactive states */
} memorystatus_memlimit_properties2_t;

#define MEMORYSTATUS_MEMLIMIT_ATTR_FATAL        0x1     /* if set, exceeding the memlimit is fatal */

//
// end copied from XNU
//

// what XNU's task_convert_phys_footprint_limit(-1) gives without a system-wide task limit (max_task_footprint, which
// macOS doesn't set): (int)(LEDGER_LIMIT_INFINITY >> 20)
#define NO_LIMIT_MB -1

// the only process states this keeps; XNU's memorystatus_build_state() reports the others too, which never apply here
// (suspended, frozen and thawed take a freezer; tracked, idle exit and dirty take dirty tracking)
static uint32_t buildState(const DarlingServer::Memorystatus::State& state) {
	return state.priorityAssertion ? kMemorystatusAssertion : 0;
}

static DarlingServer::Log memorystatusLog("memorystatus");

// XNU's proc_list_lock, for every process's memorystatus state
static std::mutex memorystatusLock;
// the band order the next process to go to a band's tail (or head) gets
static int64_t nextTailOrder = 0;
static int64_t nextHeadOrder = -1;
// guarded by memorystatusLock
static bool aggressiveJetsamLenientAllowed = false;
static bool aggressiveJetsamLenient = false;

DarlingServer::Memorystatus::State::State():
	effectivePriority(JETSAM_PRIORITY_DEFAULT),
	requestedPriority(JETSAM_PRIORITY_DEFAULT)
{
	std::unique_lock lock(memorystatusLock);
	bandOrder = nextTailOrder++;
};

void DarlingServer::Memorystatus::resetForExec(Process& process) {
	// (State() takes the lock itself, for its band order)
	State fresh;
	std::unique_lock lock(memorystatusLock);
	process.memorystatus() = fresh;
};

namespace {
	using DarlingServer::Process;
	using State = DarlingServer::Memorystatus::State;

	// proc_find(): a live process the caller's PID (its namespace's) names; the kernel's isn't one
	std::shared_ptr<Process> findProcess(pid_t pid) {
		if (pid <= 0) {
			return nullptr;
		}
		auto maybeProcess = DarlingServer::processRegistry().lookupEntryByNSID(pid);
		if (!maybeProcess || (*maybeProcess)->isDead()) {
			return nullptr;
		}
		return *maybeProcess;
	};

	// memorystatus_update_priority_locked(), with macOS's aging bands (none) and no dirty tracking
	void updatePriorityLocked(State& state, int priority, bool headInsert) {
		if (state.useElevatedInactiveBand && priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE) {
			priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
		}
		// it goes to its band's tail, or head, even when the band is the one it was in
		state.bandOrder = headInsert ? nextHeadOrder-- : nextTailOrder++;
		state.effectivePriority = priority;
	};

	// the limit a process's memlimit gives: XNU's cached one (p_memstat_memlimit), as the active one or the inactive
	// one applies (proc_jetsam_state_is_active_locked(): in the elevated inactive band with its attribute, or at
	// FOREGROUND or above, without dirty tracking)
	int32_t currentLimitLocked(const State& state) {
		bool active = (state.useElevatedInactiveBand && state.effectivePriority == JETSAM_PRIORITY_ELEVATED_INACTIVE)
			|| state.effectivePriority >= 100 /* JETSAM_PRIORITY_FOREGROUND */;
		int32_t limit = active ? state.memlimitActive : state.memlimitInactive;
		return (limit > 0) ? limit : NO_LIMIT_MB;
	};

	memorystatus_priority_entry_t priorityEntryLocked(const Process& process, const State& state) {
		memorystatus_priority_entry_t entry {};
		entry.pid = process.nsid();
		entry.priority = state.effectivePriority;
		entry.user_data = state.userData;
		entry.limit = currentLimitLocked(state);
		entry.state = buildState(state);
		return entry;
	};

	// P_MEMSTAT_INTERNAL, which XNU gives launchd (pid 1: forkproc()'s memstat_internal, from bsd_init()) and its exec;
	// Darling's launchd stands in for the Mac's, as the simulator's launchd_sim isn't pid 1 either
	bool isInternal(const Process& process) {
		return process.nsid() == 1;
	};

	// memorystatus_cmd_get_priority_list()
	int getPriorityList(Process& caller, pid_t pid, uint64_t buffer, uint64_t bufferSize, int32_t& retval) {
		bool sizeOnly = (buffer == 0);
		size_t listSize;

		if (pid != 0) {
			// memorystatus_get_priority_pid()
			listSize = sizeof(memorystatus_priority_entry_t);
			if (!sizeOnly) {
				if (bufferSize != sizeof(memorystatus_priority_entry_t)) {
					return EINVAL;
				}
				auto process = findProcess(pid);
				if (!process) {
					return ESRCH;
				}
				memorystatus_priority_entry_t entry;
				{
					std::unique_lock lock(memorystatusLock);
					entry = priorityEntryLocked(*process, process->memorystatus());
				}
				if (!caller.writeMemory(buffer, &entry, sizeof(entry))) {
					return EFAULT;
				}
			}
		} else {
			// memorystatus_get_priority_list(): every process, by band, and in each band in order; not an internal one, whose
			// priority isn't tracked (memorystatus_list_add())
			std::vector<std::shared_ptr<Process>> processes;
			for (auto& process: DarlingServer::processRegistry().copyEntries()) {
				if (process->nsid() > 0 && !isInternal(*process) && !process->isDead()) {
					processes.push_back(process);
				}
			}
			listSize = sizeof(memorystatus_priority_entry_t) * processes.size();

			if (!sizeOnly) {
				if (bufferSize < listSize) {
					return EINVAL;
				}

				std::vector<std::pair<int64_t, memorystatus_priority_entry_t>> list;
				{
					std::unique_lock lock(memorystatusLock);
					for (auto& process: processes) {
						const auto& state = process->memorystatus();
						list.emplace_back(state.bandOrder, priorityEntryLocked(*process, state));
					}
				}
				std::sort(list.begin(), list.end(), [](const auto& a, const auto& b) {
					return (a.second.priority != b.second.priority) ? (a.second.priority < b.second.priority) : (a.first < b.first);
				});

				std::vector<memorystatus_priority_entry_t> entries;
				for (auto& [order, entry]: list) {
					entries.push_back(entry);
				}
				if (!caller.writeMemory(buffer, entries.data(), listSize)) {
					return EFAULT;
				}
			}
		}

		retval = (int32_t) listSize;
		return 0;
	};

	// memorystatus_update(), for memorystatus_cmd_set_priority_properties(): the process's (non-memlimit) part
	int update(Process& process, int priority, uint64_t userData, bool isAssertion) {
		bool headInsert = false;

		if (priority == -1) {
			/* Use as shorthand for default priority */
			priority = JETSAM_PRIORITY_DEFAULT;
		} else if (priority == JETSAM_PRIORITY_IDLE_HEAD) {
			/* JETSAM_PRIORITY_IDLE_HEAD inserts at the head of the idle queue */
			priority = JETSAM_PRIORITY_IDLE;
			headInsert = true;
		} else if ((priority < 0) || (priority >= MEMSTAT_BUCKET_COUNT)) {
			/* Sanity check */
			return EINVAL;
		}
		// (macOS's applications aging band is 0, so XNU leaves the bands above idle as they are)

		std::unique_lock lock(memorystatusLock);
		auto& state = process.memorystatus();

		state.userData = userData;

		if (isAssertion) {
			if (priority == JETSAM_PRIORITY_IDLE) {
				/*
				 * Assertions relinquish control when the process is heading to IDLE.
				 */
				if (state.priorityAssertion) {
					state.priorityAssertion = false;
				} else {
					/*
					 * Ignore an idle priority transition if the process is not
					 * already managed by assertions.
					 */
					memorystatusLog.debug() << "Ignoring assertion driven idle priority for " << process.nsid() << ": not previously controlled" << memorystatusLog.endLog;
					return 0;
				}
			} else {
				state.priorityAssertion = true;
			}

			/* Always update the assertion priority in this path */
			state.assertionPriority = priority;
			// (with dirty tracking, XNU would weigh the requested priority in here; Darling has none)
		} else {
			state.requestedPriority = priority;
		}

		updatePriorityLocked(state, priority, headInsert);
		return 0;
	};

	// memorystatus_cmd_set_priority_properties()
	int setPriorityProperties(Process& caller, pid_t pid, uint32_t flags, uint64_t buffer, uint64_t bufferSize) {
		bool isAssertion = false;
		memorystatus_priority_properties_t entry;

		/* Validate inputs */
		if ((pid == 0) || (buffer == 0) || (bufferSize != sizeof(memorystatus_priority_properties_t))) {
			return EINVAL;
		}

		/* Validate flags */
		if (flags != 0) {
			if (flags & ~(MEMORYSTATUS_SET_PRIORITY_ASSERTION)) {
				return EINVAL;
			}
			isAssertion = true;
		}

		if (!caller.readMemory(buffer, &entry, sizeof(entry))) {
			return EFAULT;
		}

		auto process = findProcess(pid);
		if (!process) {
			return ESRCH;
		}

		if (isInternal(*process)) {
			return EPERM;
		}

		return update(*process, entry.priority, entry.user_data, isAssertion);
	};

	// memorystatus_cmd_set_memlimit_properties() and memorystatus_set_memlimit_properties()
	int setMemlimitProperties(Process& caller, pid_t pid, uint64_t buffer, uint64_t bufferSize) {
		memorystatus_memlimit_properties_t entry;

		/* Validate inputs */
		if ((pid == 0) || (buffer == 0) || (bufferSize != sizeof(memorystatus_memlimit_properties_t))) {
			return EINVAL;
		}

		if (!caller.readMemory(buffer, &entry, sizeof(entry))) {
			return EFAULT;
		}

		auto process = findProcess(pid);
		if (!process) {
			return ESRCH;
		}

		/*
		 * Check for valid attribute flags.
		 */
		const uint32_t validAttrs = MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
		if ((entry.memlimit_active_attr & ~validAttrs) != 0 || (entry.memlimit_inactive_attr & ~validAttrs) != 0) {
			return EINVAL;
		}

		bool activeFatal = entry.memlimit_active_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
		bool inactiveFatal = entry.memlimit_inactive_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;

		/*
		 * Setting a limit of <= 0 implies that the process has no
		 * high-water-mark and has no per-task-limit.  That means
		 * the system_wide task limit is in place, which by the way,
		 * is always fatal.
		 */
		// (memorystatus_get_default_task_active_limit() is -1 without the entitlements that raise it)
		if (entry.memlimit_active <= 0) {
			entry.memlimit_active = -1;
			activeFatal = true;
		}
		if (entry.memlimit_inactive <= 0) {
			entry.memlimit_inactive = -1;
			inactiveFatal = true;
		}

		std::unique_lock lock(memorystatusLock);
		auto& state = process->memorystatus();
		state.memlimitActive = entry.memlimit_active;
		state.memlimitActiveFatal = activeFatal;
		state.memlimitInactive = entry.memlimit_inactive;
		state.memlimitInactiveFatal = inactiveFatal;
		// (no limit is enforced)
		return 0;
	};

	// memorystatus_cmd_get_memlimit_properties() and memorystatus_get_memlimit_properties_internal()
	int getMemlimitProperties(Process& caller, pid_t pid, uint64_t buffer, uint64_t bufferSize) {
		memorystatus_memlimit_properties2_t entry {};

		/* Validate inputs */
		if ((pid == 0) || (buffer == 0) ||
		    ((bufferSize != sizeof(memorystatus_memlimit_properties_t)) &&
		    (bufferSize != sizeof(memorystatus_memlimit_properties2_t)))) {
			return EINVAL;
		}

		auto process = findProcess(pid);
		if (!process) {
			return ESRCH;
		}

		{
			std::unique_lock lock(memorystatusLock);
			const auto& state = process->memorystatus();
			entry.v1.memlimit_active = (state.memlimitActive > 0) ? state.memlimitActive : NO_LIMIT_MB;
			entry.v1.memlimit_active_attr = state.memlimitActiveFatal ? MEMORYSTATUS_MEMLIMIT_ATTR_FATAL : 0;
			entry.v1.memlimit_inactive = (state.memlimitInactive > 0) ? state.memlimitInactive : NO_LIMIT_MB;
			entry.v1.memlimit_inactive_attr = state.memlimitInactiveFatal ? MEMORYSTATUS_MEMLIMIT_ATTR_FATAL : 0;
		}

		if (!caller.writeMemory(buffer, &entry, bufferSize)) {
			return EFAULT;
		}
		return 0;
	};

	// memorystatus_cmd_get_memlimit_excess_np(): by how much the process's footprint (here, its resident size)
	// exceeds its inactive limit
	int getMemlimitExcess(Process& caller, pid_t pid, uint32_t flags, uint64_t buffer, uint64_t bufferSize) {
		uint64_t delta = 0;
		int32_t limit;

		/* Validate inputs */
		if ((pid == 0) || (buffer == 0) || (bufferSize != sizeof(uint64_t)) || (flags != 0)) {
			return EINVAL;
		}

		auto process = findProcess(pid);
		if (!process) {
			return ESRCH;
		}

		{
			std::unique_lock lock(memorystatusLock);
			limit = process->memorystatus().memlimitInactive;
		}

		// no limit: XNU's -1 MB, which as bytes (in a uint64_t) no footprint exceeds
		if (limit > 0) {
			uint64_t footprint;
			try {
				footprint = process->memoryInfo().residentSize;
			} catch (const std::system_error&) {
				return ESRCH;
			}
			uint64_t limitBytes = (uint64_t) limit * 1024 * 1024;
			if (footprint > limitBytes) {
				delta = footprint - limitBytes;
			}
		}

		if (!caller.writeMemory(buffer, &delta, sizeof(delta))) {
			return EFAULT;
		}
		return 0;
	};

	// memorystatus_update_inactive_jetsam_priority_band(), with no aging bands
	int updateInactiveBand(pid_t pid, int32_t command, bool effectiveNow) {
		bool enable = (command == MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE);

		auto process = findProcess(pid);
		if (!process) {
			return ESRCH;
		}

		std::unique_lock lock(memorystatusLock);
		auto& state = process->memorystatus();

		if (state.useElevatedInactiveBand == enable) {
			/*
			 * No change in state.
			 */
			return 0;
		}

		state.useElevatedInactiveBand = enable;

		if (effectiveNow) {
			if (enable && state.effectivePriority < JETSAM_PRIORITY_ELEVATED_INACTIVE) {
				updatePriorityLocked(state, JETSAM_PRIORITY_ELEVATED_INACTIVE, false);
			} else if (!enable && state.effectivePriority == JETSAM_PRIORITY_ELEVATED_INACTIVE) {
				updatePriorityLocked(state, JETSAM_PRIORITY_IDLE, false);
			}
		}

		return 0;
	};

	// memorystatus_get_process_is_managed() and memorystatus_set_process_is_managed()
	int processIsManaged(pid_t pid, bool set, bool setManaged, int32_t& retval) {
		/* Validate inputs */
		if (pid == 0) {
			return EINVAL;
		}

		auto process = findProcess(pid);
		if (!process) {
			return ESRCH;
		}

		std::unique_lock lock(memorystatusLock);
		auto& state = process->memorystatus();
		if (set) {
			// (XNU also lets a managed process be frozen; there's no freezer)
			state.managed = setManaged;
		} else {
			retval = state.managed ? 1 : 0;
		}
		return 0;
	};
};

int DarlingServer::Memorystatus::control(Process& caller, int32_t command, pid_t pid, uint32_t flags, uint64_t buffer, uint64_t bufferSize, int32_t& retval) {
	int error = EINVAL;

	// XNU wants root or the memorystatus entitlement for every command but the freezer's (which macOS lacks). Darling
	// doesn't check entitlements, so every caller counts as entitled.

	/*
	 * Sanity check.
	 * Do not enforce it for snapshots.
	 */
	if (command != MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT) {
		if (bufferSize > MEMORYSTATUS_BUFFERSIZE_MAX) {
			return EINVAL;
		}
	}

	switch (command) {
	case MEMORYSTATUS_CMD_GET_PRIORITY_LIST:
		error = getPriorityList(caller, pid, buffer, bufferSize, retval);
		break;
	case MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES:
		error = setPriorityProperties(caller, pid, flags, buffer, bufferSize);
		break;
	case MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES:
		error = setMemlimitProperties(caller, pid, buffer, bufferSize);
		break;
	case MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES:
		error = getMemlimitProperties(caller, pid, buffer, bufferSize);
		break;
	case MEMORYSTATUS_CMD_GET_MEMLIMIT_EXCESS:
		error = getMemlimitExcess(caller, pid, flags, buffer, bufferSize);
		break;
	case MEMORYSTATUS_CMD_GRP_SET_PROPERTIES:
	case MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT:
		// not yet: group priorities and probabilities, and jetsam snapshots, which nothing has asked for. ENOTSUP,
		// not XNU's answers, so a caller that does can tell
		memorystatusLog.warning() << "memorystatus_control(" << command << ") from " << caller.nsid() << " isn't supported yet" << memorystatusLog.endLog;
		error = ENOTSUP;
		break;
	case MEMORYSTATUS_CMD_GET_PRESSURE_STATUS:
		// (XNU wants PRIV_VM_PRESSURE; see above.) Memory pressure is always normal.
		retval = 0;
		error = 0;
		break;
	case MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_ENABLE: {
		std::unique_lock lock(memorystatusLock);
		if (!aggressiveJetsamLenientAllowed) {
			aggressiveJetsamLenientAllowed = true;
			aggressiveJetsamLenient = true;
			error = 0;
		}
	} break;
	case MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_DISABLE: {
		std::unique_lock lock(memorystatusLock);
		aggressiveJetsamLenientAllowed = false;
		aggressiveJetsamLenient = false;
		error = 0;
	} break;
	case MEMORYSTATUS_CMD_GET_AGGRESSIVE_JETSAM_LENIENT_MODE: {
		std::unique_lock lock(memorystatusLock);
		retval = aggressiveJetsamLenient ? 1 : 0;
		error = 0;
	} break;
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE:
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE:
		// memorystatus_low_mem_privileged_listener(): there are no low-memory notifications to be privileged for
		error = 0;
		break;
	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE:
	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE:
		error = updateInactiveBand(pid, command, flags != 0);
		break;
	case MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED:
		// as XNU takes it: flags is a boolean_t that only TRUE (1) sets
		error = processIsManaged(pid, true, flags == 1, retval);
		break;
	case MEMORYSTATUS_CMD_GET_PROCESS_IS_MANAGED:
		error = processIsManaged(pid, false, false, retval);
		break;
	// the jetsam commands (high water marks, task limits, coalition swappability, memlimit conversion) and the
	// freezer's: macOS has neither
	default:
		error = EINVAL;
		break;
	}

	return error;
};
