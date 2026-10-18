/**
 * This file is part of Darling.
 *
 * Copyright (C) 2021 Darling developers
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <darlingserver/process.hpp>
#include <darlingserver/registry.hpp>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/uio.h>
#include <darlingserver/logging.hpp>

#include <fstream>
#include <regex>
#include <utility>

#include <sys/mman.h>
#include <poll.h>

static DarlingServer::Log processLog("process");

DarlingServer::Process::Process(ID id, NSID nsid, Architecture architecture, int pipe):
	_pid(id),
	_nspid(nsid),
	_architecture(architecture)
{
	int pidfd = (pipe >= 0) ? pipe : syscall(SYS_pidfd_open, _pid, 0);
	if (pidfd < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to open pidfd for process");
	}

	_pidfd = std::make_shared<FD>(pidfd);

	// we could use stat instead of status, but it's more complicated with comm potentially getting in the way of parsing (it can include whitespace and parentheses)
	std::ifstream statusFile("/proc/" + std::to_string(id) + "/status");
	std::string line;

	std::shared_ptr<Process> parentProcess = nullptr;

	while (std::getline(statusFile, line)) {
		if (line.substr(0, sizeof("PPid") - 1) == "PPid") {
			auto pos = line.find_last_of('\t');
			std::string id;

			if (pos != line.npos) {
				id = line.substr(pos + 1);
			}

			if (id.empty()) {
				throw std::runtime_error("Failed to parse parent process ID");
			}

			if (auto maybeParentProcess = processRegistry().lookupEntryByID(std::stoi(id))) {
				parentProcess = *maybeParentProcess;
				_parentProcess = parentProcess;
			}

			break;
		}
	}

	if (parentProcess) {
		std::shared_lock parentLock(parentProcess->_rwlock);

		// inherit vchroot from parent process
		_vchrootDescriptor = parentProcess->_vchrootDescriptor;
		_cachedVchrootPath = parentProcess->_cachedVchrootPath;

		// inherit groups from parent process
		_groups = parentProcess->_groups;

		// a fork runs its parent's executable until it execs
		_executablePath = parentProcess->_executablePath;
		_executableUUID = parentProcess->_executableUUID;
	}

	// NOTE: see thread.cpp for why it's okay to use `this` here
	_dtapeTask = dtape_task_create(parentProcess ? parentProcess->_dtapeTask : nullptr, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
	_dtapeForkWaitSemaphore = dtape_semaphore_create(_dtapeTask, 0);

	processLog.info() << "New process created with ID " << _pid << " and NSID " << _nspid;
};

DarlingServer::Process::Process(KernelProcessConstructorTag tag):
	_pid(-1),
	_nspid(0)
{
#if __x86_64__
	_architecture = Architecture::x86_64;
#elif __i386__
	_architecture = Architecture::i386;
#elif __aarch64__
	_architecture = Architecture::ARM64;
#elif __arm__
	_architecture = Architecture::ARM32;
#else
	#error Unknown architecture
#endif
	_dtapeTask = dtape_task_create(nullptr, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
};

DarlingServer::Process::~Process() {
	processLog.info() << *this << ": process being destroyed" << processLog.endLog;
};

DarlingServer::Process::ID DarlingServer::Process::id() const {
	return _pid;
};

DarlingServer::Process::NSID DarlingServer::Process::nsid() const {
	return _nspid;
};

DarlingServer::EternalID DarlingServer::Process::eternalID() const {
	return _eid;
};

void DarlingServer::Process::_setEternalID(EternalID eid) {
	_eid = eid;
};

std::vector<std::shared_ptr<DarlingServer::Thread>> DarlingServer::Process::threads() const {
	std::vector<std::shared_ptr<DarlingServer::Thread>> result;
	std::shared_lock lock(_rwlock);

	for (auto& [nsid, maybeThread]: _threads) {
		if (auto thread = maybeThread.lock()) {
			result.push_back(thread);
		}
	}

	return result;
};

std::string DarlingServer::Process::vchrootPath() const {
	std::shared_lock lock(_rwlock);
	return _cachedVchrootPath;
};

void DarlingServer::Process::setVchrootDirectory(std::shared_ptr<FD> directoryDescriptor) {
	std::unique_lock lock(_rwlock);
	_vchrootDescriptor = directoryDescriptor;

	char* tmp = new char[4096];

	auto fdPath = "/proc/self/fd/" + std::to_string(_vchrootDescriptor->fd());
	auto len = readlink(fdPath.c_str(), tmp, 4095);

	if (len < 0) {
		throw std::system_error(errno, std::generic_category(), "readlink");
	}

	tmp[len] = '\0';

	_cachedVchrootPath = std::string(tmp);
	delete[] tmp;
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::currentProcess() {
	auto thread = Thread::currentThread();
	if (!thread) {
		return nullptr;
	}

	return thread->process();
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::parentProcess() const {
	return _parentProcess.lock();
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::kernelProcess() {
	static std::shared_ptr<Process> process = [&]() {
		auto proc = std::make_shared<Process>(KernelProcessConstructorTag());
		processRegistry().registerEntry(proc, true);
		return proc;
	}();
	return process;
};

bool DarlingServer::Process::startSuspended() const {
	std::shared_lock lock(_rwlock);
	return _startSuspended;
};

void DarlingServer::Process::setStartSuspended(bool startSuspended) {
	std::unique_lock lock(_rwlock);
	_startSuspended = startSuspended;
};

bool DarlingServer::Process::_readOrWriteMemory(bool isWrite, uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const {
	struct iovec local;
	struct iovec remote;
	const auto func = isWrite ? process_vm_writev : process_vm_readv;
	static DarlingServer::Log processMemoryAccessLog("procmem");

	if (isDead()) {
		processMemoryAccessLog.error()
			<< "Failed to "
			<< (isWrite ? "write " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< "): process dead"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = ESRCH;
		}
		return false;
	}

	local.iov_base = localBuffer;
	local.iov_len = length;

	remote.iov_base = (void*)remoteAddress;
	remote.iov_len = length;

	if (func(id(), &local, 1, &remote, 1, 0) < 0) {
		int code = errno;
		processMemoryAccessLog.error()
			<< "Failed to "
			<< (isWrite ? "write " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< "): "
			<< code
			<< " ("
			<< strerror(code)
			<< ")"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = code;
		}
		return false;
	} else {
		processMemoryAccessLog.debug()
			<< "Successfully "
			<< (isWrite ? "wrote " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< ")"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = 0;
		}
		return true;
	}
};

bool DarlingServer::Process::readMemory(uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const {
	return _readOrWriteMemory(false, remoteAddress, localBuffer, length, errorCode);
};

bool DarlingServer::Process::writeMemory(uintptr_t remoteAddress, const void* localBuffer, size_t length, int* errorCode) const {
	// the const_cast is safe; when writing to a process' memory, localBuffer is not modified
	return _readOrWriteMemory(true, remoteAddress, const_cast<void*>(localBuffer), length, errorCode);
};

void DarlingServer::Process::notifyCheckin(const Thread& thread, Architecture architecture, bool isFork) {
	// every new thread checks in (mldr's elfcalls); that is neither an exec nor a new process arriving
	if (thread.nsid() != _nspid) {
		return;
	}

	std::unique_lock lock(_rwlock);

	bool didExec = _pendingReplacement;

	if (didExec) {
		_replaceTaskAfterExec(lock, architecture);
	} else if (isFork && architecture != _architecture) {
		throw std::runtime_error("Impossible: parent process architecture != child process architecture on fork");
	}

	_pendingReplacement = false;

	lock.unlock();

	if (didExec) {
		// notify listeners that we have exec'd (i.e. been replaced)
		_notifyListeningKqchannels(NOTE_EXEC, 0);
	} else if (isFork) {
		// tell the parent process (if we have one) that we've arrived: its fork() returns now, and not before,
		// because our task copied the parent's special ports when we were registered, and the parent may change
		// them as soon as fork() returns (launchd resets its bootstrap port)
		if (auto parent = _parentProcess.lock()) {
			parent->_forkChildArrived(_nspid, _pid);
			parent->_notifyListeningKqchannels(NOTE_FORK, nsid());
		}
	}
};

void DarlingServer::Process::_replaceTaskAfterExec(std::unique_lock<std::shared_mutex>& lock, Architecture architecture) {
	processLog.info() << *this << ": replacing process with a new task (with architecture \"" << architectureToString(architecture) << "\")" << processLog.endLog;

	// clear all threads except the main thread
	std::shared_ptr<Thread> mainThread = nullptr;
	while (!_threads.empty()) {
		auto it = _threads.begin();
		auto thread = it->second.lock();
		lock.unlock();
		if (thread) {
			if (thread->_nstid == _nspid) {
				mainThread = thread;
			} else {
				thread->_process = nullptr;
				thread->notifyDead();
			}
		}
		lock.lock();
		_threads.erase(it);
	}
	if (!mainThread) {
		throw std::runtime_error("Main thread for process died?");
	}
	_threads[mainThread->nsid()] = mainThread;

	// update the process architecture
	_architecture = architecture;

	// a new image: XNU's exec makes a new proc, with memorystatus's state as forkproc() sets it up
	Memorystatus::resetForExec(*this);

	// replace the old task with a new task that inherits from it
	auto oldTask = _dtapeTask;
	auto newTask = dtape_task_create(oldTask, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
	_dtapeTask = newTask;

	// now replace the main thread's duct-taped thread with a new one
	auto oldThread = mainThread->_dtapeThread;
	auto newThread = dtape_thread_create(_dtapeTask, mainThread->_nstid, mainThread.get());
	mainThread->_dtapeThread = newThread;

	// destroy the main thread's old S2C semaphores: taken under the thread's lock, as _s2cPerform() retains them under
	// it, and _scheduleRelease() takes them
	dtape_semaphore_t* oldS2CSemaphores[4];
	{
		std::unique_lock threadLock(mainThread->_rwlock);
		oldS2CSemaphores[0] = std::exchange(mainThread->_s2cPerformSempahore, nullptr);
		oldS2CSemaphores[1] = std::exchange(mainThread->_s2cReplySempahore, nullptr);
		oldS2CSemaphores[2] = std::exchange(mainThread->_s2cInterruptEnterSemaphore, nullptr);
		oldS2CSemaphores[3] = std::exchange(mainThread->_s2cInterruptExitSemaphore, nullptr);
	}
	for (auto semaphore: oldS2CSemaphores) {
		if (semaphore) {
			dtape_semaphore_destroy(semaphore);
		}
	}

	// replace the fork-wait semaphore with one of the new task's (a fork child's arrival raises it)
	auto newForkWaitSemaphore = dtape_semaphore_create(_dtapeTask, 0);
	dtape_semaphore_t* oldForkWaitSemaphore;
	{
		std::unique_lock forkLock(_forkLock);
		oldForkWaitSemaphore = _dtapeForkWaitSemaphore;
		_dtapeForkWaitSemaphore = newForkWaitSemaphore;
	}
	dtape_semaphore_destroy(oldForkWaitSemaphore);

	// release the main thread's old duct-taped thread
	dtape_thread_release(oldThread);

	// release the old task
	dtape_task_release(oldTask);

	// create new S2C semaphores for the main thread
	auto performSemaphore = dtape_semaphore_create(_dtapeTask, 1);
	auto replySemaphore = dtape_semaphore_create(_dtapeTask, 0);
	auto enterSemaphore = dtape_semaphore_create(_dtapeTask, 0);
	auto exitSemaphore = dtape_semaphore_create(_dtapeTask, 0);
	std::unique_lock threadLock(mainThread->_rwlock);
	mainThread->_s2cPerformSempahore = performSemaphore;
	mainThread->_s2cReplySempahore = replySemaphore;
	mainThread->_s2cInterruptEnterSemaphore = enterSemaphore;
	mainThread->_s2cInterruptExitSemaphore = exitSemaphore;
};

void DarlingServer::Process::setPendingReplacement() {
	std::unique_lock lock(_rwlock);

	processLog.info() << "Process " << id() << " (" << nsid() << ") is now pending replacement" << processLog.endLog;

	_pendingReplacement = true;
};

void DarlingServer::Process::registerKqchan(std::shared_ptr<Kqchan> kqchan) {
	std::unique_lock lock(_rwlock);

	_kqchannels[kqchan->_idForProcess()] = kqchan;
};

void DarlingServer::Process::unregisterKqchan(std::shared_ptr<Kqchan> kqchan) {
	std::unique_lock lock(_rwlock);

	_kqchannels.erase(kqchan->_idForProcess());
};

// the ID (the PID in our namespace) of the process a pidfd refers to, or -1 if it is unknown or reaped
static pid_t pidOfPidfd(int pidfd) {
	std::ifstream fdinfo("/proc/self/fdinfo/" + std::to_string(pidfd));
	std::string line;
	while (std::getline(fdinfo, line)) {
		if (line.rfind("Pid:", 0) == 0) {
			try {
				pid_t pid = std::stoi(line.substr(4));
				// 0: in a PID namespace we can't see into
				return (pid > 0) ? pid : -1;
			} catch (...) {
				return -1;
			}
		}
	}
	return -1;
};

static bool pidfdExited(int pidfd) {
	struct pollfd pfd = { pidfd, POLLIN, 0 };
	return poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR));
};

void DarlingServer::Process::_forkChildArrived(NSID child, ID childID) {
	std::unique_lock lock(_forkLock);
	_forkArrivals[child] = childID;
	if (_dtapeForkWaitSemaphore) {
		dtape_semaphore_up(_dtapeForkWaitSemaphore);
	}
};

DarlingServer::Process::ForkWaitResult DarlingServer::Process::waitForChildAfterFork(NSID child, int childPidfd) {
	// how often we look whether a child that hasn't checked in has died; it normally checks in within milliseconds
	static constexpr uint64_t deathPollNs = 100ull * 1000 * 1000;
	// without a pidfd (Linux before 5.3) we can't see the child die: give up after this long rather than hang
	static constexpr int maxPollsWithoutPidfd = 100;

	ID childID = -1;
	if (childPidfd >= 0) {
		childID = pidOfPidfd(childPidfd);
		if (childID < 0 && !pidfdExited(childPidfd)) {
			processLog.warning() << *this << ": fork wait: no PID for the pidfd of child " << child << "; going by its namespace PID" << processLog.endLog;
		}
	}

	// timed-out waits, which are what counts without a pidfd
	for (int polls = 0; ;) {
		dtape_semaphore_t* semaphore;
		bool gone = false;
		{
			std::unique_lock lock(_forkLock);
			auto it = _forkArrivals.find(child);
			if (it != _forkArrivals.end()) {
				// another ID is an earlier process that had this namespace PID and whose arrival no fork() took:
				// a child whose parent died before it checked in (it was then reparented to us)
				bool ours = childID < 0 || it->second == childID;
				_forkArrivals.erase(it);
				if (ours) {
					return ForkWaitResult::Arrived;
				}
			}
			semaphore = _dtapeForkWaitSemaphore;
			if (semaphore) {
				dtape_semaphore_retain(semaphore);
			}
		}

		if (!semaphore) {
			// we are dying
			return ForkWaitResult::ChildGone;
		}

		if (childPidfd >= 0 ? pidfdExited(childPidfd) : polls >= maxPollsWithoutPidfd) {
			if (childPidfd < 0) {
				processLog.warning() << *this << ": fork wait: child " << child << " hasn't checked in after " << (maxPollsWithoutPidfd * deathPollNs / 1000000000ull) << " s; fork() returns" << processLog.endLog;
			}
			gone = true;
		} else {
			// woken by any child's arrival: look again
			switch (dtape_semaphore_down_timed(semaphore, deathPollNs)) {
				case dtape_semaphore_wait_result_ok:
					break;
				case dtape_semaphore_wait_result_timed_out:
					polls++;
					break;
				case dtape_semaphore_wait_result_interrupted:
					// the child's arrival, if any, stays for the retry
					dtape_semaphore_release(semaphore);
					return ForkWaitResult::Interrupted;
				default:
					// the semaphore was destroyed: we are dying or exec'ing
					gone = true;
					break;
			}
		}
		dtape_semaphore_release(semaphore);

		if (gone) {
			// the child may have arrived just before it died
			std::unique_lock lock(_forkLock);
			auto it = _forkArrivals.find(child);
			if (it != _forkArrivals.end() && (childID < 0 || it->second == childID)) {
				_forkArrivals.erase(it);
			}
			return ForkWaitResult::ChildGone;
		}
	}
};

void DarlingServer::Process::registerListeningKqchan(std::shared_ptr<Kqchan::Process> kqchan) {
	std::unique_lock lock(_rwlock);
	uintptr_t id = static_cast<std::shared_ptr<Kqchan>>(kqchan)->_idForProcess();
	_listeningKqchannels[id] = kqchan;
};

void DarlingServer::Process::unregisterListeningKqchan(uintptr_t kqchanID) {
	std::unique_lock lock(_rwlock);
	_listeningKqchannels.erase(kqchanID);
};

void DarlingServer::Process::_notifyListeningKqchannels(uint32_t event, int64_t data) {
	decltype(_listeningKqchannels) listeningKqchannels;

	// we do NOT want to be holding our rwlock when we notify the kqchannels; that can lead to deadlocks
	{
		std::shared_lock lock(_rwlock);
		listeningKqchannels = _listeningKqchannels;
	}

	for (auto& [id, maybeKqchan]: listeningKqchannels) {
		auto kqchan = maybeKqchan.lock();

		if (!kqchan) {
			continue;
		}

		kqchan->_notify(event, data);
	}
};

bool DarlingServer::Process::is64Bit() const {
	return _architecture == Architecture::x86_64 || _architecture == Architecture::ARM64;
};

DarlingServer::Process::Architecture DarlingServer::Process::architecture() const {
	return _architecture;
};

void DarlingServer::Process::logToStream(Log::Stream& stream) const {
	stream << "[P:" << _pid << "(" << _nspid << ")]";
};

DarlingServer::Process::MemoryInfo DarlingServer::Process::memoryInfo() const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryInfo");
	}

	MemoryInfo info;
	std::ifstream file("/proc/" + std::to_string(_pid) + "/statm");

	file >> info.virtualSize >> info.residentSize;

	info.virtualSize *= sysconf(_SC_PAGESIZE);
	info.residentSize *= sysconf(_SC_PAGESIZE);

	// CHECKME: can different processes have different page sizes on Linux?
	info.pageSize = sysconf(_SC_PAGESIZE);

	// TODO
	info.regionCount = 0;

	return info;
};

static const std::regex memoryRegionEntryRegex("([0-9a-fA-F]+)\\-([0-9a-fA-F]+)\\s+((?:r|w|x|p|s|\\-)+)\\s+([0-9a-fA-F]+)\\s+([0-9a-fA-F]+):([0-9a-fA-F]+)\\s+([0-9]+)");

DarlingServer::Process::MemoryRegionInfo DarlingServer::Process::memoryRegionInfo(uintptr_t address) const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryRegionInfo");
	}

	MemoryRegionInfo info;
	std::ifstream file("/proc/" + std::to_string(_pid) + "/maps");
	std::string line;

	uintptr_t endAddress;

	while (std::getline(file, line)) {
		std::smatch match;

		if (!std::regex_search(line, match, memoryRegionEntryRegex)) {
			processLog.warning() << "Encountered malformed `/proc/<pid>/maps` entry? Definitely a bug (on our part)." << processLog.endLog;
			continue;
		}

		info.startAddress = std::stoul(match[1].str(), nullptr, 16);
		endAddress = std::stoul(match[2].str(), nullptr, 16);

		if (endAddress <= address || info.startAddress > address) {
			continue;
		}

		info.pageCount = (endAddress - info.startAddress) / sysconf(_SC_PAGESIZE);

		info.mapOffset = std::stoul(match[4].str(), nullptr, 16);

		auto perms = match[3].str();

		info.protection = 0;

		if (perms.find('r') != std::string::npos) {
			info.protection |= PROT_READ;
		}
		if (perms.find('w') != std::string::npos) {
			info.protection |= PROT_WRITE;
		}
		if (perms.find('x') != std::string::npos) {
			info.protection |= PROT_EXEC;
		}

		info.shared = perms.find('s') != std::string::npos;
		info.device = (std::stoull(match[5].str(), nullptr, 16) << 32) | std::stoull(match[6].str(), nullptr, 16);
		info.inode = std::stoull(match[7].str());

		return info;
	}

	processLog.warning() << *this << ": Address 0x" << std::hex << address << " not found in \"/proc/" << std::dec << _pid << "/maps\"" << processLog.endLog;
	throw std::system_error(EFAULT, std::generic_category());
};

#if DSERVER_EXTENDED_DEBUG

void DarlingServer::Process::_registerName(uint32_t name, uintptr_t pointer) {
	std::unique_lock lock(_rwlock);
	_registeredNames[name] = pointer;
};

void DarlingServer::Process::_unregisterName(uint32_t name) {
	std::unique_lock lock(_rwlock);
	_registeredNames.erase(name);
};

void DarlingServer::Process::_addPortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID) {
	std::unique_lock lock(_rwlock);
	auto& members = _portSetMembers[portSetID];
	members.insert(portID);
};

void DarlingServer::Process::_removePortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID) {
	std::unique_lock lock(_rwlock);
	if (_portSetMembers.find(portSetID) != _portSetMembers.end()) {
		auto& members = _portSetMembers[portSetID];
		members.erase(portID);
		if (members.empty()) {
			_portSetMembers.erase(portSetID);
		}
	}
};

void DarlingServer::Process::_clearPortSet(dtape_port_set_id_t portSetID) {
	std::unique_lock lock(_rwlock);
	_portSetMembers.erase(portSetID);
};

#endif

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::tracerProcess() const {
	std::shared_lock lock(_rwlock);
	return _tracerProcess.lock();
};

bool DarlingServer::Process::setTracerProcess(std::shared_ptr<Process> tracerProcess) {
	std::unique_lock lock(_rwlock);
	if (!_tracerProcess.expired()) {
		return false;
	}
	_tracerProcess = tracerProcess;
	return true;
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Process::_pickS2CThread(void) const {
	if (isDead()) {
		return nullptr;
	}

	// if we're the process for the current thread (i.e. we're the current process), use the current thread
	if (currentProcess().get() == this) {
		return Thread::currentThread();
	}

	// otherwise, pick any thread to perform the call

	std::shared_ptr<Thread> thread = nullptr;

	{
		std::shared_lock lock(_rwlock);
		for (auto& [id, weakThread]: _threads) {
			thread = weakThread.lock();
			// a dead one would never take it
			if (thread && !thread->isDead()) {
				break;
			}
			thread = nullptr;
		}
	}

	return thread;
};

std::string DarlingServer::Process::executablePath() const {
	std::shared_lock lock(_rwlock);
	return _executablePath;
};

std::array<uint8_t, 16> DarlingServer::Process::executableUUID() const {
	std::shared_lock lock(_rwlock);
	return _executableUUID;
};

void DarlingServer::Process::setExecutable(std::string path, const std::array<uint8_t, 16>& uuid) {
	std::unique_lock lock(_rwlock);
	_executablePath = std::move(path);
	_executableUUID = uuid;
};

// Runs `function` with a thread of ours to perform the S2C call. One that dies before it takes the call (it was
// checking out, with darlingserver's signals blocked) fails it with ESRCH, unsent, and another thread is picked:
// _pickS2CThread() skips the dead. 16 tries at most.
template<typename Function>
auto DarlingServer::Process::_performS2C(Function&& function) {
	for (int attempt = 1; ; attempt++) {
		auto thread = _pickS2CThread();
		if (!thread) {
			throw std::system_error(ESRCH, std::generic_category());
		}
		try {
			return function(thread);
		} catch (const std::system_error& e) {
			if (e.code().value() != ESRCH || !thread->isDead() || attempt >= 16) {
				throw;
			}
		}
	}
};

uintptr_t DarlingServer::Process::allocatePages(size_t pageCount, int protection, uintptr_t addressHint, bool fixed, bool overwrite) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->allocatePages(pageCount, protection, addressHint, fixed, overwrite);
	});
};

void DarlingServer::Process::freePages(uintptr_t address, size_t pageCount) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->freePages(address, pageCount);
	});
};

uintptr_t DarlingServer::Process::mapFile(int fd, size_t pageCount, int protection, uintptr_t addressHint, size_t pageOffset, bool fixed, bool overwrite) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->mapFile(fd, pageCount, protection, addressHint, pageOffset, fixed, overwrite);
	});
};

void DarlingServer::Process::changeProtection(uintptr_t address, size_t pageCount, int protection) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->changeProtection(address, pageCount, protection);
	});
};

void DarlingServer::Process::syncMemory(uintptr_t address, size_t size, int sync_flags) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->syncMemory(address, size, sync_flags);
	});
};

static const std::regex memoryRegionEntryAddressRegex("([0-9a-fA-F]+)\\-([0-9a-fA-F]+)");

uintptr_t DarlingServer::Process::getNextRegion(uintptr_t address) const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call getNextRegion");
	}

	std::ifstream file("/proc/" + std::to_string(_pid) + "/maps");
	std::string line;

	while (std::getline(file, line)) {
		std::smatch match;

		if (!std::regex_search(line, match, memoryRegionEntryAddressRegex)) {
			processLog.warning() << "Encountered malformed `/proc/<pid>/maps` entry? Definitely a bug (on our part)." << processLog.endLog;
			continue;
		}

		auto startAddress = std::stoul(match[1].str(), nullptr, 16);
		auto endAddress = std::stoul(match[2].str(), nullptr, 16);

		if (startAddress <= address) {
			continue;
		}

		// /proc/<pid>/maps is sorted in ascending order, so as soon as we find a line with a starting address greater than `address`, that's the next region

		return startAddress;
	}

	return 0;
};

void DarlingServer::Process::notifyDead() {
	decltype(_threads) threads;
	{
		std::unique_lock lock(_rwlock);
		if (_dead) {
			return;
		}

		processLog.info() << *this << ": process dying" << processLog.endLog;
		_dead = true;
		threads = _threads;

		// clear out all kqchannels we own
		_kqchannels.clear();
	}

	// keep ourselves alive until the duct-taped context is done
	_selfReference = shared_from_this();

	// TODO: get exit status
	_notifyListeningKqchannels(NOTE_EXIT, 0);

	// notify all our threads that we're dead
	for (auto [id, maybeThread]: threads) {
		auto thread = maybeThread.lock();
		if (!thread) {
			continue;
		}
		thread->notifyProcessDead();
	}

	// schedule the duct-taped task to be terminated and released
	// these need a microthread context, so we call them within a kernel microthread
	// also destroy the fork-wait semaphore here
	Thread::kernelAsync([self = shared_from_this()]() {
		// its threads are dead: terminate the task's IPC now, as XNU does, rather than with the last reference to it
		dtape_task_dying(self->_dtapeTask);

		{
			std::unique_lock forkLock(self->_forkLock);
			if (self->_dtapeForkWaitSemaphore) {
				dtape_semaphore_destroy(self->_dtapeForkWaitSemaphore);
				self->_dtapeForkWaitSemaphore = nullptr;
			}
		}
		dtape_task_release(self->_dtapeTask);
		self->_dtapeTask = nullptr;

		// That was normally the last reference, and destroying the task disposed of us. A reference left over keeps the
		// task and this process alive for good. The main thread that exited before the process did, as dispatch_main()
		// makes it (launchd_sim and cfprefsd among others), held one until Thread::notifyProcessDead() released it; its
		// release may still be on its way here, and drops its reference when it runs.
		if (self->_selfReference) {
			processLog.warning() << *self << ": task still referenced after the process died: by a dead thread whose release hasn't run yet, or else leaked" << processLog.endLog;
		}
	});

	processRegistry().unregisterEntry(shared_from_this());
};

void DarlingServer::Process::_dispose() {
	_selfReference = nullptr;
};

bool DarlingServer::Process::isDead() const {
	std::shared_lock lock(_rwlock);
	return _dead;
};

std::vector<uint32_t> DarlingServer::Process::groups() const {
	std::shared_lock lock(_rwlock);
	return _groups;
};

DarlingServer::Memorystatus::State& DarlingServer::Process::memorystatus() {
	return _memorystatus;
};

void DarlingServer::Process::setGroups(const std::vector<uint32_t>& groups) {
	std::unique_lock lock(_rwlock);
	_groups = groups;
};
