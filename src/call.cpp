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

#define _GNU_SOURCE 1
#include <darlingserver/call.hpp>
#include <darlingserver/server.hpp>
#include <sys/uio.h>

#include <darlingserver/logging.hpp>
#include <darlingserver/duct-tape.h>
#include <darlingserver/config.hpp>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <darlingserver/kqchan.hpp>
#include <darlingserver/memorystatus.hpp>
#include <algorithm>
#include <cstring>
#include <utility>
#include <rtsig.h>

static DarlingServer::Log callLog("calls");

DarlingServer::Log DarlingServer::Call::rpcReplyLog("replies");

// The largest reply of any call. (The generated DSERVER_RPC_REPLY_MAX_LENGTH nests a max() macro once per call, so its
// expansion doubles with each: the compiler runs out of memory on it.)
static constexpr size_t maxReplySize() {
	size_t max = 0;
	#define CALL_CASE(_callName, _className) max = std::max(max, sizeof(dserver_rpc_reply_ ## _callName ## _t))
	DSERVER_CONSTRUCT_CASES
	#undef CALL_CASE
	return max;
}

std::shared_ptr<DarlingServer::Call> DarlingServer::Call::callFromMessage(Message&& requestMessage) {
	if (requestMessage.data().size() < sizeof(dserver_rpc_callhdr_t)) {
		throw ProtocolError("Message buffer was too small for call header");
	}

	dserver_rpc_callhdr_t* header = reinterpret_cast<dserver_rpc_callhdr_t*>(requestMessage.data().data());
	std::shared_ptr<Call> result = nullptr;
	std::shared_ptr<Process> process = nullptr;
	std::shared_ptr<Thread> thread = nullptr;

	// first, make sure we know this call number, and that the message is large enough for its call, before anything
	// changes for the thread that sent it
	#define CALL_CASE(_callName, _className) \
		case dserver_callnum_ ## _callName: { \
			if (requestMessage.data().size() < sizeof(dserver_rpc_call_ ## _callName ## _t)) { \
				throw ProtocolError("Message buffer was too small for dserver_call_" #_callName "_t", -EINVAL); \
			} \
		} break;

	switch (header->number) {
		case dserver_callnum_s2c:
			break;

		case dserver_callnum_push_reply: {
			if (requestMessage.data().size() < sizeof(dserver_rpc_call_push_reply_t)) {
				throw ProtocolError("Message buffer was too small for dserver_rpc_call_push_reply_t");
			}
			// the reply is allocated and read before it's saved: no larger than any reply
			auto pushReplyCall = reinterpret_cast<const dserver_rpc_call_push_reply_t*>(header);
			if (pushReplyCall->reply_size > maxReplySize()) {
				throw ProtocolError("Pushed reply larger than any reply");
			}
		} break;

		DSERVER_CONSTRUCT_CASES

		default:
			// as XNU's ipc_kobject_server() answers MIG_BAD_ID, and unix_syscall() nosys
			throw ProtocolError("Invalid call number", -ENOSYS);
	}

	#undef CALL_CASE

	if ((header->number & DSERVER_CALL_UNMANAGED_FLAG) == 0) {
		// A push, an S2C reply and an interrupt_exit only make sense from a thread that has made calls before (an
		// interrupt_enter, an S2C call): don't register a process or thread for one. A push from a thread that had
		// checked out registered a Thread nobody would check out, which a later thread of another process with the
		// same TID would have found.
		if (header->number == dserver_callnum_push_reply || header->number == dserver_callnum_s2c || header->number == dserver_callnum_interrupt_exit) {
			auto knownThread = threadRegistry().lookupEntryByNSID(header->tid);
			if (!knownThread || !(*knownThread)->process() || (*knownThread)->process()->nsid() != header->pid) {
				throw ProtocolError("Call from a thread darlingserver doesn't know", -ESRCH);
			}
		}

		// now let's lookup (and possibly create) the process and thread making this call
		process = processRegistry().registerIfAbsent(header->pid, [&]() {
			std::shared_ptr<Process> tmp = nullptr;

			int lifetimePipe = -1;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				if (checkinCall->body.lifetime_listener_pipe != -1) {
					lifetimePipe = requestMessage.extractDescriptorAtIndex(checkinCall->body.lifetime_listener_pipe);
					checkinCall->body.lifetime_listener_pipe = -1;
				}
			}

			try {
				tmp = std::make_shared<Process>(requestMessage.pid(), header->pid, static_cast<Process::Architecture>(header->architecture), lifetimePipe);
			} catch (std::system_error e) {
				return tmp;
			}

			Server::sharedInstance().monitorProcess(tmp);
			return tmp;
		});

		if (!process) {
			throw ProtocolError("Received call from non-existent process?", -ESRCH);
		}

		// before the thread's reply address moves to this message's socket: a message naming another process's
		// thread mustn't redirect that thread's replies. The header's PID is the client's word, so a mismatch is
		// a client's error (or a stale entry, whose calls then fail, loudly); either way, not darlingserver's to die of.
		if (process->id() != requestMessage.pid()) {
			throw ProtocolError("System-reported message PID " + std::to_string(requestMessage.pid()) + " != darlingserver-recorded PID " + std::to_string(process->id()), -ESRCH);
		}

		bool registeredHere = false;
		thread = threadRegistry().registerIfAbsent(header->tid, [&]() {
			std::shared_ptr<Thread> tmp = nullptr;

			void* stackHint = nullptr;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				stackHint = reinterpret_cast<void*>(checkinCall->body.stack_hint);
			}

			try {
				tmp = std::make_shared<Thread>(process, header->tid, stackHint);
			} catch (std::system_error e) {
				return tmp;
			}

			tmp->setAddress(requestMessage.address());
			tmp->registerWithProcess();

			registeredHere = true;
			return tmp;
		});

		if (!thread) {
			throw ProtocolError("Received call from non-existent thread?", -ESRCH);
		}

		// (logged here, not in the factory, which runs with the registry's lock held)
		// Every thread's first call is its checkin: mldr's at process start and thread start, a fork child's. A
		// thread registered by another call is a client bug, most likely a signal handler that ran before the
		// thread had checked in on its own socket, or after it had checked out. Nothing else does it, so it's
		// logged as an error, which the default log level shows.
		if (registeredHere && header->number != dserver_callnum_checkin) {
			const char* name = dserver_callnum_to_string(header->number);
			callLog.error() << "Thread " << header->tid << " of PID " << header->pid << " made call #" << header->number << " (" << (name ? name : "unknown") << ") without checking in first (a signal handler before its checkin or after its checkout?)" << callLog.endLog;
		}

		// A thread darlingserver knows from another process: an entry its thread never removed (it died without its
		// checkout), now found by a thread of this process that Linux gave the same TID.
		if (!registeredHere && thread->process() != process) {
			const char* name = dserver_callnum_to_string(header->number);
			callLog.error() << "Thread " << header->tid << " of PID " << header->pid << " made call #" << header->number << " (" << (name ? name : "unknown") << "), but darlingserver knows that TID from another process: a stale entry" << callLog.endLog;
		}

		thread->setAddress(requestMessage.address());
	}

	auto pidString = (process) ? (std::to_string(process->id()) + " (" + std::to_string(process->nsid()) + ")") : (std::to_string(header->pid) + " (-1)");
	auto tidString = (thread) ? (std::to_string(thread->id()) + " (" + std::to_string(thread->nsid()) + ")") : (std::to_string(header->tid) + " (-1)");
	callLog.debug() << "Received call #" << header->number << " (" << dserver_callnum_to_string(header->number) << ") from PID " << pidString << ", TID " << tidString << callLog.endLog;

	if (header->number == dserver_callnum_s2c) {
		// this is an S2C reply

		// (taken under the lock: a released thread has none, see Thread::_scheduleRelease())
		dtape_semaphore_t* replySemaphore;
		{
			std::unique_lock lock(thread->_rwlock);

			if (thread->_s2cReply) {
				throw ProtocolError("Received S2C reply but thread already had one pending");
			}

			thread->_s2cReply = std::move(requestMessage);
			replySemaphore = thread->_s2cReplySempahore;
			if (replySemaphore) {
				dtape_semaphore_retain(replySemaphore);
			}
		}

		if (replySemaphore) {
			dtape_semaphore_up(replySemaphore);
			dtape_semaphore_release(replySemaphore);
		}

		return nullptr;
	} else if (header->number == dserver_callnum_push_reply) {
		// this is a reply push
		// (used to send interrupted replies back to the server)

		auto pushReplyCall = reinterpret_cast<const dserver_rpc_call_push_reply_t*>(requestMessage.data().data());
		Message replyToSave(pushReplyCall->reply_size, 0);

		// extract the reply-push synchronization pipe
		auto pipeDesc = requestMessage.descriptors().empty() ? -1 : requestMessage.extractDescriptorAtIndex(requestMessage.descriptors().size() - 1);
		char tmp = DSERVER_PUSH_REPLY_SAVED;

		if (pipeDesc < 0) {
			// nothing to wake the client with: it waits for ever, but the others go on
			callLog.error() << *thread << ": Client pushed a reply without a synchronization pipe; dropped it" << callLog.endLog;
			return nullptr;
		}

		// A push the thread's state can't take is the client's mistake (a fork child that ran a signal handler on
		// its parent's socket made them): drop the reply and let the client go on, instead of dying with every
		// other process's calls.
		auto dropPushedReply = [&](const char* why) {
			callLog.error() << *thread << ": Client-pushed reply dropped: " << why << callLog.endLog;
			char dropped = DSERVER_PUSH_REPLY_DROPPED;
			write(pipeDesc, &dropped, sizeof(dropped));
			close(pipeDesc);
			return nullptr;
		};

		if (!process->readMemory(pushReplyCall->reply, replyToSave.data().data(), pushReplyCall->reply_size)) {
			return dropPushedReply("its body couldn't be read");
		}

		replyToSave.replaceDescriptors(requestMessage.descriptors());
		requestMessage.replaceDescriptors({});

		replyToSave.setAddress(requestMessage.address());

		{
			std::unique_lock lock(thread->_rwlock);
			if ((thread->_pendingCall && thread->_pendingCall->number() == Call::Number::InterruptEnter) || !thread->_pendingInterrupts.empty()) {
				// this means the client got interrupted after we had already sent a reply for the interrupted call,
				// the client saw this unexpected reply while waiting for interrupt_enter to respond and sent it back to us,
				// and we received both calls (interrupt_enter and push_reply) at the same time.
				// The interrupt_enter may also still be queued behind the call it interrupted (setPendingCall), which
				// has replied but not yet returned to the top of its microthread.
				if (thread->_pendingSavedReply) {
					// the interrupted call gets the reply that came first
					lock.unlock();
					return dropPushedReply("the pending interrupt already has a saved reply");
				}
				thread->_pendingSavedReply = std::move(replyToSave);
			} else {
				if (thread->_interrupts.empty()) {
					lock.unlock();
					return dropPushedReply("the thread isn't in an interrupt");
				}
				if (thread->_interrupts.top().savedReply) {
					// the interrupted call gets the reply that came first
					lock.unlock();
					return dropPushedReply("the interrupt already has a saved reply");
				}
				thread->_interrupts.top().savedReply = std::move(replyToSave);
			}
		}

		callLog.debug() << *thread << ": Saved client-pushed reply (" << ((thread->_pendingSavedReply) ? "pending" : "normal") << ")" << callLog.endLog;

		// write a byte to the pipe so the caller can continue
		write(pipeDesc, &tmp, sizeof(tmp));
		// and close it
		close(pipeDesc);

		return nullptr;
	}

	// finally, let's construct the call class

	// (its size was checked above)
	#define CALL_CASE(_callName, _className) \
		case dserver_callnum_ ## _callName: { \
			result = std::make_shared<_className>(thread, reinterpret_cast<dserver_rpc_call_ ## _callName ## _t*>(header), std::move(requestMessage)); \
		} break;

	switch (header->number) {
		DSERVER_CONSTRUCT_CASES

		default:
			throw std::invalid_argument("Invalid call number");
	}

	#undef CALL_CASE

	// Thread::_s2cPerform() gives mldr's checkin and thread-exit checkout the S2C signal (mldr's RPC hooks abort on an S2C
	// call); libsystem's, the fork child's checkin and the exec's checkout, serve one inline. Told apart here, as the
	// exec's pipe is gone once the checkout has run.
	if (auto checkin = std::dynamic_pointer_cast<Checkin>(result)) {
		result->_madeByMldr = !checkin->_body.is_fork;
	} else if (auto checkout = std::dynamic_pointer_cast<Checkout>(result)) {
		result->_madeByMldr = checkout->_body.exec_listener_pipe < 0;
	}

	if (thread) {
		if (!thread->setPendingCall(result)) {
			// queued behind the thread's pending call, and scheduled when that one is done: nothing to schedule now
			callLog.debug() << *thread << ": Call queued behind the pending call" << callLog.endLog;
			return nullptr;
		}
		return result;
	} else {
		Thread::kernelAsync([result]() {
			result->processCall();
		});
		return nullptr;
	}
};

std::shared_ptr<DarlingServer::Call> DarlingServer::Call::dispatchMessage(Message&& requestMessage) {
	// what the call is logged with, before callFromMessage takes the message
	dserver_rpc_callhdr_t header = {};
	memcpy(&header, requestMessage.data().data(), std::min(sizeof(header), requestMessage.data().size()));
	pid_t senderPID = requestMessage.pid();
	Address replyAddress = requestMessage.address();
	const char* name = dserver_callnum_to_string(header.number);

	try {
		return callFromMessage(std::move(requestMessage));
	} catch (const ProtocolError& e) {
		// One client's malformed or out-of-order call mustn't take down every process: drop the call and go on.
		callLog.error() << "Dropped call #" << header.number << " (" << (name ? name : "unknown") << ") from PID " << senderPID << " (" << header.pid << "), TID " << header.tid << ": " << e.what() << callLog.endLog;

		// a push dropped before it was looked at still has its pipe: wake the client with it
		if (header.number == dserver_callnum_push_reply && !requestMessage.descriptors().empty()) {
			int pipeDesc = requestMessage.extractDescriptorAtIndex(requestMessage.descriptors().size() - 1);
			if (pipeDesc >= 0) {
				char dropped = DSERVER_PUSH_REPLY_DROPPED;
				write(pipeDesc, &dropped, sizeof(dropped));
				close(pipeDesc);
			}
		}

		// so that the caller doesn't wait for ever: an S2C reply and a push aren't answered with a reply
		if (e.replyCode() != 0 && header.number != dserver_callnum_s2c && header.number != dserver_callnum_push_reply) {
			sendErrorReply(replyAddress, header.number, e.replyCode());
		}
	} catch (const std::exception& e) {
		// darlingserver's own invariant: say so, and end it, as XNU panics
		callLog.error() << "Internal error on call #" << header.number << " (" << (name ? name : "unknown") << ") from PID " << senderPID << " (" << header.pid << "), TID " << header.tid << ": " << e.what() << callLog.endLog;
		throw;
	}
	return nullptr;
};

void DarlingServer::Call::sendErrorReply(Address replyAddress, uint32_t callNumber, int code) {
	Message reply(sizeof(dserver_rpc_replyhdr_t), 0);
	reply.setAddress(replyAddress);
	auto replyHeader = reinterpret_cast<dserver_rpc_replyhdr_t*>(reply.data().data());
	replyHeader->number = static_cast<dserver_callnum_t>(callNumber);
	replyHeader->code = code;
	sendReply(std::move(reply));
};

void DarlingServer::Call::sendErrorReply(int code) {
	sendErrorReply(_replyAddress, _header.number, code);
};

DarlingServer::Call::Call(std::shared_ptr<Thread> thread, Address replyAddress, dserver_rpc_callhdr_t* callHeader):
	_thread(thread),
	_replyAddress(replyAddress),
	_header(*callHeader)
	{};

DarlingServer::Call::~Call() {};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Call::thread() const {
	return _thread.lock();
};

void DarlingServer::Call::sendBasicReply(int resultCode) {
	throw std::runtime_error("This call cannot send a basic reply");
};

void DarlingServer::Call::sendBSDReply(int resultCode, uint32_t returnValue) {
	throw std::runtime_error("This call cannot send a BSD reply");
};

bool DarlingServer::Call::isXNUTrap() const {
	return false;
};

bool DarlingServer::Call::isBSDTrap() const {
	return false;
};

void DarlingServer::Call::sendReply(Message&& reply) {
	Server::sharedInstance().sendMessage(std::move(reply));
};

//
// call processing
//

/*
 *
 * A note about RPC wrappers:
 *
 * The auto-generated RPC wrappers provide both client-side wrappers as well as server-side wrappers.
 * The server-side wrappers automatically handle a few things like replies and descriptors.
 *
 * Replies:
 * The RPC wrappers provide a custom `_sendReply` method specific to each call class.
 * This method takes the result/status code as its first parameter followed by the return parameters
 * specified in the call interface. When a call is done processing, it simply calls `_sendReply` with the necessary
 * parameters and the RPC wrappers will take care of setting up the message and loading it onto the reply queue
 * for the server to send it out.
 *
 * Descriptors:
 * The RPC wrappers automatically handle ownership of descriptors, both incoming and outgoing.
 *
 * Incoming descriptors are extracted from the message and ownership is moved into the call instance.
 * The call processing code can use the descriptor however it likes while the call instance is still alive.
 * If it would like to move ownership out of the call instance, it can set the descriptor in the `_body` to `-1`.
 * Descriptors still left in the `_body` when the call instance is destroyed are automatically closed.
 *
 * Ownership of outgoing descriptors is passed into the reply message. In other words, when a descriptor
 * is given to `_sendReply`, the call instance loses ownership of that descriptor. If the call instance
 * would like to retain ownership, it should `dup()` the descriptor and pass the `dup()`ed descriptor to `_sendReply` instead.
 *
 */

void DarlingServer::Call::Checkin::processCall() {
	// the Call instance creation already took care of registering the process and thread.

	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the process needs to know when its main thread checks in, in case it has a pending replacement,
			// and to tell its parent when the fork is complete
			process->notifyCheckin(*thread, static_cast<Process::Architecture>(_header.architecture), _body.is_fork);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Checkout::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.exec_listener_pipe >= 0) {
				// this is actually an execve;
				// let's monitor the FD we got

				// make it non-blocking
				int flags = fcntl(_body.exec_listener_pipe, F_GETFL);
				if (flags < 0) {
					code = -errno;
				} else {
					flags |= O_NONBLOCK;
					if (fcntl(_body.exec_listener_pipe, F_SETFL, flags) < 0) {
						code = -errno;
					} else {
						// now monitor it
						auto fd = std::make_shared<FD>(_body.exec_listener_pipe);
						_body.exec_listener_pipe = -1; // the FD instance now owns the descriptor

						auto replacingWithDarlingProcess = _body.executing_macho;

						std::weak_ptr<Process> weakProcess = process;
						Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::HangUp, false, true, [fd, weakProcess, replacingWithDarlingProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
							Server::sharedInstance().removeMonitor(monitor);

							auto process = weakProcess.lock();

							if (!process) {
								// the process died...
								return;
							}

							char tmp;
							int result = read(fd->fd(), &tmp, sizeof(tmp));

							if (result < 0) {
								// we shouldn't even get EAGAIN
								throw std::system_error(errno, std::generic_category(), "Failed to read from exec listener pipe");
							}

							if (result == 0) {
								// the execve succeeded
								if (replacingWithDarlingProcess) {
									process->setPendingReplacement();
								} else {
									// the Darling process was replaced with a non-Darling process
									// treat it like death
									process->notifyDead();
								}
							} else {
								// the execve failed
								// do nothing in this case
							}
						}));
					}
				}
			} else {
				thread->notifyDead();

				// if this was the last thread in the process, it'll be automatically unregistered
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	// The call is over: when the thread returns to the top of its microthread, a dead one with no active call is
	// released (doneWorking). Reset below, `_thread` no longer lets the reply deactivate it (pushCallReply()), and a
	// thread that had checked out stayed, with its duct-taped thread (still in its task's thread list) and its
	// stack, for ever.
	// Not the main thread: its Linux thread stays (mldr parks it, as dispatch_main() leaves it), and so does the
	// process, which has no other thread of ours until it starts one; with its last thread gone, darlingserver would
	// take it for dead (~Thread). It is released when the process dies (notifyProcessDead()).
	// The thread held the call's only reference (its active call): `self` keeps it until the reply is sent.
	auto self = shared_from_this();
	if (auto thread = _thread.lock(); thread && thread->activeCall().get() == this && thread->process() && thread->id() != thread->process()->id()) {
		thread->deactivateCall(self);
	}

	// clear the thread pointer so that the reply will be sent directly through the server
	// (otherwise, we would attempt to send it through the thread, which is now dead)
	_thread.reset();

	_sendReply(code);
};

void DarlingServer::Call::VchrootPath::processCall() {
	int code = 0;
	size_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.buffer_size > 0) {
				auto tmpstr = process->vchrootPath().substr(0, _body.buffer_size - 1);
				auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

				fullLength = process->vchrootPath().length();

				if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::TaskSelfTrap::processCall() {
	const auto taskSelfPort = dtape_task_self_trap();
	_sendReply(0, taskSelfPort);
};

void DarlingServer::Call::HostSelfTrap::processCall() {
	const auto hostSelfPort = dtape_host_self_trap();
	_sendReply(0, hostSelfPort);
};

void DarlingServer::Call::ThreadSelfTrap::processCall() {
	const auto threadSelfPort = dtape_thread_self_trap();
	_sendReply(0, threadSelfPort);
};

void DarlingServer::Call::MachReplyPort::processCall() {
	const auto machReplyPort = dtape_mach_reply_port();
	_sendReply(0, machReplyPort);
};

static DarlingServer::Log kprintfLog("kprintf");
// the level kprintf strings are logged at, which kprintf_logged answers for
static constexpr DarlingServer::Log::Type kprintfLevel = DarlingServer::Log::Type::Info;

void DarlingServer::Call::Kprintf::processCall() {
	int code = 0;

	// a client that doesn't ask kprintf_logged (mldr, an older image) pays for the call, not for reading the string
	if (!kprintfLog.willLog(kprintfLevel)) {
		_sendReply(0);
		return;
	}

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			char* tmp = (char*)malloc(_body.string_length + 1);

			if (tmp) {
				if (process->readMemory(_body.string, tmp, _body.string_length, &code)) {
					size_t len = _body.string_length;

					// strip trailing whitespace
					while (len > 0 && isspace(tmp[len - 1])) {
						--len;
					}
					tmp[len] = '\0';

					kprintfLog.stream(kprintfLevel) << tmp << kprintfLog.endLog;
				} else {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				}

				free(tmp);
			} else {
				code = -ENOMEM;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::KprintfLogged::processCall() {
	_sendReply(0, kprintfLog.willLog(kprintfLevel));
};

void DarlingServer::Call::StartedSuspended::processCall() {
	int code = 0;
	bool suspended = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			suspended = process->startSuspended();
			process->setStartSuspended(false);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, suspended);
};

void DarlingServer::Call::GetTracer::processCall() {
	int code = 0;
	int32_t tracer = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (auto tracerProcess = process->tracerProcess()) {
				tracer = tracerProcess->nsid();
			} else {
				// leave `tracer` as 0
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, tracer);
};

void DarlingServer::Call::Uidgid::processCall() {
	int code = 0;
	int uid = -1;
	int gid = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// HACK
			// we shouldn't need to access _dtapeTask; Process should provide a method for this (but it doesn't yet because i'm not sure how to make that API feel at-home in C++)
			dtape_task_uidgid(process->_dtapeTask, _body.new_uid, _body.new_gid, &uid, &gid);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, uid, gid);
};

void DarlingServer::Call::SetThreadHandles::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->setThreadHandles(_body.pthread_handle, _body.dispatch_qaddr);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Vchroot::processCall() {
	int code = 0;

	// TODO: wrap all `processCall` calls in try-catch like this
	try {
		if (auto thread = _thread.lock()) {
			if (auto process = thread->process()) {
				process->setVchrootDirectory(std::make_shared<FD>(_body.directory_fd));
				_body.directory_fd = -1;
			} else {
				code = -ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} catch (std::system_error err) {
		code = -err.code().value();
	} catch (...) {
		code = std::numeric_limits<int>::min();
	}

	_sendReply(code);
};

void DarlingServer::Call::MldrPath::processCall() {
	int code = 0;
	uint64_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto tmpstr = std::string(Config::defaultMldrPath).substr(0, _body.buffer_size - 1);
			auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

			fullLength = process->vchrootPath().length();

			if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
				// writeMemory returns a positive error code, but we want a negative one
				code = -code;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::ThreadGetSpecialReplyPort::processCall() {
	_sendReply(0, dtape_thread_get_special_reply_port());
};

void DarlingServer::Call::MkTimerCreate::processCall() {
	_sendReply(0, dtape_mk_timer_create());
};

void DarlingServer::Call::PthreadKill::processCall() {
	int code = 0;

	if (auto targetThread = Thread::threadForPort(_body.thread_port)) {
		try {
			targetThread->sendSignal(_body.signal);
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadCanceled::processCall() {
	int code = 0;

	// unused: since cancel-xnu, libsystem_kernel answers pthread_canceled from the thread's own flags
	// (bsdthread/cancelable.h), and it always ships with this server
	callLog.warning() << "TODO: " << __PRETTY_FUNCTION__ << callLog.endLog;
	code = -ENOSYS;

	_sendReply(code);
};

void DarlingServer::Call::PthreadMarkcancel::processCall() {
	int code = 0;

	// XNU's __pthread_markcancel (bsd/kern/kern_sig.c 992-1022) takes a thread of the caller's own task only
	// (PORT_TO_THREAD_IN_CURRENT_TASK). The marking itself is the target's: its flags are in its own memory, so the
	// signal's handler there sets them and interrupts the cancelable syscall it may be blocked in (libsystem_kernel's
	// sigexc.h, SIGNAL_PTHREAD_CANCEL: LINUX_SIGRTMIN + 2, after Darling's SUSPEND and S2C).
	auto targetThread = Thread::threadForPort(_body.thread_port);
	auto thread = _thread.lock();
	if (!targetThread || !thread || !thread->process() || targetThread->process() != thread->process()) {
		code = -ESRCH;
	} else {
		static_assert(LINUX_SIGRTMIN + 2 <= LINUX_SIGRTMAX, "a real-time signal of its own");
		try {
			targetThread->sendSignal(LINUX_SIGRTMIN + 2);
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	}

	_sendReply(code);
};

void DarlingServer::Call::KqchanMachPortOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::MachPort>(process, _body.port_name, _body.receive_buffer, _body.receive_buffer_size, _body.saved_filter_flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the port
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::KqchanProcOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::Process>(process, _body.pid, _body.flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the process
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::ForkWaitForChild::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			switch (process->waitForChildAfterFork(_body.child, _body.child_pidfd)) {
				case Process::ForkWaitResult::Arrived:
					break;
				case Process::ForkWaitResult::ChildGone:
					code = -ESRCH;
					break;
				case Process::ForkWaitResult::Interrupted:
					// the client waits again; the child's arrival is kept until then
					code = -EINTR;
					break;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Sigprocess::processCall() {
	int code = 0;
	int newBSDSignal = 0;

	if (auto thread = _thread.lock()) {
		try {
			thread->processSignal(_body.bsd_signal_number, _body.linux_signal_number, _body.code, _body.signal_address, _body.thread_state, _body.float_state);
			newBSDSignal = thread->pendingSignal();
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, newBSDSignal);
};

void DarlingServer::Call::TaskIs64Bit::processCall() {
	int code = 0;
	bool is64Bit = false;

	if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.id)) {
		auto targetProcess = *maybeTargetProcess;
		is64Bit = targetProcess->is64Bit();
	} else {
		code = -ESRCH;
	}

	_sendReply(code, is64Bit);
};

void DarlingServer::Call::ProcIdentity::processCall() {
	int code = 0;
	uint64_t uniqueID = 0;
	uint64_t parentUniqueID = 0;
	uint32_t pidversion = 0;
	uint64_t uuid[2] = { 0, 0 };

	if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.pid)) {
		auto targetProcess = *maybeTargetProcess;
		// HACK: like Uidgid, this reaches into the process's task
		dtape_task_identity(targetProcess->_dtapeTask, &uniqueID, &parentUniqueID, &pidversion);
		auto executableUUID = targetProcess->executableUUID();
		memcpy(uuid, executableUUID.data(), sizeof(uuid));
	} else {
		code = -ESRCH;
	}

	_sendReply(code, uniqueID, parentUniqueID, pidversion, uuid[0], uuid[1]);
};

void DarlingServer::Call::FileportMakeport::processCall() {
	int code = 0;
	uint32_t portName = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the fileport owns the descriptor now
			code = dtape_fileport_makeport(process->_dtapeTask, _body.fd, &portName);
			_body.fd = -1;
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portName);
};

void DarlingServer::Call::FileportMakefd::processCall() {
	int code = 0;
	int fd = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			fd = dtape_fileport_makefd(process->_dtapeTask, _body.port_name);
			if (fd < 0) {
				code = fd;
				fd = -1;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	// the reply takes the descriptor
	_sendReply(code, fd);
};

void DarlingServer::Call::SpawnSetSpecialPort::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			code = dtape_task_set_special_port_for_spawn(process->_dtapeTask, _body.which, _body.port_name);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::InterruptEnter::processCall() {
	Thread::_handleInterruptEnterForCurrentThread();

	_sendReply(0);
};

void DarlingServer::Call::InterruptExit::processCall() {
	auto thread = _thread.lock();

	{
		std::shared_lock lock(thread->_rwlock);
		if (thread->_interrupts.empty()) {
			// an interrupt_exit without its interrupt_enter: there's no interrupt, nor a saved user state, to pop
			lock.unlock();
			callLog.error() << *thread << ": interrupt_exit without an interrupt" << callLog.endLog;
			_sendReply(-EINVAL);
			return;
		}
	}

	dtape_thread_sigexc_exit(thread->_dtapeThread);

	_sendReply(0);

	{
		std::unique_lock lock(thread->_rwlock);

		auto tmp = std::move(thread->_interrupts.top());

		thread->_interrupts.pop();

		if (tmp.savedReply) {
			callLog.debug() << *thread << ": Going to send saved reply" << callLog.endLog;
			Server::sharedInstance().sendMessage(std::move(*tmp.savedReply));
			tmp.savedReply = std::nullopt;
		}
	}
};

void DarlingServer::Call::ConsoleOpen::processCall() {
	static Log consoleLog("console");

	int code = 0;
	int sockets[2] = { -1, -1 };

	// we don't really need bidirectional communication, so a pipe would suffice,
	// except that when you set O_NONBLOCK on one side of a pipe, it is set for both.

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
		int err = errno;
		callLog.warning() << __PRETTY_FUNCTION__ << ": socketpair failed with " << err << callLog.endLog;

		// just report EMFILE for the peer
		code = EMFILE;
	} else {
		// make our side non-blocking
		int flags = fcntl(sockets[0], F_GETFL);
		if (flags < 0) {
			code = -errno;
		} else {
			flags |= O_NONBLOCK;
			if (fcntl(sockets[0], F_SETFL, flags) < 0) {
				code = -errno;
			} else {
				// now monitor it
				auto fd = std::make_shared<FD>(sockets[0]);
				std::weak_ptr<Process> weakProcess;

				if (auto thread = _thread.lock()) {
					if (auto process = thread->process()) {
						weakProcess = process;
					}
				}

				Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::Readable | Monitor::Event::HangUp, false, false, [fd, weakProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
					auto proc = weakProcess.lock();

					if (!proc || static_cast<uint64_t>(events & Monitor::Event::HangUp) != 0) {
						Server::sharedInstance().removeMonitor(monitor);
						return;
					}

					if (static_cast<uint64_t>(events & Monitor::Event::Readable) != 0) {
						std::stringstream data;
						while (true) {
							char buf[128];
							auto count = read(fd->fd(), buf, sizeof(buf) - 1);
							if (count <= 0) {
								break;
							}
							buf[count] = '\0';
							data << buf;
						}
						consoleLog.info() << *proc << ": " << data.rdbuf();
					}
				}));
			}
		}
	}

	if (code != 0) {
		if (sockets[0] >= 0) {
			close(sockets[0]);
			sockets[0] = -1;
		}
		if (sockets[1] >= 0) {
			close(sockets[1]);
			sockets[1] = -1;
		}
	}
	_sendReply(code, sockets[1]);
};

void DarlingServer::Call::SetDyldInfo::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			dtape_task_set_dyld_info(process->_dtapeTask, _body.address, _body.length);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::StopAfterExec::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->setStartSuspended(true);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetTracer::processCall() {
	int code = 0;
	std::shared_ptr<Process> targetProcess = nullptr;
	std::shared_ptr<Process> tracerProcess = nullptr;

	if (_body.target == 0) {
		if (auto thread = _thread.lock()) {
			targetProcess = thread->process();
		}
	} else {
		if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.target)) {
			targetProcess = *maybeTargetProcess;
		}
	}

	if (targetProcess) {
		if (_body.tracer == 0) {
			// leave tracer process as nullptr
		} else {
			if (auto maybeTracerProcess = processRegistry().lookupEntryByNSID(_body.tracer)) {
				tracerProcess = *maybeTracerProcess;
			} else {
				// intentionally not negated because this is not an internal error;
				// this is a perfectly valid case
				code = ESRCH;
			}
		}

		if (code == 0) {
			if (!targetProcess->setTracerProcess(tracerProcess)) {
				// again, not negated because this isn't an internal error;
				// simply indicates there was already a tracer set for the target
				code = EPERM;
			}
		}
	} else {
		// ditto from before
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::TidForThread::processCall() {
	int code = 0;
	int32_t tid = 0;

	if (auto thread = Thread::threadForPort(_body.thread)) {
		tid = thread->nsid();
	} else {
		// might be user error (e.g. invalid port number or dead thread), so don't negate it
		code = ESRCH;
	}

	_sendReply(code, tid);
};

void DarlingServer::Call::PtraceSigexc::processCall() {
	int code = 0;

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.target)) {
		auto process = *maybeProcess;

		dtape_task_set_sigexc_enabled(process->_dtapeTask, _body.enabled);
		dtape_task_try_resume(process->_dtapeTask);
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PtraceThupdate::processCall() {
	int code = 0;

	if (auto maybeThread = threadRegistry().lookupEntryByNSID(_body.target)) {
		auto thread = *maybeThread;

		thread->setPendingSignal(_body.signum);
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::ThreadSuspended::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->waitWhileUserSuspended(_body.thread_state, _body.float_state);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::S2CPerform::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		// The request this green light answers (Thread::_s2cPerform()), taken with the two semaphores under the lock,
		// and the semaphores retained: notifyDead() and the release destroy them. With no request, the signal is stale
		// (its caller stopped waiting, or an exec voided it): nothing waits for this green light, so it's answered at
		// once. (Not an error: sigrt_handler aborts on one.)
		dtape_semaphore_t* enterSemaphore = nullptr;
		dtape_semaphore_t* exitSemaphore = nullptr;
		{
			std::unique_lock lock(thread->_rwlock);
			if (thread->_s2cRequest != 0 && thread->_s2cInterruptEnterSemaphore && thread->_s2cInterruptExitSemaphore) {
				thread->_s2cTaken = std::exchange(thread->_s2cRequest, 0);
				enterSemaphore = thread->_s2cInterruptEnterSemaphore;
				exitSemaphore = thread->_s2cInterruptExitSemaphore;
				dtape_semaphore_retain(enterSemaphore);
				dtape_semaphore_retain(exitSemaphore);
			}
		}
		if (enterSemaphore) {
			dtape_semaphore_up(enterSemaphore);
			dtape_semaphore_down_simple(exitSemaphore);
			dtape_semaphore_release(enterSemaphore);
			dtape_semaphore_release(exitSemaphore);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetExecutablePath::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::string tmpstr;
			tmpstr.resize(_body.buffer_size);
			if (!process->readMemory((uintptr_t)_body.buffer, tmpstr.data(), _body.buffer_size, &code)) {
				code = -code;
			} else {
				std::array<uint8_t, 16> uuid;
				memcpy(uuid.data(), &_body.uuid_low, sizeof(_body.uuid_low));
				memcpy(uuid.data() + sizeof(_body.uuid_low), &_body.uuid_high, sizeof(_body.uuid_high));
				process->setExecutable(tmpstr.c_str(), uuid);
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
}

void DarlingServer::Call::GetExecutablePath::processCall() {
	int code = 0;
	uint64_t fullLength;

	if (auto callingThread = _thread.lock()) {
		if (auto callingProcess = callingThread->process()) {
			if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.pid)) {
				auto targetProcess = *maybeTargetProcess;
				auto path = targetProcess->executablePath();
				auto len = std::min(path.length() + 1, _body.buffer_size);
				if (!callingProcess->writeMemory((uintptr_t)_body.buffer, path.c_str(), len, &code)) {
					code = -code;
				}
				fullLength = path.length();
			} else {
				// not negated because this is an acceptable case.
				// e.g. the target process may have died before the call was processed.
				code = ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
}

void DarlingServer::Call::Groups::processCall() {
	int code = 0;
	std::vector<uint32_t> oldGroups;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			oldGroups = process->groups();

			if (_body.new_groups != 0 && _body.new_group_count > 0) {
				std::vector<uint32_t> newGroups;
				newGroups.resize(_body.new_group_count);

				if (!process->readMemory((uintptr_t)_body.new_groups, newGroups.data(), newGroups.size() * sizeof(uint32_t), &code)) {
					code = -code;
				} else {
					process->setGroups(newGroups);
				}
			}

			if (code == 0 && _body.old_groups != 0 && _body.old_group_space > 0) {
				auto len = std::min(oldGroups.size(), _body.old_group_space) * sizeof(uint32_t);
				if (!process->writeMemory((uintptr_t)_body.old_groups, oldGroups.data(), len, &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, oldGroups.size());
};

void DarlingServer::Call::MemorystatusControl::processCall() {
	int code = 0;
	int32_t retval = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// a Linux errno, which the client converts, as every call's
			code = -Memorystatus::control(*process, _body.command, _body.pid, _body.flags, _body.buffer, _body.buffer_size, retval);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, retval);
};

void DarlingServer::Call::DebugListProcesses::processCall() {
	int code = 0;
	auto processes = processRegistry().copyEntries();
	int pipes[2] = {-1, -1};

	code = pipe(pipes);
	if (code == 0) {
		for (const auto& process: processes) {
			dserver_debug_process_t debugProcess;
			debugProcess.pid = process->nsid();
			debugProcess.port_count = dtape_debug_task_port_count(process->_dtapeTask);
			write(pipes[1], &debugProcess, sizeof(debugProcess));
		}

		close(pipes[1]);
	}

	_sendReply(code, processes.size(), pipes[0]);
};

void DarlingServer::Call::DebugListPorts::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_task_list_ports(process->_dtapeTask, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMembers::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_portset_list_members(process->_dtapeTask, _body.portset, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMessages::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_port_list_messages(process->_dtapeTask, _body.port, [](void* context, const dtape_debug_message_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_message_t debugMessage;

				debugMessage.sender = port->sender;
				debugMessage.size = port->size;

				write(writeFD, &debugMessage, sizeof(debugMessage));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

DSERVER_CLASS_SOURCE_DEFS;
