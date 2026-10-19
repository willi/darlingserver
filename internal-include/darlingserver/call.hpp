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

#ifndef _DARLINGSERVER_CALL_HPP_
#define _DARLINGSERVER_CALL_HPP_

#include <darlingserver/rpc.h>
#include <darlingserver/rpc.internal.h>

#include <darlingserver/message.hpp>
#include <darlingserver/registry.hpp>
#include <darlingserver/logging.hpp>

#include <memory>
#include <stdexcept>

#include <unistd.h>

namespace DarlingServer {
	class CallWithReply;

	// A client's call that breaks darlingserver's protocol: an unknown call number, a malformed message, a call its
	// thread's state can't take. It costs only that call (and, when the caller waits for one, an error reply);
	// darlingserver's own broken invariants are other exceptions, and still end darlingserver.
	class ProtocolError: public std::runtime_error {
	public:
		// replyCode: what the caller is answered with (a negative errno), or 0 for no answer
		ProtocolError(const std::string& what, int replyCode = 0):
			std::runtime_error(what),
			_replyCode(replyCode)
			{};

		int replyCode() const {
			return _replyCode;
		};

	private:
		int _replyCode;
	};

	class Call {
	public:
		enum class Number: unsigned int {
			Invalid = dserver_callnum_invalid,
			DSERVER_ENUM_VALUES
		};

		static inline const char* callNumberToString(Number number) {
			return dserver_callnum_to_string(static_cast<dserver_callnum_t>(number));
		};

	protected:
		std::weak_ptr<Thread> _thread;
		Address _replyAddress;
		dserver_rpc_callhdr_t _header;
		// mldr's checkin or thread-exit checkout, not libsystem's (the fork child's checkin, the exec's checkout): set by
		// callFromMessage()
		bool _madeByMldr = false;

		static DarlingServer::Log rpcReplyLog;

		static void sendReply(Message&& reply);

	public:
		Call(std::shared_ptr<Thread> thread, Address replyAddress, dserver_rpc_callhdr_t* callHeader);
		virtual ~Call();

		// A call for the server loop to schedule its thread for, or null when there's nothing to schedule: a call with no
		// thread, dispatched with kernelAsync(); a push_reply, consumed here; or a call queued behind its thread's pending
		// one (an InterruptEnter, which doneWorking schedules).
		static std::shared_ptr<Call> callFromMessage(Message&& requestMessage);

		// callFromMessage for the main loop: a call that breaks the protocol is logged and dropped
		static std::shared_ptr<Call> dispatchMessage(Message&& requestMessage);

		// answers a call with only a reply header: its number and `code`, a negative errno. The client's wrapper
		// returns that code.
		static void sendErrorReply(Address replyAddress, uint32_t callNumber, int code);
		// the same, for a call that will never be processed
		void sendErrorReply(int code);

		virtual Number number() const = 0;
		bool madeByMldr() const { return _madeByMldr; };
		std::shared_ptr<Thread> thread() const;

		virtual void processCall() = 0;

		virtual void sendBasicReply(int resultCode);
		// FIXME: this should actually be in a "BSD" subclass with BSD traps inheriting from it
		virtual void sendBSDReply(int resultCode, uint32_t returnValue);

		virtual bool isXNUTrap() const;
		virtual bool isBSDTrap() const;

		DSERVER_CLASS_DECLS;
	};

	DSERVER_CLASS_DEFS;
};

#endif // _DARLINGSERVER_CALL_HPP_
