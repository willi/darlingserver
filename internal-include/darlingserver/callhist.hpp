/**
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Darling developers
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

#ifndef _DARLINGSERVER_CALLHIST_HPP_
#define _DARLINGSERVER_CALLHIST_HPP_

#include <cstdint>
#include <string>

// DSERVER_CALL_HIST: what darlingserver did since it started, counted, for a boot's wakeups. Each received call by
// number, and the other things that wake its threads, as events. SIGUSR2 writes the counts to
// <prefix>/private/var/log/dserver-callhist.txt. Without the option every function here is empty, and SIGUSR2 keeps its
// default action, which ends darlingserver.
namespace DarlingServer::CallHist {
	enum class Event: unsigned int {
		EpollWakeup,     // epoll_wait() returned with events (the epoll thread woke)
		WorkItem,        // the worker ran a scheduled thread's doWork() (a worker wakeup when its queue was empty)
		TimerFired,      // the timerfd expired (a timer callout microthread)
		KqchanMessage,   // a kqchan (Mach port or process) message received, on its own socket
		Count,
	};

#if DSERVER_CALL_HIST
	void countCall(uint32_t number);
	void countEvent(Event event);
	void installDump(const std::string& prefix);
#else
	inline void countCall(uint32_t) {};
	inline void countEvent(Event) {};
	inline void installDump(const std::string&) {};
#endif
};

#endif // _DARLINGSERVER_CALLHIST_HPP_
