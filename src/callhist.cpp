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

#include <darlingserver/callhist.hpp>

#if DSERVER_CALL_HIST
#include <darlingserver/rpc.h>
#include <darlingserver/logging.hpp>
#include <filesystem>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

// The counts are cumulative from darlingserver's start, so two dumps (say at launchd up and at home) can be diffed by
// phase. A counter per call number (without the unmanaged flag; the numbers are small and dense), one each for an S2C reply
// and a push_reply, and one per event. A message is counted once its number is valid, so calls rejected later (an
// unknown thread, say) are counted too. The handler only reads lock-free atomics and makes async-signal-safe calls.
namespace {
	constexpr size_t callSlots = 1024;
	constexpr size_t eventCount = static_cast<size_t>(DarlingServer::CallHist::Event::Count);
	std::atomic<uint64_t> callHist[callSlots + 2];
	std::atomic<uint64_t> eventHist[eventCount];
	const char* const eventNames[eventCount] = {
		"event:epoll_wakeup",
		"event:work_item",
		"event:timer_fired",
		"event:kqchan_message",
	};
	char histPath[4096];
	char histTmpPath[4096 + 8];
	// one dump at a time (a second SIGUSR2 may land on another thread)
	std::atomic<bool> histDumping{false};

	size_t histSlot(uint32_t number) {
		if (number == dserver_callnum_s2c) {
			return callSlots;
		} else if (number == dserver_callnum_push_reply) {
			return callSlots + 1;
		}
		uint32_t index = number & ~DSERVER_CALL_UNMANAGED_FLAG;
		return (index < callSlots) ? index : 0;
	}

	void histWrite(int fd, const char* s) {
		write(fd, s, strlen(s));
	}

	void histWriteNumber(int fd, uint64_t value) {
		char buf[24];
		size_t i = sizeof(buf);
		do {
			buf[--i] = '0' + (value % 10);
			value /= 10;
		} while (value != 0);
		write(fd, buf + i, sizeof(buf) - i);
	}

	void histLine(int fd, uint64_t count, const char* number, uint64_t value, const char* name) {
		histWriteNumber(fd, count);
		histWrite(fd, " ");
		if (number) {
			histWrite(fd, number);
		} else {
			histWriteNumber(fd, value);
		}
		histWrite(fd, " ");
		histWrite(fd, name);
		histWrite(fd, "\n");
	}

	// written to a temporary file and renamed into place, so a reader never sees a partial dump
	void histDump(int) {
		if (histDumping.exchange(true)) {
			return;
		}
		int savedErrno = errno;
		int fd = open(histTmpPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
		if (fd >= 0) {
			for (size_t i = 0; i < callSlots + 2; ++i) {
				uint64_t count = callHist[i].load(std::memory_order_relaxed);
				if (count == 0) {
					continue;
				}
				uint32_t number = (i == callSlots) ? dserver_callnum_s2c : (i == callSlots + 1) ? dserver_callnum_push_reply : i;
				// slot 0: a number past the table (none today: the calls are numbered densely from 1)
				const char* name = (i == 0) ? "(out of range)" : dserver_callnum_to_string(static_cast<dserver_callnum_t>(number));
				if (!name && i < callSlots) {
					// an unmanaged call is named under its number with the flag (the slot has it masked off)
					number |= DSERVER_CALL_UNMANAGED_FLAG;
					name = dserver_callnum_to_string(static_cast<dserver_callnum_t>(number));
				}
				histLine(fd, count, nullptr, number, name ? name : "(unnamed)");
			}
			for (size_t i = 0; i < eventCount; ++i) {
				uint64_t count = eventHist[i].load(std::memory_order_relaxed);
				if (count != 0) {
					histLine(fd, count, "-", 0, eventNames[i]);
				}
			}
			close(fd);
			rename(histTmpPath, histPath);
		}
		errno = savedErrno;
		histDumping.store(false);
	}
};

void DarlingServer::CallHist::countCall(uint32_t number) {
	callHist[histSlot(number)].fetch_add(1, std::memory_order_relaxed);
};

void DarlingServer::CallHist::countEvent(Event event) {
	eventHist[static_cast<size_t>(event)].fetch_add(1, std::memory_order_relaxed);
};

void DarlingServer::CallHist::installDump(const std::string& prefix) {
	static DarlingServer::Log histLog("callhist");
	std::error_code error;
	std::filesystem::create_directories(prefix + "/private/var/log", error);
	int n = snprintf(histPath, sizeof(histPath), "%s/private/var/log/dserver-callhist.txt", prefix.c_str());
	if (n < 0 || static_cast<size_t>(n) >= sizeof(histPath)) {
		histLog.error() << "prefix path too long for the call histogram; SIGUSR2 left at its default" << histLog.endLog;
		return;
	}
	snprintf(histTmpPath, sizeof(histTmpPath), "%s.tmp", histPath);
	struct sigaction action {};
	action.sa_handler = histDump;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	sigaction(SIGUSR2, &action, NULL);
};
#endif
