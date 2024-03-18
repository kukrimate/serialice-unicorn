/*
 * misc.h: Miscellaneous helpers
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <vector>

#define ARRAY_SIZE(x) (sizeof (x) / sizeof *(x))

#define KiB 1024
#define MiB (1024 * 1024)
#define GiB (1024 * 1024 * 1024)

#define NON_COPYABLE(Class) \
	Class(const Class &) = delete; \
	Class &operator=(const Class &) = delete;

#define NON_MOVEABLE(Class) \
	Class(Class &&) = delete; \
	Class &operator=(Class &&) = delete;

__attribute__((noreturn))
__attribute__((format(printf, 1, 2)))
void throw_fmt(const char *fmt, ...);


template<typename Callable>
class Defer {
private:
	NON_COPYABLE(Defer)
	NON_MOVEABLE(Defer)
	Callable m_callable;
public:
	Defer(Callable callable) : m_callable(callable) {}
	~Defer() { m_callable(); }
};

class FileHandle {
private:
	NON_COPYABLE(FileHandle)
	NON_MOVEABLE(FileHandle)

	const char *m_path;
	int m_fd;
public:
	FileHandle(const char *path, int flags);
	~FileHandle();

	size_t read(void *buf, size_t size);
	size_t write(const void *buf, size_t size);
	off_t seek(off_t offset, int whence);

	template<typename... Args>
	int fcntl(int cmd, Args... args)
	{
		auto ret = ::fcntl(m_fd, cmd, args...);
		if (ret < 0)
			throw_fmt("fcntl failed on %s: %s", m_path, strerror(errno));
		return ret;
	}

	template<typename... Args>
	int ioctl(unsigned long request, Args... args)
	{
		auto ret = ::ioctl(m_fd, request, args...);
		if (ret < 0)
			throw_fmt("ioctl failed on %s: %s", m_path, strerror(errno));
		return ret;
	}

	void tcgetattr(struct termios *termios);
	void tcsetattr(int optional_actions, struct termios *termios);
	void tcflush(int queue_selector);
};

std::vector<char> read_file(const char *path);
