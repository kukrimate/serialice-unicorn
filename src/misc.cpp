/*
 * misc.h: Miscellaneous helpers
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>

#include "misc.h"

void throw_fmt(const char *fmt, ...)
{
	char *s = NULL;
	va_list ap;
	va_start(ap, fmt);
	vasprintf(&s, fmt, ap);
	va_end(ap);
	Defer _free_s([&] { free(s); });
	throw std::runtime_error(s);
}

FileHandle::FileHandle(const char *path, int flags)
{
	m_path = path;
	m_fd = open(path, flags);
	if (m_fd < 0)
		throw_fmt("Failed to open %s: %s", path, strerror(errno));
}

FileHandle::~FileHandle()
{
	if (close(m_fd) < 0)
		throw_fmt("Failed to close %s: %s", m_path, strerror(errno));
}

size_t FileHandle::read(void *buf, size_t size)
{
retry:
	auto ret = ::read(m_fd, buf, size);
	if (ret < 0) {
		if (errno == EINTR)
			goto retry;
		throw_fmt("Failed to read from %s: %s", m_path, strerror(errno));
	}
	return ret;
}

size_t FileHandle::write(const void *buf, size_t size)
{
retry:
	auto ret = ::write(m_fd, buf, size);
	if (ret < 0) {
		if (errno == EINTR)
			goto retry;
		throw_fmt("Failed to write to %s: %s", m_path, strerror(errno));
	}
	return ret;
}

off_t FileHandle::seek(off_t offset, int whence)
{
retry:
	auto ret = ::lseek(m_fd, offset, whence);
	if (ret < 0)
		throw_fmt("Seek failed on %s: %s", m_path, strerror(errno));
	return ret;
}

void FileHandle::tcgetattr(struct termios *termios)
{
	auto ret = ::tcgetattr(m_fd, termios);
	if (ret < 0)
		throw_fmt("tcgetattr failed on %s: %s", m_path, strerror(errno));
}


void FileHandle::tcsetattr(int optional_actions, struct termios *termios)
{
	auto ret = ::tcsetattr(m_fd, optional_actions, termios);
	if (ret < 0)
		throw_fmt("tcsetattr failed on %s: %s", m_path, strerror(errno));
}

void FileHandle::tcflush(int queue_selector)
{
	auto ret = ::tcflush(m_fd, queue_selector);
	if (ret < 0)
		throw_fmt("tcflush failed on %s: %s", m_path, strerror(errno));
}

std::vector<char> read_file(const char *path)
{
	FileHandle file(path, O_RDONLY);
	size_t size = file.seek(0, SEEK_END);
	file.seek(0, SEEK_SET);
	std::vector<char> data(size);
	char *ptr = data.data();
	for (size_t bytes_read = 0; bytes_read < size; ) {
		bytes_read += file.read(ptr, size);
		ptr += bytes_read;
		size -= bytes_read;
	}
	return data;
}
