/*
 * misc.h: Miscellaneous helper
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <sstream>
#include <stdexcept>

#define KiB 1024
#define MiB (1024 * 1024)
#define GiB (1024 * 1024 * 1024)

inline auto output_all(std::stringstream &ss) {}

template<typename T>
auto output_all(std::stringstream &ss, T t) { ss << t; }

template<typename T, typename... U>
auto output_all(std::stringstream &ss, T t, U... u) { ss << t; output_all(ss, u...); }

template<typename... T>
auto format_error(T... t) -> std::runtime_error
{
	std::stringstream ss;
	output_all(ss, t...);
	return std::runtime_error(ss.str());

}
