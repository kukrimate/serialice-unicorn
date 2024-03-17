cmake_minimum_required(VERSION 3.1)

# Unicorn Engine (only build x86)
set(UNICORN_ARCH "x86" CACHE STRING "Unicorn architecture")
add_subdirectory(unicorn)

include(FindPkgConfig)
if (APPLE)
	# Use Lua from macports
	pkg_check_modules(LUA53 REQUIRED IMPORTED_TARGET lua-c++)
else()
	# otheriwse Linux packaging is usually versioned
	pkg_check_modules(LUA53 REQUIRED IMPORTED_TARGET lua-5.3)
endif()

# Project for serialice-unicorn
project(serialice-unicorn CXX)
add_executable(serialice-unicorn
	src/com.cpp src/com.h src/emu.cpp src/emu.h
	src/filter.cpp src/filter.h src/main.cpp
	src/misc.h)
set_property(TARGET serialice-unicorn PROPERTY CXX_STANDARD 20)
target_link_libraries(serialice-unicorn unicorn PkgConfig::LUA53)
