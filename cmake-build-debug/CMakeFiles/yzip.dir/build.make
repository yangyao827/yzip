# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/yangyao/App/clion/clion-2021.3.3/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/yangyao/App/clion/clion-2021.3.3/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yangyao/CLionProjects/yzip-2/diploma_project

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/yzip.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/yzip.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/yzip.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/yzip.dir/flags.make

CMakeFiles/yzip.dir/yzip.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/yzip.cpp.o: ../yzip.cpp
CMakeFiles/yzip.dir/yzip.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/yzip.dir/yzip.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/yzip.cpp.o -MF CMakeFiles/yzip.dir/yzip.cpp.o.d -o CMakeFiles/yzip.dir/yzip.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/yzip.cpp

CMakeFiles/yzip.dir/yzip.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/yzip.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/yzip.cpp > CMakeFiles/yzip.dir/yzip.cpp.i

CMakeFiles/yzip.dir/yzip.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/yzip.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/yzip.cpp -o CMakeFiles/yzip.dir/yzip.cpp.s

CMakeFiles/yzip.dir/version/version_etc.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/version/version_etc.cpp.o: ../version/version_etc.cpp
CMakeFiles/yzip.dir/version/version_etc.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/yzip.dir/version/version_etc.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/version/version_etc.cpp.o -MF CMakeFiles/yzip.dir/version/version_etc.cpp.o.d -o CMakeFiles/yzip.dir/version/version_etc.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/version/version_etc.cpp

CMakeFiles/yzip.dir/version/version_etc.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/version/version_etc.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/version/version_etc.cpp > CMakeFiles/yzip.dir/version/version_etc.cpp.i

CMakeFiles/yzip.dir/version/version_etc.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/version/version_etc.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/version/version_etc.cpp -o CMakeFiles/yzip.dir/version/version_etc.cpp.s

CMakeFiles/yzip.dir/error/error.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/error/error.cpp.o: ../error/error.cpp
CMakeFiles/yzip.dir/error/error.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/yzip.dir/error/error.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/error/error.cpp.o -MF CMakeFiles/yzip.dir/error/error.cpp.o.d -o CMakeFiles/yzip.dir/error/error.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/error/error.cpp

CMakeFiles/yzip.dir/error/error.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/error/error.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/error/error.cpp > CMakeFiles/yzip.dir/error/error.cpp.i

CMakeFiles/yzip.dir/error/error.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/error/error.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/error/error.cpp -o CMakeFiles/yzip.dir/error/error.cpp.s

CMakeFiles/yzip.dir/getfile/get_file.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/getfile/get_file.cpp.o: ../getfile/get_file.cpp
CMakeFiles/yzip.dir/getfile/get_file.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/yzip.dir/getfile/get_file.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/getfile/get_file.cpp.o -MF CMakeFiles/yzip.dir/getfile/get_file.cpp.o.d -o CMakeFiles/yzip.dir/getfile/get_file.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/getfile/get_file.cpp

CMakeFiles/yzip.dir/getfile/get_file.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/getfile/get_file.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/getfile/get_file.cpp > CMakeFiles/yzip.dir/getfile/get_file.cpp.i

CMakeFiles/yzip.dir/getfile/get_file.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/getfile/get_file.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/getfile/get_file.cpp -o CMakeFiles/yzip.dir/getfile/get_file.cpp.s

CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o: ../file_handle/file_handle.cpp
CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o -MF CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o.d -o CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/file_handle/file_handle.cpp

CMakeFiles/yzip.dir/file_handle/file_handle.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/file_handle/file_handle.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/file_handle/file_handle.cpp > CMakeFiles/yzip.dir/file_handle/file_handle.cpp.i

CMakeFiles/yzip.dir/file_handle/file_handle.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/file_handle/file_handle.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/file_handle/file_handle.cpp -o CMakeFiles/yzip.dir/file_handle/file_handle.cpp.s

CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o: ../bitfile/bitfile.cpp
CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o -MF CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o.d -o CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/bitfile/bitfile.cpp

CMakeFiles/yzip.dir/bitfile/bitfile.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/bitfile/bitfile.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/bitfile/bitfile.cpp > CMakeFiles/yzip.dir/bitfile/bitfile.cpp.i

CMakeFiles/yzip.dir/bitfile/bitfile.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/bitfile/bitfile.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/bitfile/bitfile.cpp -o CMakeFiles/yzip.dir/bitfile/bitfile.cpp.s

CMakeFiles/yzip.dir/lzw/lzw.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/lzw/lzw.cpp.o: ../lzw/lzw.cpp
CMakeFiles/yzip.dir/lzw/lzw.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/yzip.dir/lzw/lzw.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/lzw/lzw.cpp.o -MF CMakeFiles/yzip.dir/lzw/lzw.cpp.o.d -o CMakeFiles/yzip.dir/lzw/lzw.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/lzw/lzw.cpp

CMakeFiles/yzip.dir/lzw/lzw.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/lzw/lzw.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/lzw/lzw.cpp > CMakeFiles/yzip.dir/lzw/lzw.cpp.i

CMakeFiles/yzip.dir/lzw/lzw.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/lzw/lzw.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/lzw/lzw.cpp -o CMakeFiles/yzip.dir/lzw/lzw.cpp.s

CMakeFiles/yzip.dir/endswith/endswith.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/endswith/endswith.cpp.o: ../endswith/endswith.cpp
CMakeFiles/yzip.dir/endswith/endswith.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/yzip.dir/endswith/endswith.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/endswith/endswith.cpp.o -MF CMakeFiles/yzip.dir/endswith/endswith.cpp.o.d -o CMakeFiles/yzip.dir/endswith/endswith.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/endswith/endswith.cpp

CMakeFiles/yzip.dir/endswith/endswith.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/endswith/endswith.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/endswith/endswith.cpp > CMakeFiles/yzip.dir/endswith/endswith.cpp.i

CMakeFiles/yzip.dir/endswith/endswith.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/endswith/endswith.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/endswith/endswith.cpp -o CMakeFiles/yzip.dir/endswith/endswith.cpp.s

CMakeFiles/yzip.dir/encryption/encryption.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/encryption/encryption.cpp.o: ../encryption/encryption.cpp
CMakeFiles/yzip.dir/encryption/encryption.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object CMakeFiles/yzip.dir/encryption/encryption.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/encryption/encryption.cpp.o -MF CMakeFiles/yzip.dir/encryption/encryption.cpp.o.d -o CMakeFiles/yzip.dir/encryption/encryption.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/encryption/encryption.cpp

CMakeFiles/yzip.dir/encryption/encryption.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/encryption/encryption.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/encryption/encryption.cpp > CMakeFiles/yzip.dir/encryption/encryption.cpp.i

CMakeFiles/yzip.dir/encryption/encryption.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/encryption/encryption.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/encryption/encryption.cpp -o CMakeFiles/yzip.dir/encryption/encryption.cpp.s

CMakeFiles/yzip.dir/package/package_check.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/package/package_check.cpp.o: ../package/package_check.cpp
CMakeFiles/yzip.dir/package/package_check.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object CMakeFiles/yzip.dir/package/package_check.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/package/package_check.cpp.o -MF CMakeFiles/yzip.dir/package/package_check.cpp.o.d -o CMakeFiles/yzip.dir/package/package_check.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/package/package_check.cpp

CMakeFiles/yzip.dir/package/package_check.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/package/package_check.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/package/package_check.cpp > CMakeFiles/yzip.dir/package/package_check.cpp.i

CMakeFiles/yzip.dir/package/package_check.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/package/package_check.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/package/package_check.cpp -o CMakeFiles/yzip.dir/package/package_check.cpp.s

CMakeFiles/yzip.dir/package/get_cur_time.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/package/get_cur_time.cpp.o: ../package/get_cur_time.cpp
CMakeFiles/yzip.dir/package/get_cur_time.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building CXX object CMakeFiles/yzip.dir/package/get_cur_time.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/package/get_cur_time.cpp.o -MF CMakeFiles/yzip.dir/package/get_cur_time.cpp.o.d -o CMakeFiles/yzip.dir/package/get_cur_time.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/package/get_cur_time.cpp

CMakeFiles/yzip.dir/package/get_cur_time.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/package/get_cur_time.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/package/get_cur_time.cpp > CMakeFiles/yzip.dir/package/get_cur_time.cpp.i

CMakeFiles/yzip.dir/package/get_cur_time.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/package/get_cur_time.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/package/get_cur_time.cpp -o CMakeFiles/yzip.dir/package/get_cur_time.cpp.s

CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o: ../package/mode_to_letters.cpp
CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building CXX object CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o -MF CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o.d -o CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/package/mode_to_letters.cpp

CMakeFiles/yzip.dir/package/mode_to_letters.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/package/mode_to_letters.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/package/mode_to_letters.cpp > CMakeFiles/yzip.dir/package/mode_to_letters.cpp.i

CMakeFiles/yzip.dir/package/mode_to_letters.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/package/mode_to_letters.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/package/mode_to_letters.cpp -o CMakeFiles/yzip.dir/package/mode_to_letters.cpp.s

CMakeFiles/yzip.dir/package/pack.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/package/pack.cpp.o: ../package/pack.cpp
CMakeFiles/yzip.dir/package/pack.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Building CXX object CMakeFiles/yzip.dir/package/pack.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/package/pack.cpp.o -MF CMakeFiles/yzip.dir/package/pack.cpp.o.d -o CMakeFiles/yzip.dir/package/pack.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/package/pack.cpp

CMakeFiles/yzip.dir/package/pack.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/package/pack.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/package/pack.cpp > CMakeFiles/yzip.dir/package/pack.cpp.i

CMakeFiles/yzip.dir/package/pack.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/package/pack.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/package/pack.cpp -o CMakeFiles/yzip.dir/package/pack.cpp.s

CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o: ../is_file_exist/is_file_exist.cpp
CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_14) "Building CXX object CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o -MF CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o.d -o CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/is_file_exist/is_file_exist.cpp

CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/is_file_exist/is_file_exist.cpp > CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.i

CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/is_file_exist/is_file_exist.cpp -o CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.s

CMakeFiles/yzip.dir/size_h/size_h.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/size_h/size_h.cpp.o: ../size_h/size_h.cpp
CMakeFiles/yzip.dir/size_h/size_h.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_15) "Building CXX object CMakeFiles/yzip.dir/size_h/size_h.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/size_h/size_h.cpp.o -MF CMakeFiles/yzip.dir/size_h/size_h.cpp.o.d -o CMakeFiles/yzip.dir/size_h/size_h.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/size_h/size_h.cpp

CMakeFiles/yzip.dir/size_h/size_h.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/size_h/size_h.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/size_h/size_h.cpp > CMakeFiles/yzip.dir/size_h/size_h.cpp.i

CMakeFiles/yzip.dir/size_h/size_h.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/size_h/size_h.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/size_h/size_h.cpp -o CMakeFiles/yzip.dir/size_h/size_h.cpp.s

CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o: CMakeFiles/yzip.dir/flags.make
CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o: ../verbose_info/verbose_info.cpp
CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o: CMakeFiles/yzip.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_16) "Building CXX object CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o -MF CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o.d -o CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o -c /home/yangyao/CLionProjects/yzip-2/diploma_project/verbose_info/verbose_info.cpp

CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yangyao/CLionProjects/yzip-2/diploma_project/verbose_info/verbose_info.cpp > CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.i

CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yangyao/CLionProjects/yzip-2/diploma_project/verbose_info/verbose_info.cpp -o CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.s

# Object files for target yzip
yzip_OBJECTS = \
"CMakeFiles/yzip.dir/yzip.cpp.o" \
"CMakeFiles/yzip.dir/version/version_etc.cpp.o" \
"CMakeFiles/yzip.dir/error/error.cpp.o" \
"CMakeFiles/yzip.dir/getfile/get_file.cpp.o" \
"CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o" \
"CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o" \
"CMakeFiles/yzip.dir/lzw/lzw.cpp.o" \
"CMakeFiles/yzip.dir/endswith/endswith.cpp.o" \
"CMakeFiles/yzip.dir/encryption/encryption.cpp.o" \
"CMakeFiles/yzip.dir/package/package_check.cpp.o" \
"CMakeFiles/yzip.dir/package/get_cur_time.cpp.o" \
"CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o" \
"CMakeFiles/yzip.dir/package/pack.cpp.o" \
"CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o" \
"CMakeFiles/yzip.dir/size_h/size_h.cpp.o" \
"CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o"

# External object files for target yzip
yzip_EXTERNAL_OBJECTS =

yzip: CMakeFiles/yzip.dir/yzip.cpp.o
yzip: CMakeFiles/yzip.dir/version/version_etc.cpp.o
yzip: CMakeFiles/yzip.dir/error/error.cpp.o
yzip: CMakeFiles/yzip.dir/getfile/get_file.cpp.o
yzip: CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o
yzip: CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o
yzip: CMakeFiles/yzip.dir/lzw/lzw.cpp.o
yzip: CMakeFiles/yzip.dir/endswith/endswith.cpp.o
yzip: CMakeFiles/yzip.dir/encryption/encryption.cpp.o
yzip: CMakeFiles/yzip.dir/package/package_check.cpp.o
yzip: CMakeFiles/yzip.dir/package/get_cur_time.cpp.o
yzip: CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o
yzip: CMakeFiles/yzip.dir/package/pack.cpp.o
yzip: CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o
yzip: CMakeFiles/yzip.dir/size_h/size_h.cpp.o
yzip: CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o
yzip: CMakeFiles/yzip.dir/build.make
yzip: CMakeFiles/yzip.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_17) "Linking CXX executable yzip"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/yzip.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/yzip.dir/build: yzip
.PHONY : CMakeFiles/yzip.dir/build

CMakeFiles/yzip.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/yzip.dir/cmake_clean.cmake
.PHONY : CMakeFiles/yzip.dir/clean

CMakeFiles/yzip.dir/depend:
	cd /home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yangyao/CLionProjects/yzip-2/diploma_project /home/yangyao/CLionProjects/yzip-2/diploma_project /home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug /home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug /home/yangyao/CLionProjects/yzip-2/diploma_project/cmake-build-debug/CMakeFiles/yzip.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/yzip.dir/depend

