# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yangyao/Git/yzip

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yangyao/Git/yzip

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/bin/ccmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/yangyao/Git/yzip/CMakeFiles /home/yangyao/Git/yzip//CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/yangyao/Git/yzip/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named yzip

# Build rule for target.
yzip: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 yzip
.PHONY : yzip

# fast build rule for target.
yzip/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/build
.PHONY : yzip/fast

bitfile/bitfile.o: bitfile/bitfile.cpp.o
.PHONY : bitfile/bitfile.o

# target to build an object file
bitfile/bitfile.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/bitfile/bitfile.cpp.o
.PHONY : bitfile/bitfile.cpp.o

bitfile/bitfile.i: bitfile/bitfile.cpp.i
.PHONY : bitfile/bitfile.i

# target to preprocess a source file
bitfile/bitfile.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/bitfile/bitfile.cpp.i
.PHONY : bitfile/bitfile.cpp.i

bitfile/bitfile.s: bitfile/bitfile.cpp.s
.PHONY : bitfile/bitfile.s

# target to generate assembly for a file
bitfile/bitfile.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/bitfile/bitfile.cpp.s
.PHONY : bitfile/bitfile.cpp.s

encryption/encryption.o: encryption/encryption.cpp.o
.PHONY : encryption/encryption.o

# target to build an object file
encryption/encryption.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/encryption/encryption.cpp.o
.PHONY : encryption/encryption.cpp.o

encryption/encryption.i: encryption/encryption.cpp.i
.PHONY : encryption/encryption.i

# target to preprocess a source file
encryption/encryption.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/encryption/encryption.cpp.i
.PHONY : encryption/encryption.cpp.i

encryption/encryption.s: encryption/encryption.cpp.s
.PHONY : encryption/encryption.s

# target to generate assembly for a file
encryption/encryption.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/encryption/encryption.cpp.s
.PHONY : encryption/encryption.cpp.s

endswith/endswith.o: endswith/endswith.cpp.o
.PHONY : endswith/endswith.o

# target to build an object file
endswith/endswith.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/endswith/endswith.cpp.o
.PHONY : endswith/endswith.cpp.o

endswith/endswith.i: endswith/endswith.cpp.i
.PHONY : endswith/endswith.i

# target to preprocess a source file
endswith/endswith.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/endswith/endswith.cpp.i
.PHONY : endswith/endswith.cpp.i

endswith/endswith.s: endswith/endswith.cpp.s
.PHONY : endswith/endswith.s

# target to generate assembly for a file
endswith/endswith.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/endswith/endswith.cpp.s
.PHONY : endswith/endswith.cpp.s

error/error.o: error/error.cpp.o
.PHONY : error/error.o

# target to build an object file
error/error.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/error/error.cpp.o
.PHONY : error/error.cpp.o

error/error.i: error/error.cpp.i
.PHONY : error/error.i

# target to preprocess a source file
error/error.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/error/error.cpp.i
.PHONY : error/error.cpp.i

error/error.s: error/error.cpp.s
.PHONY : error/error.s

# target to generate assembly for a file
error/error.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/error/error.cpp.s
.PHONY : error/error.cpp.s

file_handle/file_handle.o: file_handle/file_handle.cpp.o
.PHONY : file_handle/file_handle.o

# target to build an object file
file_handle/file_handle.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/file_handle/file_handle.cpp.o
.PHONY : file_handle/file_handle.cpp.o

file_handle/file_handle.i: file_handle/file_handle.cpp.i
.PHONY : file_handle/file_handle.i

# target to preprocess a source file
file_handle/file_handle.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/file_handle/file_handle.cpp.i
.PHONY : file_handle/file_handle.cpp.i

file_handle/file_handle.s: file_handle/file_handle.cpp.s
.PHONY : file_handle/file_handle.s

# target to generate assembly for a file
file_handle/file_handle.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/file_handle/file_handle.cpp.s
.PHONY : file_handle/file_handle.cpp.s

getfile/get_file.o: getfile/get_file.cpp.o
.PHONY : getfile/get_file.o

# target to build an object file
getfile/get_file.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/getfile/get_file.cpp.o
.PHONY : getfile/get_file.cpp.o

getfile/get_file.i: getfile/get_file.cpp.i
.PHONY : getfile/get_file.i

# target to preprocess a source file
getfile/get_file.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/getfile/get_file.cpp.i
.PHONY : getfile/get_file.cpp.i

getfile/get_file.s: getfile/get_file.cpp.s
.PHONY : getfile/get_file.s

# target to generate assembly for a file
getfile/get_file.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/getfile/get_file.cpp.s
.PHONY : getfile/get_file.cpp.s

is_file_exist/is_file_exist.o: is_file_exist/is_file_exist.cpp.o
.PHONY : is_file_exist/is_file_exist.o

# target to build an object file
is_file_exist/is_file_exist.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.o
.PHONY : is_file_exist/is_file_exist.cpp.o

is_file_exist/is_file_exist.i: is_file_exist/is_file_exist.cpp.i
.PHONY : is_file_exist/is_file_exist.i

# target to preprocess a source file
is_file_exist/is_file_exist.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.i
.PHONY : is_file_exist/is_file_exist.cpp.i

is_file_exist/is_file_exist.s: is_file_exist/is_file_exist.cpp.s
.PHONY : is_file_exist/is_file_exist.s

# target to generate assembly for a file
is_file_exist/is_file_exist.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/is_file_exist/is_file_exist.cpp.s
.PHONY : is_file_exist/is_file_exist.cpp.s

lzw/lzw.o: lzw/lzw.cpp.o
.PHONY : lzw/lzw.o

# target to build an object file
lzw/lzw.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/lzw/lzw.cpp.o
.PHONY : lzw/lzw.cpp.o

lzw/lzw.i: lzw/lzw.cpp.i
.PHONY : lzw/lzw.i

# target to preprocess a source file
lzw/lzw.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/lzw/lzw.cpp.i
.PHONY : lzw/lzw.cpp.i

lzw/lzw.s: lzw/lzw.cpp.s
.PHONY : lzw/lzw.s

# target to generate assembly for a file
lzw/lzw.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/lzw/lzw.cpp.s
.PHONY : lzw/lzw.cpp.s

package/get_cur_time.o: package/get_cur_time.cpp.o
.PHONY : package/get_cur_time.o

# target to build an object file
package/get_cur_time.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/get_cur_time.cpp.o
.PHONY : package/get_cur_time.cpp.o

package/get_cur_time.i: package/get_cur_time.cpp.i
.PHONY : package/get_cur_time.i

# target to preprocess a source file
package/get_cur_time.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/get_cur_time.cpp.i
.PHONY : package/get_cur_time.cpp.i

package/get_cur_time.s: package/get_cur_time.cpp.s
.PHONY : package/get_cur_time.s

# target to generate assembly for a file
package/get_cur_time.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/get_cur_time.cpp.s
.PHONY : package/get_cur_time.cpp.s

package/mode_to_letters.o: package/mode_to_letters.cpp.o
.PHONY : package/mode_to_letters.o

# target to build an object file
package/mode_to_letters.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/mode_to_letters.cpp.o
.PHONY : package/mode_to_letters.cpp.o

package/mode_to_letters.i: package/mode_to_letters.cpp.i
.PHONY : package/mode_to_letters.i

# target to preprocess a source file
package/mode_to_letters.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/mode_to_letters.cpp.i
.PHONY : package/mode_to_letters.cpp.i

package/mode_to_letters.s: package/mode_to_letters.cpp.s
.PHONY : package/mode_to_letters.s

# target to generate assembly for a file
package/mode_to_letters.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/mode_to_letters.cpp.s
.PHONY : package/mode_to_letters.cpp.s

package/pack.o: package/pack.cpp.o
.PHONY : package/pack.o

# target to build an object file
package/pack.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/pack.cpp.o
.PHONY : package/pack.cpp.o

package/pack.i: package/pack.cpp.i
.PHONY : package/pack.i

# target to preprocess a source file
package/pack.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/pack.cpp.i
.PHONY : package/pack.cpp.i

package/pack.s: package/pack.cpp.s
.PHONY : package/pack.s

# target to generate assembly for a file
package/pack.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/pack.cpp.s
.PHONY : package/pack.cpp.s

package/package_check.o: package/package_check.cpp.o
.PHONY : package/package_check.o

# target to build an object file
package/package_check.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/package_check.cpp.o
.PHONY : package/package_check.cpp.o

package/package_check.i: package/package_check.cpp.i
.PHONY : package/package_check.i

# target to preprocess a source file
package/package_check.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/package_check.cpp.i
.PHONY : package/package_check.cpp.i

package/package_check.s: package/package_check.cpp.s
.PHONY : package/package_check.s

# target to generate assembly for a file
package/package_check.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/package/package_check.cpp.s
.PHONY : package/package_check.cpp.s

size_h/size_h.o: size_h/size_h.cpp.o
.PHONY : size_h/size_h.o

# target to build an object file
size_h/size_h.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/size_h/size_h.cpp.o
.PHONY : size_h/size_h.cpp.o

size_h/size_h.i: size_h/size_h.cpp.i
.PHONY : size_h/size_h.i

# target to preprocess a source file
size_h/size_h.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/size_h/size_h.cpp.i
.PHONY : size_h/size_h.cpp.i

size_h/size_h.s: size_h/size_h.cpp.s
.PHONY : size_h/size_h.s

# target to generate assembly for a file
size_h/size_h.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/size_h/size_h.cpp.s
.PHONY : size_h/size_h.cpp.s

verbose_info/verbose_info.o: verbose_info/verbose_info.cpp.o
.PHONY : verbose_info/verbose_info.o

# target to build an object file
verbose_info/verbose_info.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.o
.PHONY : verbose_info/verbose_info.cpp.o

verbose_info/verbose_info.i: verbose_info/verbose_info.cpp.i
.PHONY : verbose_info/verbose_info.i

# target to preprocess a source file
verbose_info/verbose_info.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.i
.PHONY : verbose_info/verbose_info.cpp.i

verbose_info/verbose_info.s: verbose_info/verbose_info.cpp.s
.PHONY : verbose_info/verbose_info.s

# target to generate assembly for a file
verbose_info/verbose_info.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/verbose_info/verbose_info.cpp.s
.PHONY : verbose_info/verbose_info.cpp.s

version/version_etc.o: version/version_etc.cpp.o
.PHONY : version/version_etc.o

# target to build an object file
version/version_etc.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/version/version_etc.cpp.o
.PHONY : version/version_etc.cpp.o

version/version_etc.i: version/version_etc.cpp.i
.PHONY : version/version_etc.i

# target to preprocess a source file
version/version_etc.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/version/version_etc.cpp.i
.PHONY : version/version_etc.cpp.i

version/version_etc.s: version/version_etc.cpp.s
.PHONY : version/version_etc.s

# target to generate assembly for a file
version/version_etc.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/version/version_etc.cpp.s
.PHONY : version/version_etc.cpp.s

yzip.o: yzip.cpp.o
.PHONY : yzip.o

# target to build an object file
yzip.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/yzip.cpp.o
.PHONY : yzip.cpp.o

yzip.i: yzip.cpp.i
.PHONY : yzip.i

# target to preprocess a source file
yzip.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/yzip.cpp.i
.PHONY : yzip.cpp.i

yzip.s: yzip.cpp.s
.PHONY : yzip.s

# target to generate assembly for a file
yzip.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/yzip.dir/build.make CMakeFiles/yzip.dir/yzip.cpp.s
.PHONY : yzip.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... yzip"
	@echo "... bitfile/bitfile.o"
	@echo "... bitfile/bitfile.i"
	@echo "... bitfile/bitfile.s"
	@echo "... encryption/encryption.o"
	@echo "... encryption/encryption.i"
	@echo "... encryption/encryption.s"
	@echo "... endswith/endswith.o"
	@echo "... endswith/endswith.i"
	@echo "... endswith/endswith.s"
	@echo "... error/error.o"
	@echo "... error/error.i"
	@echo "... error/error.s"
	@echo "... file_handle/file_handle.o"
	@echo "... file_handle/file_handle.i"
	@echo "... file_handle/file_handle.s"
	@echo "... getfile/get_file.o"
	@echo "... getfile/get_file.i"
	@echo "... getfile/get_file.s"
	@echo "... is_file_exist/is_file_exist.o"
	@echo "... is_file_exist/is_file_exist.i"
	@echo "... is_file_exist/is_file_exist.s"
	@echo "... lzw/lzw.o"
	@echo "... lzw/lzw.i"
	@echo "... lzw/lzw.s"
	@echo "... package/get_cur_time.o"
	@echo "... package/get_cur_time.i"
	@echo "... package/get_cur_time.s"
	@echo "... package/mode_to_letters.o"
	@echo "... package/mode_to_letters.i"
	@echo "... package/mode_to_letters.s"
	@echo "... package/pack.o"
	@echo "... package/pack.i"
	@echo "... package/pack.s"
	@echo "... package/package_check.o"
	@echo "... package/package_check.i"
	@echo "... package/package_check.s"
	@echo "... size_h/size_h.o"
	@echo "... size_h/size_h.i"
	@echo "... size_h/size_h.s"
	@echo "... verbose_info/verbose_info.o"
	@echo "... verbose_info/verbose_info.i"
	@echo "... verbose_info/verbose_info.s"
	@echo "... version/version_etc.o"
	@echo "... version/version_etc.i"
	@echo "... version/version_etc.s"
	@echo "... yzip.o"
	@echo "... yzip.i"
	@echo "... yzip.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system
