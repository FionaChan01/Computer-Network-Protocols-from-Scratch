# CMAKE generated file: DO NOT EDIT!
# Generated by "NMake Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE
NULL=nul
!ENDIF
SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "E:\Clion\CLion 2020.1.1\bin\cmake\win\bin\cmake.exe"

# The command to remove a file.
RM = "E:\Clion\CLion 2020.1.1\bin\cmake\win\bin\cmake.exe" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "C:\Users\surface\Desktop\Computer Network\project\app2"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "C:\Users\surface\Desktop\Computer Network\project\app2\cmake-build-debug"

# Include any dependencies generated for this target.
include CMakeFiles\app2.dir\depend.make

# Include the progress variables for this target.
include CMakeFiles\app2.dir\progress.make

# Include the compile flags for this target's objects.
include CMakeFiles\app2.dir\flags.make

CMakeFiles\app2.dir\main.c.obj: CMakeFiles\app2.dir\flags.make
CMakeFiles\app2.dir\main.c.obj: ..\main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="C:\Users\surface\Desktop\Computer Network\project\app2\cmake-build-debug\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/app2.dir/main.c.obj"
	C:\PROGRA~2\MICROS~1\2019\COMMUN~1\VC\Tools\MSVC\1428~1.293\bin\Hostx86\x86\cl.exe @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) /FoCMakeFiles\app2.dir\main.c.obj /FdCMakeFiles\app2.dir\ /FS -c "C:\Users\surface\Desktop\Computer Network\project\app2\main.c"
<<

CMakeFiles\app2.dir\main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/app2.dir/main.c.i"
	C:\PROGRA~2\MICROS~1\2019\COMMUN~1\VC\Tools\MSVC\1428~1.293\bin\Hostx86\x86\cl.exe > CMakeFiles\app2.dir\main.c.i @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "C:\Users\surface\Desktop\Computer Network\project\app2\main.c"
<<

CMakeFiles\app2.dir\main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/app2.dir/main.c.s"
	C:\PROGRA~2\MICROS~1\2019\COMMUN~1\VC\Tools\MSVC\1428~1.293\bin\Hostx86\x86\cl.exe @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) /FoNUL /FAs /FaCMakeFiles\app2.dir\main.c.s /c "C:\Users\surface\Desktop\Computer Network\project\app2\main.c"
<<

# Object files for target app2
app2_OBJECTS = \
"CMakeFiles\app2.dir\main.c.obj"

# External object files for target app2
app2_EXTERNAL_OBJECTS =

app2.exe: CMakeFiles\app2.dir\main.c.obj
app2.exe: CMakeFiles\app2.dir\build.make
app2.exe: CMakeFiles\app2.dir\objects1.rsp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="C:\Users\surface\Desktop\Computer Network\project\app2\cmake-build-debug\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable app2.exe"
	"E:\Clion\CLion 2020.1.1\bin\cmake\win\bin\cmake.exe" -E vs_link_exe --intdir=CMakeFiles\app2.dir --rc=C:\PROGRA~2\WI3CF2~1\10\bin\100183~1.0\x86\rc.exe --mt=C:\PROGRA~2\WI3CF2~1\10\bin\100183~1.0\x86\mt.exe --manifests  -- C:\PROGRA~2\MICROS~1\2019\COMMUN~1\VC\Tools\MSVC\1428~1.293\bin\Hostx86\x86\link.exe /nologo @CMakeFiles\app2.dir\objects1.rsp @<<
 /out:app2.exe /implib:app2.lib /pdb:"C:\Users\surface\Desktop\Computer Network\project\app2\cmake-build-debug\app2.pdb" /version:0.0  /machine:X86 /debug /INCREMENTAL /subsystem:console  kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib 
<<

# Rule to build all files generated by this target.
CMakeFiles\app2.dir\build: app2.exe

.PHONY : CMakeFiles\app2.dir\build

CMakeFiles\app2.dir\clean:
	$(CMAKE_COMMAND) -P CMakeFiles\app2.dir\cmake_clean.cmake
.PHONY : CMakeFiles\app2.dir\clean

CMakeFiles\app2.dir\depend:
	$(CMAKE_COMMAND) -E cmake_depends "NMake Makefiles" "C:\Users\surface\Desktop\Computer Network\project\app2" "C:\Users\surface\Desktop\Computer Network\project\app2" "C:\Users\surface\Desktop\Computer Network\project\app2\cmake-build-debug" "C:\Users\surface\Desktop\Computer Network\project\app2\cmake-build-debug" "C:\Users\surface\Desktop\Computer Network\project\app2\cmake-build-debug\CMakeFiles\app2.dir\DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles\app2.dir\depend

