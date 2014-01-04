############################# INITIAL SECTION #############################################

PROJECT(rmilter C)

SET(RMILTER_VERSION_MAJOR 1)
SET(RMILTER_VERSION_MINOR 6)
SET(RMILTER_VERSION_PATCH 0)

SET(RMILTER_VERSION         "${RMILTER_VERSION_MAJOR}.${RMILTER_VERSION_MINOR}.${RMILTER_VERSION_PATCH}")
SET(RMILTER_MASTER_SITE_URL "https://rspamd.com")

IF(NOT RMILTER_USER)
	SET(RMILTER_USER "nobody")
	SET(RMILTER_GROUP "nobody")
ENDIF()

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.0 FATAL_ERROR)

############################# OPTIONS SECTION #############################################

OPTION(DEBUG_MODE          "Enable debug output [default: ON]"                  ON)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: OFF]"                 OFF)
OPTION(ENABLE_DKIM         "Enable dkim signatures [default: OFF]"              OFF)
OPTION(ENABLE_SPF          "Enable SPF checks [default: OFF]"                   OFF)

############################# INCLUDE SECTION #############################################

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckLibraryExists)
INCLUDE(FindPkgConfig)
INCLUDE(CheckCCompilerFlag)
INCLUDE(FindOpenSSL)
INCLUDE(FindThreads)

FIND_PACKAGE(BISON)
FIND_PACKAGE(FLEX)

MACRO(ProcessPackage var _name0)
    PKG_SEARCH_MODULE(${var} REQUIRED "${_name0}" ${ARGN})
    IF(${var}_FOUND)
        SET(WITH_${var} 1)
        SET(_XPREFIX "${var}")
        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
            INCLUDE_DIRECTORIES("${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
            LINK_DIRECTORIES("${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
        # Handle other CFLAGS and LDFLAGS
        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
        LIST(APPEND RMILTER_REQUIRED_LIBRARIES "${${_XPREFIX}_LIBRARIES}")
    ENDIF(${var}_FOUND)
ENDMACRO(ProcessPackage name)

############################# OS SECTION #############################################

IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DFREEBSD")
	MESSAGE(STATUS "Configuring for FreeBSD")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
IF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DDARWIN")
    SET(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")
MESSAGE(STATUS "Configuring for Darwin")

ENDIF()

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DLINUX")
	LIST(APPEND RMILTER_REQUIRED_LIBRARIES "pthread")
    IF(BUILD_CPU_MODE STREQUAL "32")
    	SET(CMAKE_C_FLAGS  "-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE ${CMAKE_C_FLAGS}")
    ENDIF(BUILD_CPU_MODE STREQUAL "32")
ENDIF()

IF(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
 	IF(NOT BUILD_CPU_MODE)
	 	SET (BUILD_CPU_MODE "32")
	ENDIF(NOT BUILD_CPU_MODE)
	
	IF("${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Xa -xregs=no%frameptr -xstrconst -xc99")
		SET(SUN_BUILD32 "-xtarget=generic")
		SET(SUN_BUILD64 "-xtarget=generic64")
		IF(ENABLE_OPTIMIZATION MATCHES "ON")
			SET(CMAKE_C_OPT_FLAGS "-fast -xdepend")
		ELSE(ENABLE_OPTIMIZATION MATCHES "ON")
			SET(CMAKE_C_OPT_FLAGS "-xO0")
		ENDIF(ENABLE_OPTIMIZATION MATCHES "ON")
	ELSE("${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
		set(SUN_BUILD32 "-m32")
		set(SUN_BUILD64 "-m64")		
	ENDIF("${CMAKE_C_COMPILER_ID}" MATCHES SunPro)

 	IF (BUILD_CPU_MODE STREQUAL "32")
       message (STATUS "Building 32-bit mode on Solaris")
       # If we are asked to build 32 bit mode
       	set(CMAKE_C_FLAGS  "${SUN_BUILD32} ${CMAKE_C_FLAGS}")
       	set(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SUN_BUILD32}")
 	ELSE (BUILD_CPU_MODE STREQUAL "32")
       # solaris 64-bit mode
		message (STATUS "Building 64-bit mode on Solaris")
       	set(CMAKE_C_FLAGS  "${SUN_BUILD64} ${CMAKE_C_FLAGS}")
       	set(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SUN_BUILD64}")
    ENDIF (BUILD_CPU_MODE STREQUAL "32")

 	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__EXTENSIONS__ -DSOLARIS -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L")
    
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES rt)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES dl)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES resolv)
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES nsl)
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES socket)
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES umem)
 	# Ugly hack, but FindOpenSSL on Solaris does not link with libcrypto
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES crypto)
  	SET(CMAKE_VERBOSE_MAKEFILE ON)
  	SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
  	SET(CMAKE_INSTALL_RPATH "${PREFIX}/lib")	
ENDIF()

############################# CONFIGURE SECTION #############################################

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/include" 
					"${CMAKE_BINARY_DIR}/include"
					"${CMAKE_BINARY_DIR}/" 
					"${CMAKE_SOURCE_DIR}/compat"
					"${CMAKE_SOURCE_DIR}/uthash")

BISON_TARGET(CfgParser src/cfg_file.y ${CMAKE_CURRENT_BINARY_DIR}/cfg_yacc.c)
FLEX_TARGET(CfgScanner src/cfg_file.l  ${CMAKE_CURRENT_BINARY_DIR}/cfg_lex.c)
ADD_FLEX_BISON_DEPENDENCY(CfgScanner CfgParser)

#Check for openssl (required for dkim)
IF(OPENSSL_FOUND)
	INCLUDE_DIRECTORIES("${OPENSSL_INCLUDE_DIR}")
	LIST(APPEND RMILTER_REQUIRED_LIBRARIES "${OPENSSL_LIBRARIES}")
ELSE()
    MESSAGE(FATAL_ERROR "rmilter requires openssl for build")
ENDIF()

ProcessPackage(PCRE libpcre)

FIND_LIBRARY(LIBMILTER_LIBRARY NAMES milter PATH_SUFFIXES lib64 lib lib/libmilter lib64/libmilter
                  PATHS
                      ~/Library/Frameworks
                      /Library/Frameworks
                      /usr/local
                      /usr
                      /sw
                      /opt/local
                      /opt/csw
                      /opt
                 DOC "Path where the libmilter library can be found")

FIND_PATH(LIBMILTER_INCLUDE mfapi.h PATH_SUFFIXES include include/libmilter 
                PATHS   ~/Library/Frameworks
                      /Library/Frameworks
                      /usr/local
                      /usr
                      /sw
                      /opt/local
                      /opt/csw
                      /opt
                DOC "Path where the libmilter header files can be found")
IF(NOT LIBMILTER_LIBRARY OR NOT LIBMILTER_INCLUDE)
	MESSAGE(FATAL_ERROR "libmilter is required for building rmilter")
ENDIF()
LIST(APPEND RMILTER_REQUIRED_LIBRARIES "milter")

GET_FILENAME_COMPONENT(LIBMILTER_PATH "${LIBMILTER_LIBRARY}" PATH)
INCLUDE_DIRECTORIES("${LIBMILTER_INCLUDE}")
LINK_DIRECTORIES("${LIBMILTER_PATH}")

IF(ENABLE_DKIM MATCHES "ON")
    SET(WITH_DKIM 1)
    FIND_LIBRARY(LIBOPENDKIM_LIBRARY NAMES opendkim PATH_SUFFIXES lib64 lib lib/libopendkim lib64/libopendkim
                      PATHS
                          ~/Library/Frameworks
                          /Library/Frameworks
                          /usr/local
                          /usr
                          /sw
                          /opt/local
                          /opt/csw
                          /opt
                     DOC "Path where the opendkim library can be found")
    
    FIND_PATH(LIBOPENDKIM_INCLUDE dkim.h PATH_SUFFIXES include include/opendkim 
                    PATHS   ~/Library/Frameworks
                          /Library/Frameworks
                          /usr/local
                          /usr
                          /sw
                          /opt/local
                          /opt/csw
                          /opt
                    DOC "Path where the opendkim header files can be found")
    IF(NOT LIBOPENDKIM_LIBRARY OR NOT LIBOPENDKIM_INCLUDE)
    	MESSAGE(FATAL_ERROR "libmilter is required for building rmilter")
    ENDIF()
    GET_FILENAME_COMPONENT(LIBOPENDKIM_PATH "${LIBOPENDKIM_LIBRARY}" PATH)
    INCLUDE_DIRECTORIES("${LIBOPENDKIM_INCLUDE}")
    LINK_DIRECTORIES("${LIBOPENDKIM_PATH}")
    LIST(APPEND RMILTER_REQUIRED_LIBRARIES "opendkim")
ENDIF()

IF(ENABLE_SPF MATCHES "ON")
    SET(WITH_SPF 1)
    FIND_LIBRARY(LIBSPF2_LIBRARY NAMES spf2 PATH_SUFFIXES lib64 lib lib/libspf2 lib64/libspf2 lib/libspf lib64/libspf
                      PATHS
                          ~/Library/Frameworks
                          /Library/Frameworks
                          /usr/local
                          /usr
                          /sw
                          /opt/local
                          /opt/csw
                          /opt
                     DOC "Path where the libspf library can be found")
    
    FIND_PATH(LIBSPF2_INCLUDE spf.h PATH_SUFFIXES include include/spf include/spf2 
                    PATHS   ~/Library/Frameworks
                          /Library/Frameworks
                          /usr/local
                          /usr
                          /sw
                          /opt/local
                          /opt/csw
                          /opt
                    DOC "Path where the libspf header files can be found")
    IF(NOT LIBSPF2_LIBRARY OR NOT LIBSPF2_INCLUDE)
    	MESSAGE(FATAL_ERROR "libspf2 is required for building rmilter")
    ENDIF()
    GET_FILENAME_COMPONENT(LIBSPF2_PATH "${LIBSPF2_LIBRARY}" PATH)
    INCLUDE_DIRECTORIES("${LIBSPF2_INCLUDE}")
    LINK_DIRECTORIES("${LIBSPF2_PATH}")
    LIST(APPEND RMILTER_REQUIRED_LIBRARIES "spf2")
ENDIF()

# Process with warn flags
SET(CMAKE_C_WARN_FLAGS "")
CHECK_C_COMPILER_FLAG(-Wall SUPPORT_WALL)
CHECK_C_COMPILER_FLAG(-W SUPPORT_W)
CHECK_C_COMPILER_FLAG(-Wpointer-arith SUPPORT_WPOINTER)
CHECK_C_COMPILER_FLAG(-Wno-unused-parameter SUPPORT_WPARAM)
CHECK_C_COMPILER_FLAG(-Wno-unused-function SUPPORT_WFUNCTION)
CHECK_C_COMPILER_FLAG(-Wunused-variable SUPPORT_WUNUSED_VAR)
CHECK_C_COMPILER_FLAG(-Wpointer-sign SUPPORT_WPOINTER_SIGN)
CHECK_C_COMPILER_FLAG(-Wsign-compare SUPPORT_WSIGN_COMPARE)
CHECK_C_COMPILER_FLAG(-Wstrict-prototypes SUPPORT_WSTRICT_PROTOTYPES)
IF(NOT "${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
	CHECK_C_COMPILER_FLAG("-std=c99" SUPPORT_STD_FLAG)
ENDIF(NOT "${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
IF(SUPPORT_W)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -W")
ENDIF(SUPPORT_W)
IF(SUPPORT_WALL)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wall")
ENDIF(SUPPORT_WALL)
IF(SUPPORT_WPOINTER)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wpointer-arith")
ENDIF(SUPPORT_WPOINTER)
IF(SUPPORT_WPARAM)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-parameter")
ENDIF(SUPPORT_WPARAM)
IF(SUPPORT_WFUNCTION)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-function")
ENDIF(SUPPORT_WFUNCTION)
IF(SUPPORT_WUNUSED_VAR)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-variable")
ENDIF(SUPPORT_WUNUSED_VAR)
IF(SUPPORT_WPOINTER_SIGN)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-pointer-sign")
ENDIF(SUPPORT_WPOINTER_SIGN)
IF(SUPPORT_WSIGN_COMPARE)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-sign-compare")
ENDIF(SUPPORT_WSIGN_COMPARE)
IF(SUPPORT_WSTRICT_PROTOTYPES)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wstrict-prototypes")
ENDIF(SUPPORT_WSTRICT_PROTOTYPES)
IF(SUPPORT_STD_FLAG)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -std=c99")
ENDIF(SUPPORT_STD_FLAG)

# Optimization flags
IF(NOT CMAKE_C_OPT_FLAGS)
	IF(ENABLE_OPTIMIZATION MATCHES "ON")
		SET(CMAKE_C_OPT_FLAGS "-O3 -fstrict-aliasing")
	ELSE(ENABLE_OPTIMIZATION MATCHES "ON")
		SET(CMAKE_C_OPT_FLAGS "-O0 -fstrict-aliasing")
	ENDIF(ENABLE_OPTIMIZATION MATCHES "ON")
ENDIF(NOT CMAKE_C_OPT_FLAGS)

IF(DEBUG_MODE MATCHES "ON")
	SET(CMAKE_BUILD_TYPE "Debug")
ENDIF(DEBUG_MODE MATCHES "ON")

SET(CMAKE_C_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS} ${CMAKE_C_WARN_FLAGS}")

CHECK_INCLUDE_FILES(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES(sys/time.h  HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(sys/uio.h   HAVE_SYS_UIO_H)

CHECK_INCLUDE_FILES(fcntl.h     HAVE_FCNTL_H)
CHECK_INCLUDE_FILES(math.h      HAVE_MATH_H)
CHECK_INCLUDE_FILES(stdio.h     HAVE_STDIO_H)
CHECK_INCLUDE_FILES(stdlib.h    HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(string.h    HAVE_STRING_H)
CHECK_INCLUDE_FILES(strings.h   HAVE_STRINGS_H)
CHECK_INCLUDE_FILES(time.h      HAVE_TIME_H)
CHECK_INCLUDE_FILES(unistd.h    HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(sysexits.h  HAVE_SYSEXITS_H)
CHECK_INCLUDE_FILES(stdint.h  HAVE_STDINT_H)
CHECK_INCLUDE_FILES(stdbool.h     HAVE_STBOOL_H)
CHECK_INCLUDE_FILES(inttypes.h  HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES(endian.h  HAVE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/endian.h  HAVE_SYS_ENDIAN_H)
CHECK_INCLUDE_FILES(machine/endian.h  HAVE_MACHINE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/queue.h  HAVE_SYS_QUEUE_H)
CHECK_INCLUDE_FILES(sys/socket.h  HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES(sys/mman.h  HAVE_SYS_MMAN_H)
CHECK_INCLUDE_FILES(sys/un.h  HAVE_SYS_UN_H)
CHECK_INCLUDE_FILES(sys/stat.h  HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES(sys/wait.h  HAVE_SYS_WAIT_H)
CHECK_INCLUDE_FILES(sys/param.h  HAVE_SYS_PARAM_H)
CHECK_INCLUDE_FILES(sys/cdefs.h  HAVE_SYS_CDEFS_H)
CHECK_INCLUDE_FILES(sys/file.h  HAVE_SYS_FILE_H)
CHECK_INCLUDE_FILES(sys/utsname.h  HAVE_SYS_UTSNAME_H)
CHECK_INCLUDE_FILES(sys/resource.h  HAVE_SYS_RESOURCE_H)
CHECK_INCLUDE_FILES(netinet/in.h  HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES(arpa/inet.h  HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES(netdb.h  HAVE_NETDB_H)
CHECK_INCLUDE_FILES(syslog.h HAVE_SYSLOG_H)
CHECK_INCLUDE_FILES(siginfo.h HAVE_SIGINFO_H)
CHECK_INCLUDE_FILES(sys/sendfile.h HAVE_SYS_SENDFILE_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)

CHECK_FUNCTION_EXISTS(sendfile HAVE_SENDFILE)
CHECK_FUNCTION_EXISTS(mkstemp HAVE_MKSTEMP)
CHECK_SYMBOL_EXISTS(PATH_MAX limits.h HAVE_PATH_MAX)
CHECK_SYMBOL_EXISTS(MAXPATHLEN sys/param.h HAVE_MAXPATHLEN)
CHECK_SYMBOL_EXISTS(MAP_SHARED sys/mman.h HAVE_MMAP_SHARED)
CHECK_SYMBOL_EXISTS(MAP_ANON sys/mman.h HAVE_MMAP_ANON)
CHECK_SYMBOL_EXISTS(MAP_NOCORE sys/mman.h HAVE_MMAP_NOCORE)

################################ SOURCES SECTION ###########################
SET(RMILTERSRC
                compat/md5.c
                src/upstream.c
                src/util.c 
                src/regexp.c 
                src/libclamc.c 
                src/ratelimit.c 
                src/memcached.c 
                src/beanstalk.c 
                src/main.c 
                src/radix.c 
                src/awl.c 
                src/libspamd.c 
                src/greylist.c
                cfg_lex.c
                cfg_yacc.c
                src/cfg_file.c 
                src/rmilter.c)
IF(ENABLE_SPF MATCHES "ON")
    SET(RMILTERSRC ${RMILTERSRC}
                    src/spf.c)
ENDIF()

LIST(APPEND RMILTER_REQUIRED_LIBRARIES m)
LIST(APPEND RMILTER_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
CONFIGURE_FILE(config.h.in config.h)

ADD_EXECUTABLE(rmilter ${RMILTERSRC})
SET_TARGET_PROPERTIES(rmilter PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(rmilter ${RMILTER_REQUIRED_LIBRARIES})

##################### INSTALLATION ##########################################

# Binaries
INSTALL(TARGETS rmilter RUNTIME DESTINATION sbin)
INSTALL(FILES "doc/rmilter.8" DESTINATION ${MANDIR}/man8)
