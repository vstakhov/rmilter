############################# INITIAL SECTION #############################################

PROJECT(rmilter C)

SET(RMILTER_VERSION_MAJOR 1)
SET(RMILTER_VERSION_MINOR 6)
SET(RMILTER_VERSION_PATCH 3)

SET(RMILTER_VERSION         "${RMILTER_VERSION_MAJOR}.${RMILTER_VERSION_MINOR}.${RMILTER_VERSION_PATCH}")
SET(RMILTER_MASTER_SITE_URL "https://rspamd.com")

IF(NOT RMILTER_USER)
	SET(RMILTER_USER "nobody")
	SET(RMILTER_GROUP "nobody")
ENDIF()

IF(NOT SYSTEMDDIR)
	SET(SYSTEMDDIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
ENDIF(NOT SYSTEMDDIR)

IF(NOT SBINDIR)
	SET(SBINDIR "sbin")
ENDIF(NOT SBINDIR)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.0 FATAL_ERROR)

############################# OPTIONS SECTION #############################################

OPTION(DEBUG_MODE          "Enable debug output [default: ON]"                  ON)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: OFF]"                 OFF)
OPTION(ENABLE_DKIM         "Enable dkim signatures [default: OFF]"              OFF)
OPTION(ENABLE_SPF          "Enable SPF checks [default: OFF]"                   OFF)
OPTION(WANT_SYSTEMD_UNITS  "Install systemd unit files on Linux [default: OFF]" OFF)

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
	IF(NOT RMILTER_SEARCH_PATH)
	    PKG_SEARCH_MODULE(${var} "${_name0}" ${ARGN})
	    IF(${var}_FOUND)
	        SET(WITH_${var} 1)
	        IF(ENABLE_STATIC MATCHES "ON")
	            SET(_XPREFIX "${var}_STATIC")
	        ELSE(ENABLE_STATIC MATCHES "ON")
	            SET(_XPREFIX "${var}")
	        ENDIF(ENABLE_STATIC MATCHES "ON")
	        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
	            INCLUDE_DIRECTORIES("${_arg}")
	            SET(${var}_INCLUDE "${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
	        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
	            LINK_DIRECTORIES("${_arg}")
	            SET(${var}_LIBRARY "${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
	        # Handle other CFLAGS and LDFLAGS
	        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
	            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
	        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
	            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
	        LIST(APPEND RMILTER_REQUIRED_LIBRARIES "${${_XPREFIX}_LIBRARIES}")
	    ELSE(${var}_FOUND)
	 		# Try some more heuristic
			FIND_LIBRARY(_lib NAMES "${_name0}" ${ARGN}
						HINTS
						"${RMILTER_SEARCH_PATH}"
						PATH_SUFFIXES lib64 lib
						PATHS ${RMILTER_DEFAULT_LIBRARY_PATHS})
			IF(NOT _lib)
				MESSAGE(FATAL_ERROR "Packages ${_name0} ${ARGN} could not be found, no library")
			ENDIF(NOT _lib)
			
			FIND_PATH(_incl "${_name0}.h" 
							HINTS "${RMILTER_SEARCH_PATH}"
							PATH_SUFFIXES "include" "include/${_name0}" ${ARGN}
							PATHS 	${RMILTER_DEFAULT_INCLUDE_PATHS})
			IF(NOT _incl)
				MESSAGE(FATAL_ERROR "Packages ${_name0} ${ARGN} could not be found, no header")
			ENDIF(NOT _incl)
			
			GET_FILENAME_COMPONENT(_lib_path "${_lib}" PATH)
			INCLUDE_DIRECTORIES("${_incl}")
			LINK_DIRECTORIES("${_lib_path}")
			LIST(APPEND RMILTER_REQUIRED_LIBRARIES ${_lib})
			SET(${var}_INCLUDE "${_incl}")
			SET(${var}_LIBRARY "${_lib_path}")
			MESSAGE(STATUS "Found ${_name0} ${ARGN} in '${_lib_path}' (library) and '${_incl}' (include).")
		ENDIF(${var}_FOUND)
	ELSE(NOT RMILTER_SEARCH_PATH)
 		# Try heuristic first
		FIND_LIBRARY(_lib NAMES "${_name0}" ${ARGN}
					HINTS
					"${RMILTER_SEARCH_PATH}"
					PATH_SUFFIXES lib64 lib
					PATHS ${RMILTER_DEFAULT_LIBRARY_PATHS})
		IF(_lib)
			FIND_PATH(_incl "${_name0}.h" 
							HINTS "${RMILTER_SEARCH_PATH}"
							PATH_SUFFIXES "include" "include/${_name0}" ${ARGN}
							PATHS 	${RMILTER_DEFAULT_INCLUDE_PATHS})
			IF(_incl)
				GET_FILENAME_COMPONENT(_lib_path "${_lib}" PATH)
				INCLUDE_DIRECTORIES("${_incl}")
				LINK_DIRECTORIES("${_lib_path}")
				MESSAGE(STATUS "Found ${_name0} ${ARGN} in '${_lib_path}' (library) and '${_incl}' (include).")
				SET(${var}_INCLUDE "${_incl}")
				SET(${var}_LIBRARY "${_lib_path}")
				LIST(APPEND RMILTER_REQUIRED_LIBRARIES ${_lib})
			ENDIF(_incl)
		ENDIF(_lib)
		
		IF(NOT _incl OR NOT _lib)
			PKG_SEARCH_MODULE(${var} "${_name0}" ${ARGN})
		    IF(${var}_FOUND)
		        SET(WITH_${var} 1)
		        IF(ENABLE_STATIC MATCHES "ON")
		            SET(_XPREFIX "${var}_STATIC")
		        ELSE(ENABLE_STATIC MATCHES "ON")
		            SET(_XPREFIX "${var}")
		        ENDIF(ENABLE_STATIC MATCHES "ON")
		        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
		            INCLUDE_DIRECTORIES("${_arg}")
		            SET(${var}_INCLUDE "${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
		        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
		            LINK_DIRECTORIES("${_arg}")
		            SET(${var}_LIBRARY "${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
		        # Handle other CFLAGS and LDFLAGS
		        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
		            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
		        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
		            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
		        LIST(APPEND RMILTER_REQUIRED_LIBRARIES "${${_XPREFIX}_LIBRARIES}")
			ELSE(${var}_FOUND)
				MESSAGE(FATAL_ERROR "Packages ${_name0} ${ARGN} could not be found")
			ENDIF(${var}_FOUND)
		ENDIF(NOT _incl OR NOT _lib)
	ENDIF(NOT RMILTER_SEARCH_PATH)
	# Cleanup
	UNSET(_lib CACHE)
	UNSET(_incl CACHE)
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

ProcessPackage(PCRE libpcre libpcre3 pcre pcre3)
IF(NOT PCRE_FOUND)
    FIND_LIBRARY(LIBPCRE_LIBRARY NAMES pcre PATH_SUFFIXES lib64 lib lib/libpcre lib64/lipcre
                      PATHS
                          ~/Library/Frameworks
                          /Library/Frameworks
                          /usr/local
                          /usr
                          /sw
                          /opt/local
                          /opt/csw
                          /opt
                     DOC "Path where the pcre library can be found")
    
    FIND_PATH(LIBPCRE_INCLUDE pcre.h PATH_SUFFIXES include include/pcre3 
                    PATHS   ~/Library/Frameworks
                          /Library/Frameworks
                          /usr/local
                          /usr
                          /sw
                          /opt/local
                          /opt/csw
                          /opt
                    DOC "Path where the pcre header files can be found")
    IF(NOT LIBPCRE_LIBRARY OR NOT LIBPCRE_INCLUDE)
    	MESSAGE(FATAL_ERROR "libpcre is required for building rmilter")
    ENDIF()
    LIST(APPEND RMILTER_REQUIRED_LIBRARIES "pcre")
    
    GET_FILENAME_COMPONENT(LIBPCRE_PATH "${LIBPCRE_LIBRARY}" PATH)
    INCLUDE_DIRECTORIES("${LIBPCRE_INCLUDE}")
    LINK_DIRECTORIES("${LIBPCRE_PATH}")
ENDIF(NOT PCRE_FOUND)

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
                compat/blake2b-ref.c
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
INSTALL(TARGETS rmilter RUNTIME DESTINATION ${SBINDIR})
INSTALL(FILES "doc/rmilter.8" DESTINATION ${MANDIR}/man8)

# systemd unit
IF(WANT_SYSTEMD_UNITS MATCHES "ON")
	INSTALL(FILES "rmilter.service" DESTINATION ${SYSTEMDDIR})
ENDIF()