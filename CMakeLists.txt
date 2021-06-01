project(NetworkManager-f5vpn)
cmake_minimum_required(VERSION 2.8.10)

option(WITH_NM_PLUGIN "Compile the NetworkManager plugin" ON)
option(WITH_CLI_TOOL "Compile the command-line VPN client" OFF)
option(WITH_DEBUG "Enable debug printfs" OFF)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -Og -D_FORTIFY_SOURCE=2 -Wall -Wextra -Wformat -pedantic -Werror")

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED glib-2.0)
find_package(LibXml2 REQUIRED)
find_package(CURL REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
pkg_check_modules(NM REQUIRED libnm)

if(WITH_DEBUG)
    set(DEBUG_COMPILE_DEFINITIONS "-DWITH_DEBUG")
endif()

add_library(glib_curl STATIC lib/glib_curl.c)
target_include_directories(glib_curl PUBLIC ${GLIB_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})
target_link_libraries(glib_curl PUBLIC ${GLIB_LIBRARIES} ${CURL_LIBRARIES})

add_library(f5vpn_auth STATIC lib/f5vpn_auth.c)
target_compile_definitions(f5vpn_auth PRIVATE ${DEBUG_COMPILE_DEFINITIONS})
target_include_directories(f5vpn_auth PRIVATE ${LIBXML2_INCLUDE_DIRS})
target_include_directories(f5vpn_auth PUBLIC include)
target_link_libraries(f5vpn_auth PUBLIC glib_curl ${LIBXML2_LIBRARIES})

add_library(f5vpn_connect STATIC lib/f5vpn_connect.c)
target_compile_definitions(f5vpn_connect PRIVATE ${DEBUG_COMPILE_DEFINITIONS} -D_GNU_SOURCE -DPPPD_PLUGIN=${CMAKE_INSTALL_PREFIX}/lib/$<TARGET_FILE_NAME:pppd-plugin-f5vpn>)
target_include_directories(f5vpn_connect PRIVATE ${LIBXML2_INCLUDE_DIRS})
target_link_libraries(f5vpn_connect PUBLIC glib_curl ${LIBXML2_LIBRARIES} util)
target_include_directories(f5vpn_connect PUBLIC include)

add_library(pppd-plugin-f5vpn SHARED pppd/pppd-f5-vpn.c)
target_include_directories(pppd-plugin-f5vpn PRIVATE include)
install(TARGETS pppd-plugin-f5vpn LIBRARY DESTINATION lib)

if(WITH_NM_PLUGIN)
    add_executable(nm-f5vpn-auth-dialog auth-dialog/nm-f5vpn-auth-dialog.c)
    target_include_directories(nm-f5vpn-auth-dialog PRIVATE ${GTK3_INCLUDE_DIRS} ${NM_INCLUDE_DIRS})
    target_link_libraries(nm-f5vpn-auth-dialog f5vpn_auth ${GTK3_LIBRARIES} ${NM_LIBRARIES})
    install(TARGETS nm-f5vpn-auth-dialog RUNTIME DESTINATION lib)

    add_executable(nm-f5vpn-service service/nm-f5vpn-service.c)
    target_include_directories(nm-f5vpn-service PRIVATE ${NM_INCLUDE_DIRS})
    target_link_libraries(nm-f5vpn-service f5vpn_connect ${NM_LIBRARIES})
    install(TARGETS nm-f5vpn-service RUNTIME DESTINATION lib)

    add_library(nm-vpn-plugin-f5vpn SHARED plugin/nm-vpn-plugin-f5.c plugin/nm-f5vpn-editor.c)
    target_include_directories(nm-vpn-plugin-f5vpn PRIVATE ${GTK3_INCLUDE_DIRS} ${NM_INCLUDE_DIRS})
    install(TARGETS nm-vpn-plugin-f5vpn LIBRARY DESTINATION lib/NetworkManager)

    install(FILES conf/nm-f5vpn-service.name DESTINATION lib/NetworkManager/VPN)
    install(FILES conf/nm-f5vpn-service.conf DESTINATION share/dbus-1/system.d)
endif()

if(WITH_CLI_TOOL)
    add_executable(f5vpn-cli cli/main.c)
    target_compile_options(f5vpn-cli PRIVATE -D_GNU_SOURCE)
    target_link_libraries(f5vpn-cli PRIVATE f5vpn_auth f5vpn_connect)
endif()
