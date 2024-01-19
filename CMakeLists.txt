cmake_minimum_required(VERSION 3.5)

project(NKTools LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(BOTAN REQUIRED botan-3)

find_package(glaze QUIET)
if(NOT glaze_FOUND)
    include(FetchContent)

    FetchContent_Declare(
      glaze
      GIT_REPOSITORY https://github.com/stephenberry/glaze.git
      GIT_TAG main
      GIT_SHALLOW TRUE
    )

    FetchContent_MakeAvailable(glaze)
endif()

add_executable(NKTools
    src/main.cpp
    src/algorithm_dgdata/dgdata.h src/algorithm_dgdata/dgdata.cpp
    src/algorithm_nksave/nksave.h src/algorithm_nksave/nksave.cpp
    src/algorithm_nksave/rfc2898derivebytes.h src/algorithm_nksave/rfc2898derivebytes.cpp
    src/algorithm_nksave/savedata.h src/algorithm_nksave/savedata.cpp
)

target_include_directories(NKTools PRIVATE src ${BOTAN_INCLUDE_DIRS})
target_link_libraries(NKTools PRIVATE ${BOTAN_LIBRARIES} glaze::glaze)

include(GNUInstallDirs)
install(TARGETS NKTools
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
