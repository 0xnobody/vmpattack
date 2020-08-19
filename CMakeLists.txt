cmake_minimum_required(VERSION 3.15)
project(VMPAttach)

include(FetchContent)

FetchContent_Declare(
    VTIL-Core
    GIT_REPOSITORY https://github.com/vtil-project/VTIL-Core
    GIT_SHALLOW    true
)
FetchContent_MakeAvailable(VTIL-Core)

add_subdirectory(VMPAttack)