add_executable(VMPAttack
    analysis_context.cpp
    analysis_context.hpp
    arithmetic_expression.cpp
    arithmetic_expression.hpp
    arithmetic_operation.cpp
    arithmetic_operation_desc.hpp
    arithmetic_operation.hpp
    arithmetic_operations.hpp
    arithmetic_utilities.hpp
    disassembler.cpp
    disassembler.hpp
    flags.hpp
    instruction.cpp
    instruction.hpp
    instruction_stream.cpp
    instruction_stream.hpp
    instruction_utilities.hpp
    main.cpp
    vm_analysis_context.hpp
    vm_bridge.cpp
    vm_bridge.hpp
    vm_context.hpp
    vmentry.hpp
    vm_handler.cpp
    vm_handler.hpp
    vm_instance.cpp
    vm_instance.hpp
    vm_instruction.cpp
    vm_instruction_desc.hpp
    vm_instruction.hpp
    vm_instruction_info.hpp
    vm_instruction_set.hpp
    vmpattack.cpp
    vmpattack.hpp
    vm_state.hpp
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(VMPAttack PRIVATE VTIL Threads::Threads)