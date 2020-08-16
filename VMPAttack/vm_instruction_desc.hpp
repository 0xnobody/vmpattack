#pragma once
#include <vtil/arch>
#include "vm_instruction.hpp"

namespace vmpattack
{
    class instruction_stream;
    struct vm_state;
    struct vm_instruction_info;

    // Describes flags for information required by the instruction parser.
    //
    enum vm_instruction_flags : uint32_t
    {
        // None.
        //
        vm_instruction_none = 0,

        // The virtual instruction causes the VIP to be modified.
        //
        vm_instruction_branch = 1 << 0,

        // The virtual instruction causes the VM to exit the virtual context.
        //
        vm_instruction_vmexit = 1 << 1,

        // The virtual instruction updates the vm state.
        //
        vm_instruction_updates_state = 1 << 3,

        // The virtual instruction acts creates a new basic block, but does not branch.
        //
        vm_instruction_creates_basic_block = 1 << 4,
    };

    // This struct describes a virtual machine instruction and its
    // semantics.
    //
    struct vm_instruction_desc
    {
        // Function prototype used to match an instruction stream to a virtual instruction.
        // Returns whether or not the match succeeded, and if so, updates the vm_state to
        // the state after instruction execution, and sets vm_instruction_info based on the
        // instruction instance information.
        //
        using fn_match = bool( * )( const vm_state* state, instruction_stream* stream, vm_instruction_info* info );

        // Function prototype used to generate VTIL given a virtual instruction.
        //
        using fn_generate = void( * )( vtil::basic_block* block, const vm_instruction* instruction );

        // The user-friendly name of the instruction.
        //
        const std::string name;

        // The number of operands the instruction takes in.
        //
        const uint32_t operand_count;

        // Any flags depicting special instruction behaviours.
        //
        const uint32_t flags;

        // The match delegate.
        //
        const fn_match match;

        // The generate delegate.
        //
        const fn_generate generate;

        // Constructor.
        //
        vm_instruction_desc( const std::string& name, uint32_t operand_count, uint32_t flags, fn_match match, fn_generate generate )
            : name( name ), operand_count( operand_count ), flags( flags ), match( match ), generate( generate )
        {}
    };
}