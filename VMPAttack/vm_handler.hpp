#pragma once
#include <cstdint>
#include <memory>
#include "vm_instruction_desc.hpp"
#include "vm_state.hpp"
#include "vm_instruction_info.hpp"
#include "vm_bridge.hpp"

namespace vmpattack
{
    // This struct describes any virtual machine handler, responsible for executing an 
    // instruction.
    //
    struct vm_handler
    {
        // The handler's RVA in the loaded image.
        //
        const uint64_t rva;

        // The backing instruction descriptor.
        //
        const vm_instruction_desc* descriptor;

        // The instance's instruction information.
        //
        const std::unique_ptr<vm_instruction_info> instruction_info;

        // The handler's bridge.
        //
        const std::unique_ptr<vm_bridge> bridge;

        // Constructor.
        //
        vm_handler( const vm_instruction_desc* descriptor, std::unique_ptr<vm_instruction_info> instruction_info, uint64_t rva, std::unique_ptr<vm_bridge> bridge )
            : descriptor( descriptor ), instruction_info( std::move( instruction_info ) ), rva( rva ), bridge( std::move( bridge ) )
        {}

        // Decodes and updates the context to construct a vm_instruction describing the instruction's details.
        //
        vm_instruction decode( vm_context* context ) const;

        // Construct a vm_handler from its instruction stream.
        // Updates vm_state if required by the descriptor.
        // If the operation fails, returns empty {}.
        //
        static std::optional<std::unique_ptr<vm_handler>> from_instruction_stream( vm_state* initial_state, const instruction_stream* stream );
    };
}