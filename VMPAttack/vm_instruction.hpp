#pragma once
#include "vm_instruction_info.hpp"
#include "vm_context.hpp"

namespace vmpattack
{
    struct vm_handler;

    // This struct represents a fully-formed virtual instruction instance, containing all decoded
    // information required for full execution, including VIP-derived information.
    //
    struct vm_instruction
    {
        // A non-owning pointer to the instruction's fully-formed handler.
        //
        const vm_handler* handler;

        // A vector containing the instruction's operands.
        // NOTE: even though this is just a vector of uint64_t's, these can represent any size
        // (e.g. 1/2/4 bytes) and can be register offsets or immediate values depending on the
        // vm_instruction_info in the handler.
        //
        const std::vector<uint64_t> operands;

        // Constructor.
        //
        vm_instruction( const vm_handler* handler, const std::vector<uint64_t>& operands )
            : handler( handler ), operands( operands )
        {}

        // Converts the instruction to human-readable format.
        //
        std::string to_string() const;

        // Construct vm_instruction from its handler and a context.
        //
        static std::unique_ptr<vm_instruction> from_context( const vm_handler* handler, vm_context* context );
    };
}