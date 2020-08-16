#pragma once
#include <optional>
#include "arithmetic_operation_desc.hpp"
#include "instruction.hpp"

namespace vmpattack
{
    // This struct describes an arithmetic operation instance, containing
    // a backing descriptor and any operand arguments.
    //
    struct arithmetic_operation
    {
        // The backing operation descriptor.
        //
        const arithmetic_operation_desc* descriptor;

        // Any additional argument operands in order.
        //
        const std::vector<uint64_t> additional_operands;

        // Construct via backing descriptor and additional operand vector.
        //
        arithmetic_operation( const arithmetic_operation_desc* descriptor, const std::vector<uint64_t>& additional_operands )
            : descriptor( descriptor ), additional_operands( additional_operands )
        {}

        // Construct via instruction and descriptor.
        // If construction failed, returns empty object.
        //
        static std::optional<arithmetic_operation> from_instruction( const arithmetic_operation_desc* descriptor, const instruction* instruction );

        // Construct via instruction only.
        // If construction failed, returns empty object.
        //
        static std::optional<arithmetic_operation> from_instruction( const instruction* instruction );
    };
}