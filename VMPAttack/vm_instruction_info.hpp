#pragma once
#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include "vm_state.hpp"
#include "arithmetic_expression.hpp"

namespace vmpattack
{
    // The type of the operand.
    //
    enum vm_operand_type
    {
        // Immediate.
        //
        vm_operand_imm,

        // Register (context offset).
        //
        vm_operand_reg,
    };

    // Describes a single virtual instruction operand.
    //
    struct vm_operand
    {
        // The type of this operand.
        //
        vm_operand_type type;

        // The execution size of this operand.
        // e.g. an 8 byte register would be 8.
        //
        size_t size;

        // The byte length of this operand ie. how many vip bytes it consumes.
        // e.g. an 8 byte register would be 2, as the index occupies 2 bytes.
        //
        size_t byte_length;

        // Constructor.
        //
        vm_operand( vm_operand_type type, size_t size, size_t byte_length )
            : type( type ), size( size ), byte_length( byte_length )
        {}
    };

    // This struct describes the virtual instruction's instace information.
    // It describes properties such as the operands and sizes.
    // It does not hold any VIP-derived information.
    //
    struct vm_instruction_info
    {
        // A map of operand information with their corresponding arithmetic expression used for
        // obfuscation.
        //
        std::vector<std::pair<vm_operand, std::unique_ptr<arithmetic_expression>>> operands;

        // A vector of arbitrary sizes, determined during matching phase and
        // used during generation phase.
        //
        std::vector<size_t> sizes;

        // Instruction-specific data.
        //
        vtil::variant custom_data;

        // If the instruction updates the state, the updated state after instruction execution is
        // stored here.
        //
        std::optional<vm_state> updated_state;

        // Empty constructor.
        //
        vm_instruction_info()
            : operands{}, sizes{}
        {}

        // Construct via initial operand list.
        //
        vm_instruction_info( std::vector<std::pair<vm_operand, std::unique_ptr<arithmetic_expression>>> operands )
            : operands( std::move( operands ) ), sizes{}
        {}
    };
}