#pragma once
#include <cstdint>
#include <capstone/capstone.h>
#include <vtil/utility>

namespace vmpattack
{
    // This struct describes an arithmetic operation descriptor, outlining
    // any of its semantics.
    //
    struct arithmetic_operation_desc
    {
        // Tranform function, taking inputs, transforming them as per
        // operation semantic, and returning the final output value.
        //
        using fn_transform = uint64_t( * )( uint64_t input, const uint64_t additional_operands[] );
    
        // The instruction correspoinding to the operation.
        // NOTE: this is not nessecarily unique per operation.
        //
        x86_insn insn;

        // The number of additional operands, NOT INCLUDING the main input.
        // e.g. `neg rax` = 0
        // e.g. `xor rax, 0Ah` = 1
        //
        uint8_t num_additional_operands;

        // The transformation function.
        //
        fn_transform transform;

        // The operation input size, in bits, or none if not relevant.
        //
        std::optional<bitcnt_t> input_size;

        // Constructor.
        //
        arithmetic_operation_desc( x86_insn insn, uint8_t num_additional_operands, fn_transform transform, std::optional<bitcnt_t> input_size = {} )
            : insn( insn ), num_additional_operands( num_additional_operands ), transform( transform ), input_size( input_size )
        {}
    };
}