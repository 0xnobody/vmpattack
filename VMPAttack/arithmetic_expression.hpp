#pragma once
#include <vector>
#include "arithmetic_operation.hpp"

namespace vmpattack
{
    // This struct describes an expression instance containing numerous arithmetic_operation's
    // in a specific order. It allows for computation of an output given an input value.
    //
    struct arithmetic_expression
    {
        // An ordered vector of operations.
        //
        std::vector<arithmetic_operation> operations;

        // Compute the output for a given input, by applying each operation on said input.
        //
        uint64_t compute( uint64_t input, size_t byte_count = 8 ) const;
    };
}