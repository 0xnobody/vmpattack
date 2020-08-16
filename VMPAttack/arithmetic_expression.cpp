#include "arithmetic_expression.hpp"
#include "arithmetic_utilities.hpp"

namespace vmpattack
{
    // Compute the output for a given input, by applying each operation on said input.
    //
    uint64_t arithmetic_expression::compute( uint64_t input, size_t byte_count ) const
    {
        uint64_t output = input;

        // Loop through each operation in order.
        //
        for ( auto& operation : operations )
        {
            // Update the ouput, specifying the previous expression's output as the current input.
            //
            output = operation.descriptor->transform( output, operation.additional_operands.data() );

            // Size-cast the output.
            //
            output = dynamic_size_cast( output, byte_count );
        }

        return output;
    }
}