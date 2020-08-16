#include "arithmetic_operation.hpp"
#include "arithmetic_operations.hpp"

namespace vmpattack
{
    // Construct via instruction and descriptor.
    // If construction failed, returns empty object.
    //
    std::optional<arithmetic_operation> arithmetic_operation::from_instruction( const arithmetic_operation_desc* descriptor, const instruction* instruction )
    {
        std::vector<uint64_t> imm_operands;

        // The first operand is always the target operand. We need
        // to generate the additional operand vector, so we only loop
        // through these.
        //
        for ( int i = 1; i < instruction->operand_count(); i++ )
        {
            auto operand = instruction->operand( i );

            // Only immediate additional operands are supported, to make
            // this process simpler.
            //
            if ( operand.type != X86_OP_IMM )
                return {};

            // Append to vector.
            //
            imm_operands.push_back( operand.imm );
        }

        return arithmetic_operation( descriptor, imm_operands );
    }

    // Construct via instruction.
    // If construction failed, returns empty object.
    //
    std::optional<arithmetic_operation> arithmetic_operation::from_instruction( const instruction* instruction )
    {
        if ( auto descriptor = operation_desc_from_instruction( instruction ) )
        {
            return from_instruction( descriptor, instruction );
        }

        return {};
    }
}