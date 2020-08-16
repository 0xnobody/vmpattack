#include "analysis_context.hpp"
#include "arithmetic_operations.hpp"
#include <vtil/amd64>

namespace vmpattack
{
    // Processes the instruction, updating any properties that the instruction
    // may change.
    //
    void analysis_context::process( const instruction* instruction )
    {
        // If the expression is valid, attempt to record the current instruction
        // in the expression
        //
        if ( expression )
        {
            // Try to get operation descriptor for the current instruction
            //
            if ( auto operation_desc = operation_desc_from_instruction( instruction ) )
            {
                uint8_t read_count = 0, write_count = 0;
                cs_regs read_regs, write_regs;

                // Fetch registers read/written to by instruction
                //
                cs_regs_access( disassembler::get().get_handle(), &instruction->ins, read_regs, &read_count, write_regs, &write_count );

                // Flip flag if expression target register is being written to
                //
                bool writes_to_reg = false;
                for ( int i = 0; i < write_count; i++ )
                {
                    if ( register_base_equal( ( x86_reg )write_regs[ i ], expression_register ) )
                    {
                        writes_to_reg = true;
                        break;
                    }
                }

                // If it does write to the register, add it to the expression
                //
                if ( writes_to_reg )
                {
                    if ( auto operation = arithmetic_operation::from_instruction( instruction ) )
                        expression->operations.push_back( *operation );

                }
            }
        }

        // If we are currently tracking any registers (ie. tracked register is not empty) attempt
        // to update them using the current instruction.
        //
        if ( tracked_registers.size() > 0
          && ( instruction->ins.id == X86_INS_MOV
          || instruction->ins.id == X86_INS_XCHG ) )
        {
            // If both operands are registers.
            //
            if ( instruction->operand( 0 ).type == X86_OP_REG
              && instruction->operand( 1 ).type == X86_OP_REG )
            {
                // Loop through tracked registers vector.
                //
                for ( x86_reg* tracked_reg : tracked_registers )
                {
                    if ( instruction->ins.id == X86_INS_MOV )
                    {
                        // operand( 0 ) = operand( 1 )
                        //
                        if ( instruction->operand( 1 ).reg == *tracked_reg )
                            *tracked_reg = instruction->operand( 0 ).reg;
                    }
                    else if ( instruction->ins.id == X86_INS_XCHG )
                    {
                        // operand ( 0 ) = operand( 1 ) && operand( 1 ) = operand( 0 )
                        //
                        if ( instruction->operand( 0 ).reg == *tracked_reg )
                            *tracked_reg = instruction->operand( 1 ).reg;
                        else if ( instruction->operand( 1 ).reg == *tracked_reg )
                            *tracked_reg = instruction->operand( 0 ).reg;
                    }
                }
            }
        }

        // If we are currently tracking stack pushes, update them.
        //
        if ( pushed_registers )
        {
            if ( instruction->ins.id == X86_INS_PUSH
              && instruction->operand( 0 ).type == X86_OP_REG )
                pushed_registers->push_back( instruction->operand( 0 ).reg );
            else if ( instruction->ins.id == X86_INS_PUSHFQ
                   || instruction->ins.id == X86_INS_PUSHFD
                   || instruction->ins.id == X86_INS_PUSHF )
                pushed_registers->push_back( X86_REG_EFLAGS );
        }

        // If we are currently tracking stack pops, update them.
        //
        if ( popped_registers )
        {
            if ( instruction->ins.id == X86_INS_POP
                 && instruction->operand( 0 ).type == X86_OP_REG )
                popped_registers->push_back( instruction->operand( 0 ).reg );
            else if ( instruction->ins.id == X86_INS_POPFQ
                      || instruction->ins.id == X86_INS_POPFD
                      || instruction->ins.id == X86_INS_POPF )
                popped_registers->push_back( X86_REG_EFLAGS );
        }
    }
}