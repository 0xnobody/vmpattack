#include "vm_instruction.hpp"
#include "vm_handler.hpp"
#include <vector>
#include <sstream>

namespace vmpattack
{
    // Converts the instruction to human-readable format.
    //
    std::string vm_instruction::to_string() const
    {
        std::stringstream name_stream;
        
        name_stream << handler->descriptor->name;
        name_stream << "\t";

        // Loop through each of the handler's operands.
        //
        for ( int i = 0; i < operands.size(); i++ )
        {
            // Fetch operand and its value.
            //
            vm_operand& operand = handler->instruction_info->operands[ i ].first;
            uint64_t operand_value = operands[ i ];

            switch ( operand.type )
            {
                case vm_operand_imm:
                    name_stream << std::hex << operand.size << ":0x" << operand_value;
                    break;
                case vm_operand_reg:
                    name_stream << "REG:" << operand.size << ":0x" << std::hex << operand_value;
                    break;
            }

            // Is last operand?
            //
            if ( i != operands.size() - 1 )
                name_stream << ",\t";
        }

        // Form string from stringstream.
        //
        return name_stream.str();
    }

    // Construct vm_instruction from its handler and a context.
    //
    std::unique_ptr<vm_instruction> vm_instruction::from_context( const vm_handler* handler, vm_context* context )
    {
        std::vector<uint64_t> decrypted_operands;

        // Loop through each of the handler's operands.
        //
        for ( auto& operand : handler->instruction_info->operands )
        {
            // Fetch the byte_length from the context.
            //
            uint64_t fetched_operand = context->fetch<uint64_t>( operand.first.byte_length );

            // Decrypt the fetched operand bytes with its expression.
            //
            fetched_operand = operand.second->compute( fetched_operand );

            // Add to vector.
            //
            decrypted_operands.push_back( fetched_operand );
        }

        // Construct object.
        //
        return std::make_unique<vm_instruction>( handler, decrypted_operands );
    }
}