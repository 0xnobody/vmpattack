#include "vm_handler.hpp"
#include "vm_instruction_set.hpp"
#include "vm_bridge.hpp"
#include "arithmetic_utilities.hpp"

namespace vmpattack
{
    // Decodes and updates the context to construct a vm_instruction describing the instruction's details.
    //
    vm_instruction vm_handler::decode( vm_context* context ) const
    {
        std::vector<uint64_t> operands;

        // Loop through the handler's operand information.
        //
        for ( auto const& [operand, expression] : instruction_info->operands )
        {
            uint64_t operand_value = context->fetch<uint64_t>( operand.byte_length );

            operand_value ^= dynamic_size_cast( context->rolling_key, operand.byte_length );
            operand_value = expression->compute( operand_value, operand.byte_length );
            context->rolling_key ^= operand_value;
            
            // Add the decrypted operand.
            //
            operands.push_back( operand_value );
        }

        return vm_instruction( this, operands );
    }


    // Construct a vm_handler from its instruction stream.
    // Updates vm_state if required by the descriptor.
    // If the operation fails, returns empty {}.
    //
    std::optional<std::unique_ptr<vm_handler>> vm_handler::from_instruction_stream( vm_state* initial_state, const instruction_stream* stream )
    {
        const vm_instruction_desc* matched_instruction_desc = nullptr;

        // Allocate the vm_instruction_info.
        //
        auto instruction_info = std::make_unique<vm_instruction_info>();

        // Copy the stream, to ensure we have a fresh query for each match.
        //
        instruction_stream copied_stream = *stream;

        // Enumerate instruction set.
        //
        for ( auto instruction_desc : all_virtual_instructions )
        {
            //
            // TODO: Only update vm_state if updates_state in desc flags.
            //

            // Attempt to match the instruction.
            //
            if ( instruction_desc->match( initial_state, &copied_stream, instruction_info.get() ) )
            {
                // If match successful, save the instruction descriptor and break out of
                // the loop.
                //
                matched_instruction_desc = instruction_desc;
                break;
            }

            // Refresh stream.
            //
            copied_stream = *stream;
        }

        // If no matching descriptor found, return empty.
        //
        if ( !matched_instruction_desc )
            return {};

        // If the matched instruction updates state and its updated state is non-null, copy it into the current
        // VM state.
        //
        if ( matched_instruction_desc->flags & vm_instruction_updates_state && instruction_info->updated_state )
            *initial_state = *instruction_info->updated_state;

        // If the instruction is a VMEXIT, the handler will not have a bridge as it has no 
        // forward handler to pass execution to. We can just return a handler with a null bridge.
        //
        if ( matched_instruction_desc->flags & vm_instruction_vmexit )
            return std::make_unique<vm_handler>( matched_instruction_desc, std::move( instruction_info ), stream->rva(), nullptr );

        // Attempt to construct a bridge from the end of the stream.
        // The end of the stream is used as, in VMProtect, the bridge always immediately
        // follows the handler, so since we already advanced the stream while matching,
        // it should now be at the beginning of the bridge.
        //
        auto bridge = vm_bridge::from_instruction_stream( initial_state, &copied_stream );

        // If failed to construct bridge, return empty.
        //
        if ( !bridge )
            return {};

        // Everything was successful - we can now construct the actual vm_handler from the
        // information extracted.
        //
        return std::make_unique<vm_handler>( matched_instruction_desc, std::move( instruction_info ), stream->rva(), std::move( *bridge ) );
    }
}