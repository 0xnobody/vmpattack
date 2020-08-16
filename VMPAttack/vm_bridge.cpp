#include "vm_bridge.hpp"
#include "vm_analysis_context.hpp"

namespace vmpattack
{
    // Computes the next handler from the bridge, updating the context in respect.
    // Returns the next handler's rva.
    //
    uint64_t vm_bridge::advance( vm_context* context ) const
    {
        // XOR the encrypted next handler offset by the rolling key.
        //
        uint32_t next_handler = context->fetch<uint32_t>( 4 ) ^ ( uint32_t )context->rolling_key;

        // Decrypt the next handler via the arith expression.
        //
        next_handler = ( uint32_t )handler_expression->compute( next_handler );

        // Update rolling key.
        //
        context->rolling_key ^= next_handler;

        // Emulate movsxd.
        //
        struct { int64_t sign : 32; } s;
        s.sign = next_handler;

        // Update flow.
        //
        context->state->flow += s.sign;

        // Flow contains next handler ea.
        //
        return context->state->flow;
    }

    // Construct a vm_bridge from an initial state and its instruction stream.
    // If the operation fails, returns empty {}.
    //
    std::optional<std::unique_ptr<vm_bridge>> vm_bridge::from_instruction_stream( const vm_state* state, const instruction_stream* stream )
    {
        // Copy stream to drop the const.
        //
        instruction_stream copied_stream = *stream;

        // Initialize empty expression.h
        //
        std::unique_ptr<arithmetic_expression> bridge_expression = std::make_unique<arithmetic_expression>();

        vm_analysis_context bridge_analysis_context = vm_analysis_context( &copied_stream, state );

        x86_reg fetch_reg;
        size_t fetch_reg_size = 4;

        x86_reg rolling_key_reg = state->rolling_key_reg;

        auto result = ( &bridge_analysis_context )
            ->fetch_vip( { fetch_reg, false }, { fetch_reg_size, true } )
            ->xor_reg_reg( { fetch_reg, true }, { rolling_key_reg, true } )
            ->record_expression( fetch_reg, bridge_expression.get(), [&]()
                                 {
                                     return ( &bridge_analysis_context )
                                         ->id( X86_INS_PUSH );
                                 } );

        // If information fetch failed, return empty {}.
        //
        if ( !result )
            return {};

        // Construct actual vm_bridge from the information.
        //
        return std::make_unique<vm_bridge>( copied_stream.base(), std::move( bridge_expression ) );
    }
}