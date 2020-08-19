#include "vm_instance.hpp"
#include "analysis_context.hpp"

namespace vmpattack
{
    // Creates an initial vm_context for this instance, given an entry stub and the image's load delta.
    // The created vm_context is initialized at the first handler in the vip stream.
    //
    std::unique_ptr<vm_context> vm_instance::initialize_context( uint64_t stub, int64_t load_delta ) const
    {
        // Decrypt the stub to get the unbased (with orig imagebase) vip address.
        // Stub EA must always be cast to 32 bit.
        // Add the const 0x100000000 to the result.
        //
        uint64_t vip = ( uint32_t )vip_expression->compute( stub ) + 0x100000000;

        // Get the absolute vip ea by adding the load delta.
        //
        uint64_t absolute_vip = vip + load_delta;

        // Copy the initial state for vm_context creation.
        //
        auto copied_initial_state = std::make_unique<vm_state>( *initial_state );

        // Create a new vm_context and return it.
        // The rolling key is the pre-offsetted vip.
        //
        return std::make_unique<vm_context>( std::move( copied_initial_state ), vip, absolute_vip );
    }

    // Adds a handler to the vm_instace.
    //
    void vm_instance::add_handler( std::unique_ptr<vm_handler> handler )
    {
        // Lock the mutex.
        //
        const std::lock_guard<std::mutex> lock( handlers_mutex );

        // Push back the handler.
        //
        handlers.push_back( std::move( handler ) );
    }

    // Attempts to find a handler, given an rva.
    //
    std::optional<vm_handler*> vm_instance::find_handler( uint64_t rva )
    {
        // Lock the mutex.
        //
        const std::lock_guard<std::mutex> lock( handlers_mutex );

        // Loop through owned handlers.
        //
        for ( auto& handler : handlers )
        {
            // If the rva matches, return a non-owning pointer to said handler.
            //
            if ( handler->rva == rva )
                return handler.get();
        }

        // If not found return empty {}.
        //
        return {};
    }

    // Attempts to construct a vm_instance from the VMEntry instruction stream.
    // If fails, returns empty {}.
    //
    std::optional<std::unique_ptr<vm_instance>> vm_instance::from_instruction_stream( const instruction_stream* stream )
    {
        // Copy the stream to drop the const.
        //
        instruction_stream copied_stream = *stream;

        // Create analysis context.
        //
        analysis_context entry_analysis_context = analysis_context( &copied_stream );

        std::unique_ptr<arithmetic_expression> vip_expression = std::make_unique<arithmetic_expression>();

        x86_insn vip_offset_ins;
        x86_reg vip_reg;
        x86_reg vip_offset_reg;
        uint64_t vip_stack_offset;

        x86_reg rsp = X86_REG_RSP;
        x86_reg stack_reg;
        uint64_t stack_alloc_size;

        x86_reg flow_reg;
        uint64_t flow_rva;

        x86_reg rolling_key_reg;

        std::vector<x86_reg> pushed_regs;

        auto result = ( &entry_analysis_context )
            ->track_register_pushes( &pushed_regs, [&]()
                                     {
                                         return ( &entry_analysis_context )
                                             ->fetch_encrypted_vip( { vip_reg, false }, { vip_stack_offset, false } );
                                     } )
            ->record_expression( vip_reg, vip_expression.get(), [&]() 
                                 {
                                     return ( &entry_analysis_context )
                                         ->offset_reg( { vip_offset_ins, false }, { vip_reg, true }, { vip_offset_reg, false } );
                                 } )
            ->mov_reg_reg( { stack_reg, false }, { rsp, true }, false )
            ->allocate_stack( { stack_alloc_size, false } )
            ->mov_reg_reg( { rolling_key_reg, false }, { vip_reg, true } )
            ->set_flow( { flow_reg, false }, { flow_rva, false } );

        // If information fetch failed, return empty {}.
        //
        if ( !result )
            return {};

        // We're gonna peek into the bridge instructions to see if the vip goes forwards or backwards.
        // So we have to copy the stream to not modify the previous one.
        //
        instruction_stream peek_stream = copied_stream;

        // Create a new analysis context from the newly copied stream.
        //
        analysis_context peek_analysis_context = analysis_context( &peek_stream );

        // The VIP is offseted by 4 at each handler; search for this so.
        //
        uint64_t vip_offset_size = 4;
        x86_insn update_vip_ins;

        auto bridge_result = peek_analysis_context
            .update_reg( { update_vip_ins, false }, { vip_reg, true }, { vip_offset_size, true } );

        // If nothing found, something went wrong; return empty {}.
        //
        if ( !bridge_result )
            return {};

        // Construct initial state from information.
        //
        std::unique_ptr<vm_state> initial_state 
            = std::make_unique<vm_state>( stack_reg, vip_reg, X86_REG_RSP, rolling_key_reg, flow_reg, 
                                          update_vip_ins == X86_INS_ADD ? vm_direction_down : vm_direction_up,
                                          flow_rva );

        // At this point we have competed vm_instance construction. But now we must create the vm_bridge
        // that appends the vm_instance. 
        //
        auto bridge = vm_bridge::from_instruction_stream( initial_state.get(), &copied_stream );

        // If unsuccessful, return empty {}.
        //
        if ( !bridge )
            return {};

        // Capture the stack order.
        //
        std::vector<vtil::register_desc> stack;
        for ( x86_reg reg : pushed_regs )
        {
            if ( reg == X86_REG_EFLAGS )
            {
                stack.push_back( vtil::REG_FLAGS );
                continue;
            }

            stack.push_back( { vtil::register_physical, ( uint64_t )reg, 64 } );
        }

        // Last pushed value is the image base offset, which we'll push manually later.
        //
        stack.pop_back();
        
        // Otherwise, construct & return vm_instance.
        //
        return std::make_unique<vm_instance>( copied_stream.base(), std::move( initial_state ), stack, std::move( vip_expression ), std::move( *bridge ) );
    }
}