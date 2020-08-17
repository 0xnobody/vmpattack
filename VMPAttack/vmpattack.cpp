#include "vmpattack.hpp"
#include "disassembler.hpp"
#include <vtil/compiler>
#include <vtil/arch>
#include <functional> 
#include <locale>
#include <algorithm> 
#include <cctype>

//#define VMPATTACK_VERBOSE_1

namespace vmpattack
{
    // Attempts to find a vm_instance for the specified rva. If succeeded, returns
    // said instance. Otherwise returns nullptr.
    //
    vm_instance* vmpattack::lookup_instance( uint64_t rva )
    {
        // Lock the mutex.
        //
        const std::lock_guard<std::mutex> lock( instances_mutex );

        // Enumerate instances without acquiring them.
        //
        for ( auto& instance : instances )
        {
            // If rva is equal, return a non-owning ptr.
            //
            if ( instance->rva == rva )
                return instance.get();
        }

        // None found - return nullptr.
        //
        return nullptr;
    }

    // Adds the specified vm_instance to the cached list, exersizing thread-safe behaviour
    // in doing so.
    //
    void vmpattack::add_instance( std::unique_ptr<vm_instance> instance )
    {
        // Lock the mutex.
        //
        const std::lock_guard<std::mutex> lock( instances_mutex );

        // Add the instance.
        //
        instances.push_back( std::move( instance ) );
    }

    // Performs the specified lifting job, returning a raw, unoptimized vtil routine.
    // Optionally takes in a previous block to fork. If null, creates a new block via a new routine.
    // If the passed previous block is not completed, it is completed with a jmp to the newly created block.
    //
    std::optional<vtil::routine*> vmpattack::lift_internal( uint64_t rva, uint64_t stub, vtil::basic_block* prev_block )
    {
        // First we must either lookup or create the vm_instance.
        //
        vm_instance* instance = lookup_instance( rva );

        instruction_stream stream = disassembler::get().disassemble( image_base, rva );

        if ( !instance )
        {
            // Try to construct from instruction_stream.
            //
            auto new_instance = vm_instance::from_instruction_stream( &stream );

            // If creation failed, return empty {}.
            //
            if ( !new_instance )
                return {};

            // Otherwise, append vm_instance to cached list and fetch a non-owning ptr.
            //
            instance = new_instance->get();
            add_instance( std::move( *new_instance ) );
        }

        // Construct the initial vm_context from the vip stub.
        //
        std::unique_ptr<vm_context> initial_context = instance->initialize_context( stub, image_base - preferred_image_base );

        vtil::basic_block* block = nullptr;
        if ( prev_block )
        {
            vtil::vip_t block_vip = initial_context->vip - image_base + preferred_image_base;

            // Complete the prev block if not yet completed.
            //
            if ( !prev_block->is_complete() )
                prev_block->jmp( block_vip );

            block = prev_block->fork( block_vip );

            if ( !block )
                return {};
        }
        else
            block = vtil::basic_block::begin( initial_context->vip - image_base + preferred_image_base );

        // Push 2 arbitrary values to represent the VM stub and retaddr pushed by VMP.
        //
        block
            ->push( 0xDEADC0DEDEADC0DE )
            ->push( 0xBABEBABEBABEBABE );

        // Push all registers on VMENTRY.
        //
        for ( const vtil::register_desc& reg : instance->entry_frame )
            block->push( reg );

        // Offset image base by the preferred image base.
        // This is because, currently, the IMGBASE reg is assigned to the offset. This is incorrect.
        // It must be assigned to the actual image base.
        auto t0 = block->tmp( 64 );
        block
            ->mov( t0, vtil::REG_IMGBASE )
            //  ->sub( t0, preferred_image_base )
            ->push( t0 );

        if ( !lift_block( instance, block, initial_context.get(), instance->bridge->advance( initial_context.get() ), {} ) )
            return {};

        return block->owner;
    }

    std::vector<uint8_t> map_image( const vtil::pe_image& image )
    {
        // Kinda amazing that there's no SizeOfImage in a PE wrapper.......
        //
        uint8_t* mapped_buffer = new uint8_t[ 0x10000000 ]();

        // Copy PE headers.
        // TODO: Fix this hardcoded trash.
        //
        memcpy( mapped_buffer, image.cdata(), 0x1000 );

        // Copy each section.
        //
        for ( const vtil::section_descriptor& section : image )
            memcpy( &mapped_buffer[ section.virtual_address ], &image.raw_bytes[ section.physical_address ], section.physical_size );

        // Copy into a vector.
        //
        std::vector<uint8_t> mapped_image = { mapped_buffer, mapped_buffer + 0x10000000 };

        // Delete the raw buffer.
        //
        delete[] mapped_buffer;

        return mapped_image;
    }

    // Construct from raw image bytes vector.
    //
    vmpattack::vmpattack( const std::vector<uint8_t>& raw_bytes ) :
        image( raw_bytes ), mapped_image( map_image( image ) ), image_base( ( uint64_t )mapped_image.data() ), preferred_image_base( 0x0000000140000000 )
    {}

    // Lifts a single basic block, given the appropriate information.
    //
    bool vmpattack::lift_block( vm_instance* instance, vtil::basic_block* block, vm_context* context, uint64_t first_handler_rva, std::vector<vtil::vip_t> explored_blocks )
    {
#ifdef VMPATTACK_VERBOSE_0
        vtil::logger::log<vtil::logger::CON_CYN>( "==> Lifting Basic Block @ VIP RVA 0x%llx and Handler RVA 0x%llx\r\n", context->vip - image_base, first_handler_rva );
#endif

        // Add current block to explored list.
        //
        explored_blocks.push_back( block->entry_vip );

        uint64_t current_handler_rva = first_handler_rva;
        vm_handler* current_handler = nullptr;

        // Main loop responsible for lifting all instructions in this block.
        //
        while ( true )
        {
            // Try to lookup a cached handler.
            //
            auto handler_lookup = instance->find_handler( current_handler_rva );
            if ( !handler_lookup )
            {
                // No cached handler found; construct it ourselves.
                //
                instruction_stream stream = disassembler::get().disassemble( image_base, current_handler_rva );
                auto handler = vm_handler::from_instruction_stream( context->state.get(), &stream );

                // Assert that we matched a handler.
                //
                fassert( handler );
#ifdef _DEBUG
                if ( !handler )
                    __debugbreak();
#endif
                // Store the non-owning ptr to the handler, and give ownership of the handler
                // to vm_instance by adding it to its list.
                //
                current_handler = handler->get();
                instance->add_handler( std::move( *handler ) );
            }
            else
            {
                // Fetch the cached handler.
                //
                current_handler = *handler_lookup;

                // We much update the VM state manually if nessecary, as we are fetching a cached handler.
                //
                if ( current_handler->descriptor->flags & vm_instruction_updates_state && current_handler->instruction_info->updated_state )
                    *context->state = *current_handler->instruction_info->updated_state;
            }

            // Save the rolling key before instruction decoding.
            //
            uint64_t prev_rolling_key = context->rolling_key;

            // Decode the current handler using the context, advancing it.
            //
            vm_instruction decoded_instruction = current_handler->decode( context );

            std::string vmp_il_text = vtil::format::str( "0x%016x | 0x%016x | 0x%016x | %s", context->vip - preferred_image_base, current_handler_rva, prev_rolling_key, decoded_instruction.to_string().c_str() );

            // Print the instruction.
            //
#ifdef VMPATTACK_VERBOSE_1
            vtil::logger::log( "%s\n", vmp_il_text );
#endif

            // if ( block->size() != 0 )
            //     block->label( vmp_il_text );

            // Emit VTIL.
            //
            current_handler->descriptor->generate( block, &decoded_instruction );

            // Handle VMEXITs.
            //
            if ( current_handler->descriptor->flags & vm_instruction_vmexit )
            {
                // Fetch the address the vmexit returns to.
                //
                auto t0 = block->tmp( 64 );
                block
                    ->pop( t0 );

                // Helper lambda to remove the REG_IMGBASE register from expressions.
                //
                auto remove_imgbase = [&]( vtil::symbolic::expression::reference src ) -> vtil::symbolic::expression::reference
                {
                    return src.transform( []( vtil::symbolic::expression::delegate& ex )
                                          {
                                              if ( ex->is_variable() )
                                              {
                                                  auto& var = ex->uid.get<vtil::symbolic::variable>();
                                                  if ( var.is_register() && var.reg() == vtil::REG_IMGBASE )
                                                      *+ex = { 0, ex->size() };
                                              }
                                          }, true, false ).simplify();
                };

                // We might be able to continue lifting if we can determine the VMEXIT return address.
                //
                vtil::cached_tracer tracer;
                vtil::symbolic::expression::reference vmexit_dest = remove_imgbase( tracer.rtrace( { block->end(), t0 } ) );

#ifdef VMPATTACK_VERBOSE_0
                vtil::logger::log<vtil::logger::CON_YLW>( "VMEXIT Destination: %s\r\n", vmexit_dest.simplify( true ) );
#endif

                // First check if the VMEXIT is due to an unsupported instruction that must be manually emitted.
                //

                // Is the VMEXIT destination address a constant?
                // 
                if ( vmexit_dest->is_constant() )
                {
                    if ( uint64_t vmexit_ea = *vmexit_dest->get<uint64_t>() )
                    {
                        uint64_t vmexit_rva = vmexit_ea - preferred_image_base;

                        // Is this VMEXIT just caused by an unsupported instruction that we need to manually emit?
                        // Attempt to analyze the potential entry stub the vmexit exits to.
                        //
                        if ( std::optional<vmentry_analysis_result> analysis = analyze_entry_stub( vmexit_rva ) )
                        {
                            // If there is an instruction that caused the VMEXIT, emit it.
                            //
                            if ( analysis->exit_instruction )
                            {
                                // Get registers read / written to from exit instruction.
                                //
                                auto [regs_read, regs_write] = ( *analysis->exit_instruction )->get_regs_accessed();

                                // Pin any registers read.
                                //
                                for ( x86_reg reg_read : regs_read )
                                    block->vpinr( reg_read );

                                // Emit the instruction.
                                //
                                std::shared_ptr<instruction>& exit_instruction = *analysis->exit_instruction;
                                for ( int i = 0; i < exit_instruction->ins.size; i++ )
                                    block->vemit( exit_instruction->ins.bytes[ i ] );

                                // Pin any registers written.
                                //
                                for ( x86_reg reg_write : regs_write )
                                    block->vpinw( reg_write );
                            }

                            // Continue lifting via the current basic block.
                            //
                            lift_internal( analysis->job.vmentry_rva, analysis->job.entry_stub, block );
                            return true;
                        }
                    }
                }

                // Next, check if the VMEXIT is due to VXCALL.
                //

                // If it is a VXCALL, the next 64 bit value pushed on the stack will be a constant pointer
                // to the VMENTRY stub that control will be returned to after non-virtual function execution.
                //
                auto t1 = block->tmp( 64 );
                block->pop( t1 );

                // Flush the cache as we modified the instruction stream.
                //
                tracer.flush();

                // Tracer will only need to search the current block, as multiblock tracing is not needed for VMEXITs.
                //
                vtil::symbolic::expression::reference potential_retaddr = remove_imgbase( tracer.rtrace( { block->end(), t1 } ) );

#ifdef VMPATTACK_VERBOSE_0
                vtil::logger::log( "VMEXIT Potential retaddr: %s\r\n", potential_retaddr.to_string() );
#endif

                // Is the potential retaddr a constant?
                //
                if ( potential_retaddr->is_constant() )
                {
                    // Get the actual RVA without the preferred imagebase injected by VMP.
                    //
                    uint64_t potential_retaddr_rva = *potential_retaddr->get<uint64_t>() - preferred_image_base;

                    // Try to perform VMENTRY stub analysis on the constant retaddr.
                    //
                    if ( std::optional<vmentry_analysis_result> analysis = analyze_entry_stub( potential_retaddr_rva ) )
                    {
                        // Said retaddr is a VMENTRY stub! We can now conclude that the VMEXIT is caused by a VXCALL.
                        // So we emit a VXCALL, and continue lifting via the current basic block.
                        //
                        block->vxcall( t0 );
                        lift_internal( analysis->job.vmentry_rva, analysis->job.entry_stub, block );

                        return true;
                    }
                }

                // Fall back to simple vexit.
                //
                block->vexit( t0 );

                // Finish recursion, breaking out of the loop.
                //
                break;
            }

            // If it is a branching instruction, we must follow its behaviour by
            // changing our lifting vip.
            //
            if ( current_handler->descriptor->flags & vm_instruction_branch )
            {
                // Use the VTIL tracer to trace the branch at the end of the block, 
                // that was just emitted.
                // Cross-block is set to true, as the image base offset is used from
                // previous blocks in VMP.
                //
                vtil::cached_tracer tracer;
                vtil::optimizer::aux::branch_info branches_info = vtil::optimizer::aux::analyze_branch( block, &tracer, { .cross_block = true, .pack = true, .resolve_opaque = true } );

#ifdef VMPATTACK_VERBOSE_0
                vtil::logger::log( "Potential Branch Destinations: %s\r\n", branches_info.destinations );
#endif
                // Loop through any destinations resolved by the analyzer.
                //
                for ( auto branch : branches_info.destinations )
                {
                    // Only attempt to resolve branches to constant VIPs.
                    //
                    if ( branch->is_constant() )
                    {
                        vtil::vip_t branch_ea = *branch->get<uint64_t>();
                        uint64_t branch_rva = branch_ea - preferred_image_base;

                        if ( auto next_block = block->fork( branch_ea ) )
                        {
                            // If block has already been explored, we can skip it.
                            //
                            if ( std::find( explored_blocks.begin(), explored_blocks.end(), branch_ea ) != explored_blocks.end() )
                            {
#ifdef VMPATTACK_VERBOSE_0
                                vtil::logger::log( "Skipping already explored block 0x%p\r\n", branch_ea );
#endif
                                continue;
                            }

                            // If the direction is up, add 1 to the block destination to get the actual ea.
                            // This is because we offseted it -1 in the ret instruction. So the branch dest
                            // will be off by -1.
                            // Thanks to Can for this bugfix!
                            //
                            branch_rva += context->state->direction == vm_direction_up ? 1 : 0;

                            // Copy context for the branch.
                            // This is done as we will be walking each possible branch location, and 
                            // each needs its own context, as we cannot taint the current context 
                            // because it needs to be "fresh" for each branch walked.
                            //
                            // Since state is a unique_ptr (ie. it cannot by copied), we must manually copy it
                            // by creating a new vm_state.
                            // The new branch's initial rolling key is its initial non-relocated vip.
                            // 
                            vm_context branch_context = { std::make_unique<vm_state>( *context->state ), branch_rva + preferred_image_base, branch_rva + image_base };

                            // Update the newly-created context with the handler's bridge, to resolve the first
                            // handler's rva.
                            //
                            uint64_t branch_first_handler_rva = current_handler->bridge->advance( &branch_context );

                            // Recursively lift the next block.
                            // TODO: Multi-thread this part!
                            //
                            lift_block( instance, next_block, &branch_context, branch_first_handler_rva, explored_blocks );
                        }
                    }
                }

                // Branch has been encountered - we cannot continue lifting this block as it has finished.
                //
                break;
            }

            // We need to fork and create a new block if specified so by the instruction
            // flags.
            //
            if ( current_handler->descriptor->flags & vm_instruction_creates_basic_block )
            {
                vtil::vip_t new_block_ea = context->vip - image_base + preferred_image_base;

                // Offset by -1 if direction is upwards so downwards/upwards streams to the
                // same EA don't collide.
                //
                if ( context->state->direction == vm_direction_up )
                    new_block_ea -= 1;

                // Jump to the newly-created block.
                //
                block->jmp( new_block_ea );

                // Fork the current block to create the new block.
                //
                if ( vtil::basic_block* new_block = block->fork( new_block_ea ) )
                {
                    // Continue lifting via the newly created block.
                    // Use the current context as we are not changing control flow.
                    //
                    return lift_block( instance, new_block, context, current_handler->bridge->advance( context ), explored_blocks );
                }
                break;
            }

            current_handler_rva = current_handler->bridge->advance( context );
        }

        return true;
    }

    // Performs the specified lifting job, returning a raw, unoptimized vtil routine.
    //
    std::optional<vtil::routine*> vmpattack::lift( const lifting_job& job )
    {
#ifdef VMPATTACK_VERBOSE_0
        vtil::logger::log<vtil::logger::CON_CYN>( "=> Began Lifting Job for RVA 0x%llx with stub 0x%llx\r\n", job.vmentry_rva, job.entry_stub );
#endif

        return lift_internal( job.vmentry_rva, job.entry_stub, nullptr );
    }

    // Performs an analysis on the specified vmentry stub rva, returning relevant information.
    //
    std::optional<vmentry_analysis_result> vmpattack::analyze_entry_stub( uint64_t rva )
    {
        // Disassemble at the specified rva, stopping at any branch.
        //
        instruction_stream stream = disassembler::get().disassemble( image_base, rva, disassembler_none );

        // TODO: Verify this is correct.
        // In VMProtect 3, only one instruction can cause a vm exit at any single time.
        // So we have two possibilities:
        // - [Some instruction that caused a VMExit]
        // - PUSH %stub
        // - CALL %vmentry_handler
        //      or
        // - PUSH %stub
        // - CALL %vmentry_handler

        // Check size validity.
        //
        if ( stream.instructions.size() > 3 || stream.instructions.size() < 2 )
            return {};

        std::shared_ptr<instruction> call_ins = stream.instructions[ stream.instructions.size() - 1 ];
        std::shared_ptr<instruction> push_ins = stream.instructions[ stream.instructions.size() - 2 ];

        // Check if call is valid.
        //
        if ( call_ins->ins.id != X86_INS_CALL || call_ins->operand_type( 0 ) != X86_OP_IMM )
            return {};

        // Check if stub push is valid.
        //
        if ( push_ins->ins.id != X86_INS_PUSH || push_ins->operand_type( 0 ) != X86_OP_IMM )
            return {};

        uint64_t entry_stub = push_ins->operand( 0 ).imm;
        uint64_t vmentry_rva = call_ins->operand( 0 ).imm;

        // If there's an instruction that caused the VMExit, include it in the analysis data.
        //
        if ( stream.instructions.size() == 3 )
            return vmentry_analysis_result { stream.instructions[ 0 ], { entry_stub, vmentry_rva } };

        return vmentry_analysis_result{ { entry_stub, vmentry_rva } };
    }

    // Scans the given code section for VM entries.
    // Returns a list of results, of [root rva, lifting_job]
    //
    std::vector<scan_result> vmpattack::scan_for_vmentry( const std::string& section_name )
    {
        std::vector<scan_result> results = {};

        std::optional<vtil::section_descriptor> target_section = {};

        std::vector<vtil::section_descriptor> potential_vmp_sections = {};

        // Lambda to determine whether the given section name is potentially a VMP section.
        //
        auto is_vmp_section = []( const std::string& section_name ) -> bool
        {
            return section_name.ends_with( "0" ) || section_name.ends_with( "1" );
        };

        // Lambda to determine whether the given rva is within any of the potential VMP sections.
        //
        auto within_potential_vmp_sections = [&]( uint64_t rva ) -> bool
        {
            auto [rva_section, rva_section_size] = image.rva_to_section( rva );

            for ( const vtil::section_descriptor& section : potential_vmp_sections )
                if ( rva_section.name == section.name )
                    return true;

            return false;
        };

        // Sanitize section strings to make them eligible for comparison with constants.
        //
        auto sanitize_section_name = []( std::string name ) -> std::string
        {
            return std::string( name.c_str() );
        };

        // Enumerate all sections.
        //
        for ( const vtil::section_descriptor& section : image )
        {
            std::string sanitized_name = sanitize_section_name( section.name );

            if ( sanitized_name == section_name )
            {
                target_section = section;
                continue;
            }

            if ( is_vmp_section( sanitized_name ) )
                potential_vmp_sections.push_back( section );
        }

        // Is the desired section was not found, return empty {}.
        //
        if ( !target_section )
            return {};

        // Get a vector of instructions in the .text section, starting from the very beginning.
        //
        std::vector<std::unique_ptr<instruction>> text_instructions = disassembler::get().disassembly_simple( image_base, target_section->virtual_address, target_section->virtual_address + target_section->virtual_size );

        // Iterate through each instruction.
        //
        for ( const std::unique_ptr<instruction>& instruction : text_instructions )
        {
            // If instruction is JMP IMM, follow it.
            //
            if ( instruction->is_uncond_jmp() && instruction->operand( 0 ).type == X86_OP_IMM )
            {
                // Is the potential stub within a VMP section?
                //
                uint64_t potential_vmentry_rva = instruction->operand( 0 ).imm;
                if ( within_potential_vmp_sections( potential_vmentry_rva ) )
                {
                    // Try to analyze the address to verify that it is indeed a VMENTRY stub.
                    //
                    if ( std::optional<vmentry_analysis_result> analysis_result = analyze_entry_stub( potential_vmentry_rva ) )
                    {
                        // Only accept stubs with no exit instructions.
                        // Even though this should never really happen, just use this sanity check here for good measure.
                        //
                        if ( !analysis_result->exit_instruction )
                            results.push_back( { instruction->ins.address, analysis_result->job } );
                    }
                }
            }
        }

        // Return the accumulated scan results.
        //
        return results;
    }
}