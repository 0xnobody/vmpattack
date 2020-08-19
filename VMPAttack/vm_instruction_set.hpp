#pragma once
#include "vm_instruction_desc.hpp"
#include "vm_analysis_context.hpp"
#include "flags.hpp"
#include <vtil/arch>

namespace vmpattack
{
    //
    // This file describes the VMProtect instruction set, defining templates
    // and semantics for each virtual instruction.
    //

    inline const vm_instruction_desc pop = 
    { 
        "POP", 1, vm_instruction_none, 
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            std::unique_ptr<arithmetic_expression> operand_chain = std::make_unique<arithmetic_expression>();

            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg pop_reg, operand_reg;
            int64_t pop_disp = 0;
            size_t pop_size, operand_size;
            size_t store_size;

            auto result = ( &stream_context )
                // MOV(ZX) %pop_size:%pop_reg, [VSP]
                ->fetch_vsp( { pop_reg, false }, { pop_size, false }, { pop_disp, true } )

                // ADD VSP, %pop_size
                ->add_vsp( { pop_size, true } )

                // MOV(ZX) %operand_reg, %operand_size:[VIP]
                ->fetch_vip( { operand_reg, false }, { operand_size, false } )

                ->record_encryption( operand_reg, operand_chain.get() )

                // MOV %store_size:[CTX + %operand_reg], [%pop_reg]
                ->store_ctx( { pop_reg, true }, { store_size, false }, { operand_reg, true } );

            if ( !result )
                return false;

            vm_operand op = { vm_operand_reg, pop_size, operand_size };
            info->operands.push_back( { op, std::move( operand_chain ) } );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto operand = instruction->operands[ 0 ];
            auto& operand_info = instruction->handler->instruction_info->operands[ 0 ];

            vtil::register_desc reg( vtil::register_virtual, operand / 8, operand_info.first.size * 8, ( operand % 8 ) * 8 );

            block
                ->pop( reg );
        }
    };

    inline const vm_instruction_desc popstk =
    {
        "POPSTK", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg stack_reg = state->stack_reg;
            size_t pop_size = 8;
            int64_t disp = 0;

            auto result = ( &stream_context )
                // MOV 8:VSP, [VSP]
                ->fetch_vsp( { stack_reg, true }, { pop_size, true }, { disp, true } );

            if ( !result )
                return false;

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            block
              ->pop( vtil::REG_SP );
        }
    };

    inline const vm_instruction_desc push =
    {
        "PUSH", 1, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            //
            // There are 2 types of this handler: push %reg, and push %imm.
            // First, attempt to match for push imm.
            //
            {
                std::unique_ptr<arithmetic_expression> operand_chain = std::make_unique<arithmetic_expression>();

                instruction_stream copied_stream = *stream;
                vm_analysis_context stream_context = vm_analysis_context( &copied_stream, state );

                x86_reg operand_reg;
                size_t operand_size, stack_store_size;

                auto result = ( &stream_context )
                    // MOV(ZX) %operand_size:%operand_reg, [VIP]
                    ->fetch_vip( { operand_reg, false }, { operand_size, false } )

                    ->record_encryption( operand_reg, operand_chain.get() )
                    ->cast<vm_analysis_context*>()

                    // MOV %stack_store_size:[VSP], %operand_reg
                    ->store_vsp( { operand_reg, true }, { stack_store_size, false } );

                // If matching succeeded, that means that this is the push %imm variant.
                //
                if ( result )
                {
                    // Commit changes to the stream.
                    //
                    *stream = copied_stream;

                    vm_operand op = { vm_operand_imm, stack_store_size, operand_size };
                    info->operands.push_back( { op, std::move( operand_chain ) }  );

                    return true;
                }
            }

            //
            // Otherwise, we must check for the push %reg variant.
            //

            {
                std::unique_ptr<arithmetic_expression> operand_chain = std::make_unique<arithmetic_expression>();

                instruction_stream copied_stream = *stream;
                vm_analysis_context stream_context = vm_analysis_context( &copied_stream, state );

                x86_reg operand_reg, context_reg;
                size_t operand_size, stack_store_size;

                auto result = ( &stream_context )
                    // MOV(ZX) %operand_size:%operand_reg, [VIP]
                    ->fetch_vip( { operand_reg, false }, { operand_size, false } )

                    ->record_encryption( operand_reg, operand_chain.get() )
                    ->cast<vm_analysis_context*>()

                    // MOV(ZX) %context_reg, %stack_store_size:[CTX + %operand_reg]
                    ->fetch_ctx( { context_reg, false }, { stack_store_size, false }, { operand_reg, true } )
                    
                    // %stack_store_size = ALIGN(%stack_store_size)
                    ->align( stack_store_size )
                    ->cast<vm_analysis_context*>()

                    // MOV %stack_store_size:[VSP], %context_reg
                    ->store_vsp( { context_reg, true }, { stack_store_size, true } );

                // If matching succeeded, that means that this is the push %imm variant.
                //
                if ( result )
                {
                    // Commit changes to the stream.
                    //
                    *stream = copied_stream;

                    vm_operand op = { vm_operand_reg, stack_store_size, operand_size };
                    info->operands.push_back( { op, std::move( operand_chain ) } );

                    return true;
                }
            }

            // Neither variant matched.
            //
            return false;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto operand = instruction->operands[ 0 ];
            auto& operand_info = instruction->handler->instruction_info->operands[ 0 ];

            if ( operand_info.first.type == vm_operand_imm )
            {
                switch ( operand_info.first.size )
                {
                    case 8:
                        block
                            ->push( ( uint64_t )operand );
                        break;
                    case 4:
                        block
                            ->push( ( uint32_t )operand );
                        break;
                    case 2:
                        block
                            ->push( ( uint16_t )operand );
                        break;
                    case 1:
                        block
                            ->push( ( uint8_t )operand );
                        break;
                }
            }
            else if ( operand_info.first.type == vm_operand_reg )
            {
                vtil::register_desc reg( vtil::register_virtual, operand / 8, operand_info.first.size * 8, ( operand % 8 ) * 8 );

                block
                    ->push( reg );
            }
        }
    };

    inline const vm_instruction_desc pushstk =
    {
        "PUSHSTK", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg stored_stack_reg, stack_reg = state->stack_reg;
            size_t store_size;

            auto result = ( &stream_context )
                // MOV %stored_stack_reg, VSP
                ->mov_reg_reg( { stored_stack_reg, false }, { stack_reg, true } )
                ->cast<vm_analysis_context*>()

                // MOV %store_size:[VSP], %stored_stack_reg
                ->store_vsp( { stored_stack_reg, true }, { store_size, false } );

            if ( !result )
                return false;

            info->sizes.push_back( store_size );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto t0 = block->tmp( sizes[ 0 ] * 8 );

            block
              ->mov( t0, vtil::REG_SP )
              ->push( t0 );
        }
    };

    inline const vm_instruction_desc add =
    {
        "ADD", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0, s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )

                // ADD %r0, %r1
                ->add_reg_reg( { r0, true }, { r1, true } )

                // PUSHFQ
                ->id( X86_INS_PUSHFQ );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [lhs, rhs, result] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8 );
            auto [lhs_sign, rhs_sign, result_sign, parity] = block->tmp( 1, 1, 1, 8 );

            // TODO: AF
            block
                ->pop( lhs )
                ->pop( rhs )

                ->mov( result, lhs)

                ->add( result, rhs )

                ->tl( flags::SF, result, 0 )
                ->te( flags::ZF, result, 0 )
                ->tul( flags::CF, result, lhs )

                ->tl( lhs_sign, lhs, 0)
                ->tl( rhs_sign, rhs, 0)
                ->tl( result_sign, result, 0)
                ->bxor( lhs_sign, result_sign )
                ->bxor( rhs_sign, result_sign )
                ->band( lhs_sign, rhs_sign )
                ->mov( flags::OF, lhs_sign )

                //->mov( parity, result )
                //->popcnt( parity )
                //->mov( flags::PF, parity.resize( 1 ) )

                ->push( result )
                ->pushf();
        }
    };

    inline const vm_instruction_desc nand =
    {
        "NAND", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0, s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )

                // NOT %r0
                ->not_reg( { r0, true } )

                // NOT %r1
                ->not_reg( { r1, true } )

                // OR %r0, %r1
                ->or_reg_reg( { r0, true }, { r1, true } );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [lhs, rhs, result] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8 );
            auto parity = block->tmp( 8 );

            // TODO: PF
            block
                ->pop( lhs )
                ->pop( rhs )

                ->bnot( lhs )
                ->bnot( rhs )

                ->mov( result, lhs )
                ->bor( result, rhs )

                ->mov( flags::OF, 0 )
                ->mov( flags::CF, 0 )
                ->tl( flags::SF, result, 0 )
                ->te( flags::ZF, result, 0 )
                //->mov( flags::AF, vtil::UNDEFINED )

                //->mov( parity, result )
                //->popcnt( parity )
                //->mov( flags::PF, parity.resize( 1 ) )

                ->push( result )
                ->pushf();
        }
    };

    inline  vm_instruction_desc nor =
    {
        "NOR", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0, s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )

                // NOT %r0
                ->not_reg( { r0, true } )

                // NOT %r1
                ->not_reg( { r1, true } )

                // AND %r0, %r1
                ->and_reg_reg( { r0, true }, { r1, true } );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [lhs, rhs, result] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8 );
            auto parity = block->tmp( 8 );

            block
                ->pop( lhs )
                ->pop( rhs )

                ->bnot( lhs )
                ->bnot( rhs )

                ->mov( result, lhs )
                ->band( result, rhs )

                ->mov( flags::OF, 0 )
                ->mov( flags::CF, 0 )
                ->tl( flags::SF, result, 0 )
                ->te( flags::SF, result, 0 )
                //->mov( flags::AF, vtil::UNDEFINED )

                //->mov( parity, result )
                //->popcnt( parity )
                //->mov( flags::PF, parity.resize( 1 ) )

                ->push( result )
                ->pushf();
        }
    };

    inline const vm_instruction_desc ldd =
    {
        "LDD", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t aligned_size, size;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %aligned_size:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { aligned_size, false }, { initial_disp, true } )

                // MOV(ZX) %size:%r1, [%r0]
                ->fetch_memory( { r1, false }, { r0, true }, { size, false } )
                ->cast<vm_analysis_context*>()

                // MOV %size:[VSP], %r1
                ->store_vsp( { r1, true }, { size, true } );

            if ( !result )
                return false;

            info->sizes.push_back( aligned_size );
            info->sizes.push_back( size );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );

            block
                ->pop( t0 )

                ->ldd( t1, t0, 0 )

                ->push( t1 );
        }
    };

    inline const vm_instruction_desc str =
    {
        "STR", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0 = 8;
            size_t s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )

                // MOV [%r0], %s1:%r1
                ->store_memory( { r0, true }, { r1, true }, { s1, true } );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );

            block
              ->pop( t0 )
              ->pop( t1 )

              ->str( t0, 0, t1 );
        }
    };

    inline const vm_instruction_desc shld =
    {
        "SHLD", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1, r2;
            size_t size, shift_size;
            int64_t last_disp;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %size:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { size, false }, { initial_disp, true } )

                // MOV(ZX) %size:%r1, [VSP + %size]
                ->fetch_vsp( { r1, false }, { size, true }, { ( int64_t& )size, true } )

                // MOV(ZX) %shift_size:%r2, [VSP + %last_disp]
                ->fetch_vsp( { r2, false }, { shift_size, false }, { ( int64_t& )last_disp, false } )

                // SHLD %r0, %r1, %r2
                ->shld_reg_reg_reg( { r0, true }, { r1, true }, { r2, true } );

            if ( !result )
                return false;

            info->sizes.push_back( size );
            info->sizes.push_back( shift_size );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1, t2, t4, t5 ] = block->tmp( sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8 );

            auto parity = block->tmp( 8 );

            // TODO: OF for 1 bit
            //
            // shld t0, t1, t3
            // =
            // (t0 << t3) | (t1 >> (size(t1) - t3))
            //
            block
                ->pop( t0 )
                ->pop( t1 )
                ->pop( t2 )

                ->mov( t5, t0 )

                ->bshl( t0, t2 )

                ->mov( t4, sizes[ 0 ] * 8 )
                ->sub( t4, t2 )

                ->bshr( t1, t4 )
                ->bor( t0, t1 )

                ->bshr( t5, t4 )
                ->mov( flags::CF, t5 )

                ->tl( flags::SF, t0, 0 )
                ->te( flags::ZF, t0, 0 )
                //->mov( flags::AF, vtil::UNDEFINED )
                ->mov( flags::OF, vtil::UNDEFINED )

                //->mov( parity, t0 )
                //->popcnt( parity )
                //->mov( flags::PF, parity )

                ->push( t0 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc shrd =
    {
        "SHRD", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1, r2;
            size_t size, shift_size;
            int64_t last_disp;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %size:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { size, false }, { initial_disp, true } )

                // MOV(ZX) %size:%r1, [VSP + %size]
                ->fetch_vsp( { r1, false }, { size, true }, { ( int64_t& )size, true } )

                // MOV(ZX) %shift_size:%r2, [VSP + %last_disp]
                ->fetch_vsp( { r2, false }, { shift_size, false }, { ( int64_t& )last_disp, false } )

                // SHRD %r0, %r1, %r2
                ->shrd_reg_reg_reg( { r0, true }, { r1, true }, { r2, true } );

            if ( !result )
                return false;

            info->sizes.push_back( size );
            info->sizes.push_back( shift_size );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1, t2, t4, t5] = block->tmp( sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8 );
            auto parity = block->tmp( 8 );

            // shrd t0, t1, t3
            // =
            // (t0 >> t3) | (t1 << (size(t1) - t3))
            //
            block
                ->pop( t0 )
                ->pop( t1 )
                ->pop( t2 )

                ->mov( t5, t0 )

                ->bshr( t0, t2 )

                ->mov( t4, sizes[ 0 ] * 8 )
                ->sub( t4, t2 )

                ->bshl( t1, t4 )
                ->bor( t0, t1 )

                ->sub( t2, 1 )
                ->bshr( t5, t2 )
                ->mov( flags::CF, t5 )

                ->tl( flags::SF, t5, 0 )
                ->te( flags::ZF, t5, 0 )
                //->mov( flags::AF, vtil::UNDEFINED )
                ->mov( flags::OF, vtil::UNDEFINED )

                //->mov( parity, t5 )
                //->popcnt( parity )
                //->mov( flags::PF, parity )

                ->push( t0 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc shl =
    {
        "SHL", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0, s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )
                ->align( s0 )
                ->cast<vm_analysis_context*>()

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )
                ->align( s1 )
                ->cast<vm_analysis_context*>()

                // SHL %r0, %r1
                ->shl_reg_reg( { r0, true }, { r1, true } );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [lhs, rhs, result] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8 );
            auto [t0, t1] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );
            auto parity = block->tmp( 8 );

            block
                ->pop( lhs )
                ->pop( rhs )
                ->mov( result, lhs )
                ->bshl( result, rhs )

                ->mov( t1, lhs.bit_count )
                ->sub( t1, rhs )
                ->mov( t0, lhs )
                ->bshr( t0, t1 )

                ->mov( flags::CF, t0 )
                ->tl( flags::SF, result, 0 )
                ->te( flags::ZF, result, 0 )
                //->mov( flags::AF, vtil::UNDEFINED )
                ->mov( flags::OF, vtil::UNDEFINED )

                //->mov( parity, t0 )
                //->popcnt( parity )
                //->mov( flags::PF, parity )

                ->push( result )
                ->pushf();
        }
    };

    inline const vm_instruction_desc shr =
    {
        "SHR", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0, s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )
                ->align( s0 )
                ->cast<vm_analysis_context*>()

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )
                ->align( s1 )
                ->cast<vm_analysis_context*>()

                // SHR %r0, %r1
                ->shr_reg_reg( { r0, true }, { r1, true } );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [lhs, rhs, result] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8 );
            auto [t0, t1] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );
            auto parity = block->tmp( 8 );

            block
                ->pop( lhs )
                ->pop( rhs )
                ->mov( result, lhs )
                ->bshr( result, rhs )

                ->mov( t1, rhs )
                ->sub( t1, 1 )
                ->mov( t0, lhs )
                ->bshr( t0, t1 )

                ->mov( flags::CF, t0 )
                ->tl( flags::SF, result, 0 )
                ->te( flags::ZF, result, 0 )
                //->mov( flags::AF, vtil::UNDEFINED )
                ->mov( flags::OF, vtil::UNDEFINED )

                //->mov( parity, t0 )
                //->popcnt( parity )
                //->mov( flags::PF, parity )

                ->push( result )
                ->pushf();
        }
    };

    inline const vm_instruction_desc rdtsc =
    {
        "RDTSC", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            auto result = ( &stream_context )
                // RDTSC
                ->id( X86_INS_RDTSC );

            return result;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            block
                ->vemits( "rdtsc" )

                ->vpinw( X86_REG_RDX )
                ->vpinw( X86_REG_RAX )

                ->push( X86_REG_EDX )
                ->push( X86_REG_EAX );
        }
    };

    inline const vm_instruction_desc cpuid =
    {
        "CPUID", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0;
            size_t s0;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV %s0:%r1, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )

                // CPUID
                ->id( X86_INS_CPUID );

            return result;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto eax = block->tmp( 32 );

            block
                ->pop( eax )
                ->mov( X86_REG_EAX, eax )

                ->vpinr( X86_REG_EAX )

                ->vemits( "cpuid" )

                ->vpinw( X86_REG_EAX )
                ->vpinw( X86_REG_EBX )
                ->vpinw( X86_REG_ECX )
                ->vpinw( X86_REG_EDX )

                ->push( X86_REG_EAX )
                ->push( X86_REG_EBX )
                ->push( X86_REG_ECX )
                ->push( X86_REG_EDX );
        }
    };

    inline const vm_instruction_desc pushreg =
    {
        "PUSHREG", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0 = 8;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV %r0, %r1
                ->mov_reg_reg( { r0, false }, { r1, false } )
                ->cast<vm_analysis_context*>()
                
                ->store_vsp( { r0, true }, { s0, true } );

            if ( !result )
                return false;

            // Ensure reg is DRx or CRx.
            //
            if ( ( r1 >= X86_REG_DR0 && r1 <= X86_REG_DR15 ) || ( r1 >= X86_REG_CR0 && r1 <= X86_REG_CR15 ) )
            {
                info->custom_data = r1;
                return true;
            }

            return false;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            block
                ->push( instruction->handler->instruction_info->custom_data.get<x86_reg>() );
        }
    };

    inline const vm_instruction_desc popreg =
    {
        "POPREG", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0 = 8;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                ->fetch_vsp( { r0, false }, { s0, true }, { initial_disp, true } )

                ->mov_reg_reg( { r1, false }, { r0, true } );

            if ( !result )
                return false;

            // Ensure reg is DRx or CRx.
            //
            if ( ( r1 >= X86_REG_DR0 && r1 <= X86_REG_DR15 ) || ( r1 >= X86_REG_CR0 && r1 <= X86_REG_CR15 ) )
            {
                info->custom_data = r1;
                return true;
            }

            return false;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            block
                ->pop( instruction->handler->instruction_info->custom_data.get<x86_reg>() );
        }
    };

    inline const vm_instruction_desc lockor =
    {
        "LOCKOR", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0 = 8, s1;
            int64_t initial_disp = 0, d1 = 8;

            const instruction* lock_or_ins = nullptr;

            auto result = ( &stream_context )
                // MOV %r0, %s0:[VSP]
                ->fetch_vsp( { r0, false }, { s0, true }, { initial_disp, true } )

                // MOV %r1, %s1:[VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { d1, true } )

                // OR [%r0], %r1
                ->id( X86_INS_OR, &lock_or_ins );

            if ( !result || !lock_or_ins )
                return false;

            // Ensure OR instruction has the LOCK prefix.
            //
            if ( lock_or_ins->prefix( 0 ) != X86_PREFIX_LOCK )
                return false;

            // Add registers to custom instruction data.
            //
            info->custom_data = std::vector<x86_reg>();
            info->custom_data.get<std::vector<x86_reg>>().push_back( r0 );
            info->custom_data.get<std::vector<x86_reg>>().push_back( r1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            // VTIL does not support architecture-specific instructions.
            // We must emit the LOCK OR manually.
            //
            std::vector<x86_reg> regs = instruction->handler->instruction_info->custom_data.get<std::vector<x86_reg>>();

            std::string assembly = vtil::format::str( "lock or [%s], %s", vtil::amd64::name( regs[ 0 ] ), vtil::amd64::name( regs[ 1 ] ) );

            block
                ->vemits( assembly );
        }
    };

    inline const vm_instruction_desc nop =
    {
        "NOP", 0, vm_instruction_creates_basic_block | vm_instruction_updates_state,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            analysis_context stream_context = analysis_context( stream );

            x86_reg flow_reg = state->flow_reg;
            uint64_t flow_rva;

            auto result = ( &stream_context )
                // LEA %flow_reg, [%rip - {ins_len}]
                ->set_flow( { flow_reg, true }, { flow_rva, false } );

            if ( result )
            {
                info->updated_state = *state;
                info->updated_state->flow = flow_rva;

                return true;
            }

            return false;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            block
                ->nop();
        }
    };

    inline const vm_instruction_desc popf =
    {
        "POPF", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg stack_reg = state->stack_reg;

            size_t s0 = 8;

            auto result = ( &stream_context )
                // PUSH 8:[VSP]
                ->push_memory( { stack_reg, true }, { s0, true } )

                // POPFQ
                ->id( X86_INS_POPFQ );

            return result;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            block
                ->popf();
        }
    };

    inline const vm_instruction_desc div =
    {
        "DIV", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1, r2;
            size_t s0, s1;
            int64_t initial_disp = 0;
            int64_t disp, divisor_disp;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP + %disp]
                ->fetch_vsp( { r0, false }, { s0, false }, { disp, false } )

                // MOV(ZX) %s0:%r1, [VSP]
                ->fetch_vsp( { r1, false }, { s0, true }, { initial_disp, true } )

                // MOV(ZX) %s1:%r2, [VSP + %divisor_disp]
                ->fetch_vsp( { r2, false }, { s1, false }, { divisor_disp, false } )

                // DIV %r0, %r1, %r2
                ->div_reg( { r2, true } );

            if ( !result )
                return false;

            // Arguments for (I)DIV must be in AX and DX.
            //
            if ( !register_base_equal( r0, X86_REG_AX )
              || !register_base_equal( r1, X86_REG_DX ) )
                 return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1, t2, t3] = block->tmp( sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 1 ] * 8 );

            block
                // dx
                ->pop( t0 )

                // ax
                ->pop( t1 )
                ->mov( t2, t1 )

                // divisor
                ->pop( t3 )

                ->div( t1, t0, t3 )
                ->rem( t2, t0, t3 )

                ->mov( flags::CF, vtil::UNDEFINED )
                ->mov( flags::OF, vtil::UNDEFINED )
                ->mov( flags::SF, vtil::UNDEFINED )
                ->mov( flags::ZF, vtil::UNDEFINED )
                //->mov( flags::AF, vtil::UNDEFINED )
                //->mov( flags::PF, vtil::UNDEFINED )

                ->push( t1 )
                ->push( t2 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc idiv =
    {
        "IDIV", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1, r2;
            size_t s0, s1;
            int64_t initial_disp = 0;
            int64_t disp, divisor_disp;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP + %disp]
                ->fetch_vsp( { r0, false }, { s0, false }, { disp, false } )

                // MOV(ZX) %s0:%r1, [VSP]
                ->fetch_vsp( { r1, false }, { s0, true }, { initial_disp, true } )

                // MOV(ZX) %s1:%r2, [VSP + %divisor_disp]
                ->fetch_vsp( { r2, false }, { s1, false }, { divisor_disp, false } )

                // IDIV %r0, %r1, %r2
                ->idiv_reg( { r2, true } );

            if ( !result )
                return false;

            // Arguments for (I)DIV must be in AX and DX.
            //
            if ( !register_base_equal( r0, X86_REG_AX )
              || !register_base_equal( r1, X86_REG_DX ) )
                 return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1, t2, t3] = block->tmp( sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 1 ] * 8 );

            block
                // dx
                ->pop( t0 )

                // ax
                ->pop( t1 )
                ->mov( t2, t1 )

                // divisor
                ->pop( t3 )

                ->idiv( t1, t0, t3 )
                ->irem( t2, t0, t3 )

                ->mov( flags::CF, vtil::UNDEFINED )
                ->mov( flags::OF, vtil::UNDEFINED )
                ->mov( flags::SF, vtil::UNDEFINED )
                ->mov( flags::ZF, vtil::UNDEFINED )
                //->mov( flags::AF, vtil::UNDEFINED )
                //->mov( flags::PF, vtil::UNDEFINED )

                ->push( t1 )
                ->push( t2 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc mul =
    {
        "MUL", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0;
            int64_t initial_disp = 0;
            int64_t disp;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP + %disp]
                ->fetch_vsp( { r0, false }, { s0, false }, { disp, false } )

                // MOV(ZX) %s0:%r1, [VSP]
                ->fetch_vsp( { r1, false }, { s0, true }, { initial_disp, true } )

                // MUL %r0
                ->mul_reg( { r1, true } );

            if ( !result )
                return false;

            // Arguments for (I)MUL must be in AX and DX.
            //
            if ( !register_base_equal( r0, X86_REG_AX )
              || !register_base_equal( r1, X86_REG_DX ) )
                 return false;

            info->sizes.push_back( s0 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1, t2, t3] = block->tmp( sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8 );

            block
                // dx
                ->pop( t0 )
                ->mov( t2, t0 )

                // ax
                ->pop( t1 )
                ->mov( t3, t1 )

                ->mul( t0, t1 )
                ->mulhi( t2, t3 )

                ->tne( flags::CF, t2, 0 )
                ->tne( flags::OF, t2, 0 )
                ->mov( flags::SF, vtil::UNDEFINED )
                ->mov( flags::ZF, vtil::UNDEFINED )
                //->mov( flags::AF, vtil::UNDEFINED )
                //->mov( flags::PF, vtil::UNDEFINED )

                ->push( t0 )
                ->push( t2 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc imul =
    {
        "IMUL", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0;
            int64_t initial_disp = 0;
            int64_t disp;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP + %disp]
                ->fetch_vsp( { r0, false }, { s0, false }, { disp, false } )

                // MOV(ZX) %s0:%r1, [VSP]
                ->fetch_vsp( { r1, false }, { s0, true }, { initial_disp, true } )

                // IMUL %r0
                ->imul_reg( { r1, true } );

            if ( !result )
                return false;

            // Arguments for (I)MUL must be in AX and DX.
            //
            if ( !register_base_equal( r0, X86_REG_AX )
              || !register_base_equal( r1, X86_REG_DX ) )
                 return false;

            info->sizes.push_back( s0 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1, t2, t3] = block->tmp( sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8, sizes[ 0 ] * 8 );
            auto [losign, sxd] = block->tmp( 1, sizes[ 0 ] * 8 );

            block
                // dx
                ->pop( t0 )
                ->mov( t2, t0 )

                // ax
                ->pop( t1 )
                ->mov( t3, t1 )

                ->imul( t0, t1 )
                ->imulhi( t2, t3 )

                ->tl( losign, t0, 0 )
                ->ifs( sxd, losign, -1 )

                ->tne( flags::CF, t2, sxd )
                ->tne( flags::OF, t2, sxd )
                ->mov( flags::SF, vtil::UNDEFINED )
                ->mov( flags::ZF, vtil::UNDEFINED )
                //->mov( flags::AF, vtil::UNDEFINED )
                //->mov( flags::PF, vtil::UNDEFINED )

                ->push( t0 )
                ->push( t2 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc rcl =
    {
        "RCL", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0, s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )

                // RCL %r0, %r1
                ->rcl_reg_reg( { r0, true }, { r1, true } );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );
            auto [t2, t3, t4] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8 );
            auto [t5, t6] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );

            // TODO: Flags + fix this!!
            // (DST << SHIFT) | (DST >> (N - SHIFT + 1))
            // CF = DST >> ( N - SHIFT )
            block
                ->pop( t0 )
                ->pop( t1 )

                // t2 = DST << SHIFT
                ->mov( t2, t0 )
                ->bshl( t2, t1 )

                // t3 = (N - SHIFT + 1)
                ->mov( t3, t0.bit_count )
                ->sub( t3, t1 )
                // t6 = N - SHIFT
                ->mov( t6, t3 )
                ->add( t3, 1 )

                // t4 = DST >> (N - SHIFT + 1)
                ->mov( t4, t0 )
                ->bshr( t4, t3 )

                // t2 = (DST << SHIFT) | (DST >> (N - SHIFT + 1))
                ->bor( t2, t4 )

                // t5 = DST >> ( N - SHIFT )
                ->mov( t5, t0 )
                ->bshr( t5, t6 )

                // CF = ( DST >> ( N - SHIFT ) ) != 0
                ->ifs( flags::CF, t5, 1 )

                ->push( t2 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc rcr =
    {
        "RCR", 0, vm_instruction_none,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg r0, r1;
            size_t s0, s1;
            int64_t initial_disp = 0;

            auto result = ( &stream_context )
                // MOV(ZX) %s0:%r0, [VSP]
                ->fetch_vsp( { r0, false }, { s0, false }, { initial_disp, true } )

                // MOV(ZX) %s1:%r1, [VSP + %s0]
                ->fetch_vsp( { r1, false }, { s1, false }, { ( int64_t& )s0, true } )

                // RCR %r0, %r1
                ->rcr_reg_reg( { r0, true }, { r1, true } );

            if ( !result )
                return false;

            info->sizes.push_back( s0 );
            info->sizes.push_back( s1 );

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto& sizes = instruction->handler->instruction_info->sizes;

            auto [t0, t1] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );
            auto [t2, t3, t4] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8, sizes[ 0 ] * 8 );
            auto [t5, t6] = block->tmp( sizes[ 0 ] * 8, sizes[ 1 ] * 8 );

            // TODO: fix this!!
            // (DST >> SHIFT) | (DST << (N - SHIFT))
            // CF = DST >> ( N - SHIFT )
            block
                ->pop( t0 )
                ->pop( t1 )

                // t2 = DST << SHIFT
                ->mov( t2, t0 )
                ->bshl( t2, t1 )

                // t3 = (N - SHIFT + 1)
                ->mov( t3, t0.bit_count )
                ->sub( t3, t1 )
                // t6 = N - SHIFT
                ->mov( t6, t3 )
                ->add( t3, 1 )

                // t4 = DST >> (N - SHIFT + 1)
                ->mov( t4, t0 )
                ->bshr( t4, t3 )

                // t2 = (DST << SHIFT) | (DST >> (N - SHIFT + 1))
                ->bor( t2, t4 )

                // t5 = DST >> ( N - SHIFT )
                ->mov( t5, t0 )
                ->bshr( t5, t6 )

                // CF = ( DST >> ( N - SHIFT ) ) != 0
                ->ifs( flags::CF, t5, 1 )

                ->push( t2 )
                ->pushf();
        }
    };

    inline const vm_instruction_desc vmexit =
    {
        "VMEXIT", 0, vm_instruction_vmexit,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            vm_analysis_context stream_context = vm_analysis_context( stream, state );

            x86_reg rsp = X86_REG_RSP;
            x86_reg vsp = state->stack_reg;

            info->custom_data = std::vector<x86_reg>();

            auto result = ( &stream_context )
                // MOV RSP, VSP
                ->mov_reg_reg( { rsp, true }, { vsp, true } )

                // (n...) POP %reg
                ->track_register_pops( &info->custom_data.get<std::vector<x86_reg>>(), [&]()
                                       {
                                           // RET
                                           return ( &stream_context )
                                               ->id( X86_INS_RET );
                                       } );

            if ( !result || info->custom_data.get<std::vector<x86_reg>>().size() < 10 )
                return false;

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            // Pop all registers back.
            //
            for ( x86_reg reg : instruction->handler->instruction_info->custom_data.get<std::vector<x86_reg>>() )
            {
                // If reg is EFLAGS, pop the vtil virtual flags register instead to aid in optimization.
                //
                if ( reg == X86_REG_EFLAGS )
                {
                    block->pop( vtil::REG_FLAGS );
                    continue;
                }

                block->pop( reg );
            }
        }
    };

    inline const vm_instruction_desc ret =
    {
        "RET", 0, vm_instruction_branch | vm_instruction_updates_state,
        []( const vm_state* state, instruction_stream* stream, vm_instruction_info* info ) -> bool
        {
            instruction_stream initial_copied_stream = *stream;
            vm_analysis_context stream_context = vm_analysis_context( &initial_copied_stream, state );

            x86_reg reg, flow_reg;
            int64_t initial_disp = 0;
            size_t reg_size = 8;
            uint64_t new_flow_rva;

            x86_reg stack_reg = state->stack_reg;

            auto result = ( &stream_context )
                // MOV(ZX) %reg_size:%reg, [VSP + %initial_disp]
                ->fetch_vsp( { reg, false }, { reg_size, true }, { initial_disp, true } )

                // TRACK:
                // MOV/XCHG %reg, %reg
                ->simple_track_registers( { &stack_reg }, [&]()
                                          {
                                              return ( &stream_context )
                                                  ->set_flow( { flow_reg, false }, { new_flow_rva, false } );
                                          } );

            if ( !result )
                return false;

            // Now we must determina the new vm_state, starting with the new
            // vip register. We will be looking for different information in
            // the same span of instructions, so we will have to make a fresh
            // copy of the instruction stream on each query.
            //
            // We can not use vm_analysis_context any more, as the vm_state
            // is not valid until we update it. So we must only use the raw
            // analysis_context, and specify special registers manually.
            //
            instruction_stream copied_stream = initial_copied_stream;
            analysis_context post_exec_context = analysis_context( &copied_stream );

            x86_reg vip_reg, vip_fetch_reg;
            size_t vip_fetch_size = 4;

            result = ( &post_exec_context )
                // MOV %vip_fetch_size:%vip_fetch-reg, [%vip_reg]
                ->fetch_memory( { vip_fetch_reg, false }, { vip_reg, false }, { vip_fetch_size, true } );

            if ( !result )
                return false;

            // Determine new VIP fetch direction and new rolling key register.
            //
            copied_stream = *stream;
            post_exec_context = analysis_context( &copied_stream );

            x86_reg rolling_key_reg;
            x86_insn vip_offset_ins;

            uint64_t imm = 0;
            x86_reg reloc_reg;

            result = ( &post_exec_context )
                // MOV %reloc_reg, 0
                ->generic_reg_imm( X86_INS_MOVABS, { reloc_reg, false }, { imm, false/*true*/ }, false )

                // SUB %rolling_key_reg, %reloc_reg
                ->generic_reg_reg( X86_INS_SUB, { rolling_key_reg, false }, { reloc_reg, true }, false )

                // ADD/SUB %vip_reg, %vip_fetch_size
                //    ^ %vip_offset_ins
                ->update_reg( { vip_offset_ins, false }, { vip_reg, true }, { vip_fetch_size, true } )
                
                // XOR %vip_fetch_reg, %rolling_key_reg
                ->begin_encryption( { vip_fetch_reg, true }, { rolling_key_reg, true } );

            if ( !result )
                return false;

            //
            // stream needs to be updated to where the handler ends and bridge begins.
            // Luckily enough, we just so happen to be exactly there in our original
            // stream object, after the first template query. So no need to modify anything!
            //

            // Store the updated state as instruction information, for future use.
            //
            info->updated_state = { stack_reg, vip_reg, state->context_reg, rolling_key_reg, flow_reg, vip_offset_ins == X86_INS_ADD ? vm_direction_down : vm_direction_up, new_flow_rva };

            return true;
        },

        []( vtil::basic_block* block, const vm_instruction* instruction ) -> void
        {
            auto t0 = block->tmp( 64 );

            block
                ->pop( t0 );

            // If the direction is up, subtract 1 from the block destination if the direction
            // is upwards. This is in order to prevent basic block collisions when different
            // directions point to the same block EA.
            // Thanks to Can for this bugfix!
            //
            if ( instruction->handler->instruction_info->updated_state->direction == vm_direction_up )
                block->sub( t0, 1 );

            block
                ->jmp( t0 );
        }
    };

    // A concated list of all virtual instructions.
    //
    inline const vm_instruction_desc* all_virtual_instructions[] =
    {
        &push, &pop,
        &pushstk, &popstk,
        &ldd, &str,
        &add, &nand, &nor,
        &shld, &shrd, &shl, &shr,
        &div, &idiv,
        &mul, &imul,
        &ret,
        &nop, &popf,
        &vmexit,
        &rdtsc, &cpuid,
        &pushreg, &popreg,
        &lockor
    };
}