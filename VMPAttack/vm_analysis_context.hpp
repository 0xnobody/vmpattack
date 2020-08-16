#pragma once
#include "analysis_context.hpp"
#include "vm_state.hpp"

namespace vmpattack
{
    // This class provides extra pattern finding templates for VM analysis, 
    // by matching registers to a vm_state structure.
    //
    class vm_analysis_context : public analysis_context
    {
    private:
        // Stack alignment used for stack operations.
        //
        const uint8_t stack_alignment = 2;

        // The vm_state used for providing the analysis context with
        // specific registers for different pattern templates.
        // Non-owning.
        //
        const vm_state* state;

    public:
        // Consructor via an instruction_stream pointer, and a vm_state
        // pointer. Both are non-owned.
        //
        vm_analysis_context( instruction_stream* stream, const vm_state* state )
            : analysis_context( stream ), state( state )
        {}

        // Matches for an explicitly matched mov of another register into the vip register.
        // Constraints: reg:    the register that is mov'ed into vip.
        //
        vm_analysis_context* set_vip( inout<x86_reg> reg )
        {
            if ( this == nullptr ) return nullptr;

            // Drop const.
            //
            x86_reg vip_reg = state->vip_reg;

            return generic_reg_reg( X86_INS_MOV, { vip_reg, true }, reg, false )
                ->cast<vm_analysis_context*>();
        }

        // Matches for an instruction that adds an immediate value to the VSP register.
        // Constraints: imm:    the immediate value added.
        //
        vm_analysis_context* add_vsp( inout<uint64_t> imm )
        {
            if ( this == nullptr ) return nullptr;

            // Drop const.
            //
            x86_reg stack_reg = state->stack_reg;

            return generic_reg_imm( X86_INS_ADD, { stack_reg, true }, imm, false )
                ->cast<vm_analysis_context*>();
        }

        // Matches for instructions that either increment or decrement the VIP
        // via ADD or SUB instructions, using a immedaite value.
        // Constraints: id:             the id of the matched instruction (either ADD or SUB)
        //              offset:         the amount the vip is offseted by.
        //
        vm_analysis_context* update_vip( inout<x86_insn> id, inout<uint64_t> offset )
        {
            if ( this == nullptr ) return nullptr;

            // Drop const.
            //
            x86_reg vip_reg = state->vip_reg;

            // ADD VIP, %offset
            //      or
            // SUB VIP, %offset
            //  ^ %id
            //
            return update_reg( id, { vip_reg, true }, offset )
                ->cast<vm_analysis_context*>();
        }

        // Matches for instructions that offset the vip register via either a lea or add instruction.
        // Constraints: id:             the id of the matched instruction (either ADD or SUB)
        //              offset:         the register the vip is offseted by.
        //
        vm_analysis_context* offset_vip( inout<x86_insn> id, inout<x86_reg> offset )
        {
            if ( this == nullptr ) return nullptr;

            // Drop const.
            //
            x86_reg vip_reg = state->vip_reg;

            // lea VIP, 8:[%reg + %offset]
            //      or
            // add VIP, %offset
            // ^ %id
            //
            return offset_reg( id, { vip_reg, true }, offset )
                ->cast<vm_analysis_context*>();
        }

        // Matches for instructions that fetch memory from the vip stream.
        // Constraints: reg:    the register the memory is stored in.
        //              size:   the size of the memory that was read.
        //
        vm_analysis_context* fetch_vip( inout<x86_reg> reg, inout<size_t> size )
        {
            // MOV(ZX) %reg, %size:[VIP]
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_MOV
                                && instruction->ins.id != X86_INS_MOVZX)
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              // Memory base is vip, there's no index.
                              //
                              if ( instruction->operand( 1 ).mem.base != state->vip_reg
                                || instruction->operand( 1 ).mem.index != X86_REG_INVALID )
                                  return false;

                              // %size == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 1 ).size != size.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;
                              size.first = instruction->operand( 1 ).size;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_MEM } )
                ->cast<vm_analysis_context*>();
        }

        // Matches for instructions that fetch memory from the virtual stack.
        // Constraints: dst:    the destination register.
        //              size:   the size of the destination that was read.
        //              disp:   the stack displacement.
        //
        vm_analysis_context* fetch_vsp( inout<x86_reg> dst, inout<size_t> size, inout<int64_t> disp )
        {
            // mov(zx) %size:%dst, [VSP + %disp]
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_MOV
                                && instruction->ins.id != X86_INS_MOVZX)
                                  return false;

                              // %dst == dst
                              //
                              if ( dst.second )
                                  if ( instruction->operand( 0 ).reg != dst.first )
                                      return false;

                              // %size == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 0 ).size != size.first )
                                      return false;


                              // Memory base is vsp, there's no index.
                              //
                              if ( instruction->operand( 1 ).mem.base != state->stack_reg
                                || instruction->operand( 1 ).mem.index != X86_REG_INVALID )
                                  return false;

                              // %disp == disp
                              //
                              if ( disp.second )
                                  if ( instruction->operand( 1 ).mem.disp != disp.first )
                                      return false;

                              dst.first = instruction->operand( 0 ).reg;
                              size.first = instruction->operand( 0 ).size;
                              disp.first = instruction->operand( 1 ).mem.disp;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_MEM } )
                ->cast<vm_analysis_context*>();
        }

        // Matches for instructions that stores memory into the virtual stack.
        // Constraints: src:    the source register. Comparison via base.
        //              size:   the size of the destination that was written.
        //
        vm_analysis_context* store_vsp( inout<x86_reg> src, inout<size_t> size )
        {
            // mov %size:[VSP], %src
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_MOV )
                                  return false;

                              // Memory base is vsp, there's no index, and there's no disp.
                              //
                              if ( instruction->operand( 0 ).mem.base != state->stack_reg
                                   || instruction->operand( 0 ).mem.index != X86_REG_INVALID
                                   || instruction->operand( 0 ).mem.disp != 0)
                                  return false;

                              // %src == src
                              //
                              if ( src.second )
                                  if ( !register_base_equal( instruction->operand( 1 ).reg, src.first ) )
                                      return false;

                              // %size == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 0 ).size != size.first )
                                      return false;

                              src.first = instruction->operand( 1 ).reg;
                              size.first = instruction->operand( 0 ).size;

                              return true;
                          }, 2, { X86_OP_MEM, X86_OP_REG } )
                ->cast<vm_analysis_context*>();
        }

        // Matches for instructions that fetch memory from the virtual context, optionally displaced by a register.
        // Constraints: dst:    the destination register.
        //              size:   the size of the virtual context that was read.
        //              disp:   the optional context displacement register. Comparison via base.
        //
        vm_analysis_context* fetch_ctx( inout<x86_reg> dst, inout<size_t> size, inout<x86_reg> disp )
        {
            // mov(zx) %dst, %size:[VCTX + %disp]
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_MOV
                                && instruction->ins.id != X86_INS_MOVZX)
                                  return false;

                              // %dst == dst
                              //
                              if ( dst.second )
                                  if ( instruction->operand( 0 ).reg != dst.first )
                                      return false;

                              // %size == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 1 ).size != size.first )
                                      return false;


                              // Scale is 1, disp is 0, base is vcontext reg.
                              //
                              if ( instruction->operand( 1 ).mem.base != state->context_reg
                                || instruction->operand( 1 ).mem.disp != 0
                                || instruction->operand( 1 ).mem.scale != 1)
                                  return false;

                              // %disp == disp
                              //
                              if ( disp.second )
                                  if ( !register_base_equal( instruction->operand( 1 ).mem.index, disp.first ) )
                                      return false;

                              dst.first = instruction->operand( 0 ).reg;
                              size.first = instruction->operand( 1 ).size;
                              disp.first = instruction->operand( 1 ).mem.index;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_MEM } )
                ->cast<vm_analysis_context*>();
        }

        // Matches for instructions that stores memory into the virtual context, optionally offsetted by a register.
        // Constraints: src:    the source register. Comparison via base.
        //              size:   the size of the destination that was written.
        //              disp:   the optional context displacement register. Comparison via base.
        //
        vm_analysis_context* store_ctx( inout<x86_reg> src, inout<size_t> size, inout<x86_reg> disp )
        {
            // mov %size:[VCTX + %disp], %src
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_MOV )
                                  return false;

                              // Memory base is vsp, scale is 1, and there's no disp.
                              //
                              if ( instruction->operand( 0 ).mem.base != state->context_reg
                                   || instruction->operand( 0 ).mem.scale != 1
                                   || instruction->operand( 0 ).mem.disp != 0 )
                                  return false;

                              // %src == src
                              //
                              if ( src.second )
                                  if ( !register_base_equal( instruction->operand( 1 ).reg, src.first ) )
                                      return false;

                              // %size == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 0 ).size != size.first )
                                      return false;

                              // %disp == disp
                              //
                              if ( disp.second )
                                  if ( !register_base_equal( instruction->operand( 0 ).mem.index, disp.first ) )
                                      return false;

                              src.first = instruction->operand( 1 ).reg;
                              size.first = instruction->operand( 0 ).size;
                              disp.first = instruction->operand( 0 ).mem.index;

                              return true;
                          }, 2, { X86_OP_MEM, X86_OP_REG } )
                ->cast<vm_analysis_context*>();
        }

        // Generates an arithmetic expression for the given register, advancing the stream to wherever the encryption sequence ends.
        //
        vm_analysis_context* record_encryption( x86_reg reg, arithmetic_expression* expression )
        {
            if ( this == nullptr ) return nullptr;

            // Drop const.
            //
            x86_reg rolling_key_reg = state->rolling_key_reg;

            return
                // Advance stream to where the encryption sequence begins.
                //
                begin_encryption( { reg, true }, { rolling_key_reg, true } )

                // Record any operations done to the register.
                //
                ->record_expression( reg, expression, [&]()
                                     {
                                         // Advance stream to where the encryption sequence ends.
                                         //
                                         return end_encryption( { reg, true }, { rolling_key_reg, true } );
                                     } )
                ->cast<vm_analysis_context*>();
        }
    };
}