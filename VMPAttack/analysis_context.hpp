#pragma once
#include <cstdint>
#include <memory>
#include <tuple>
#include "instruction_stream.hpp"
#include "arithmetic_expression.hpp"
#include "arithmetic_operations.hpp"
#include "disassembler.hpp"
#include "instruction_utilities.hpp"

namespace vmpattack
{
    // Allows specification if the argument is an _in_ or _out_ argument.
    // If .second is true, it behaves as an _in_ variable.
    // Otherwise, it behaves as an _out_ variable.
    //
    // While this behaviour is indeed only useful at compile time, and could very 
    // possibly be implemented via templates and metaprogramming, this std::pair
    // runtime approach was chosen as it is believed that, in this particular case,
    // its simplicity is more important than any minor performance losses.
    //
    template <typename T>
    using inout = std::pair<T&, bool>;

    // This class walks over instruction_stream to provide analysis
    // capabilities. These include template pattern matching, arithmetic expresion
    // generation, and more.
    //
    class analysis_context
    {
    private:
        // The current instruction stream, used for analysis.
        // Non-owning.
        //
        instruction_stream* stream;

        // The arithmetic expression, optionally used for tracking arithmetic
        // operations on a single register.
        // Non-owning.
        //
        arithmetic_expression* expression;

        // The target register used for said arithmetic_expression, or
        // X86_REG_INVALID if not relevant.
        //
        x86_reg expression_register;

        // The registers used for simple tracking among MOV / XCHG %reg, %reg.
        //
        std::vector<x86_reg*> tracked_registers;

        // Vector used to record any stack pushes.
        //
        std::vector<x86_reg>* pushed_registers;

        // Vector used to record any stack pops.
        //
        std::vector<x86_reg>* popped_registers;

        // Processes the instruction, updating any properties that the instruction
        // may change.
        //
        void process( const instruction* instruction );

    protected:
        // A helper to pattern match the instruction for a given lambda template.
        // Allows for specification of optional operand count / type filters.
        // If specified, parameter operand_types size must match num_operands.
        //
        template <typename T>
        analysis_context* match( T match, std::optional<uint32_t> num_operands = {}, std::vector<std::optional<x86_op_type>> operand_types = {} )
        {
            fassert( operand_types.size() == 0 || operand_types.size() == num_operands && "A type (even empty) must be specified for each operand." );

            // If we are in an invalid/dead chain, just return nullptr until we
            // reach the end.
            //
            if ( this == nullptr ) return nullptr;

            while ( auto instruction = stream->next() )
            {
                // Process the instruction before anything else
                //
                process( instruction );

                // Filtering only required if num_operands is specified
                //
                if ( num_operands )
                {
                    // Make sure number of operands matches
                    //
                    if ( instruction->operand_count() != *num_operands )
                        continue;

                    // Make sure operand types, if specified, match
                    //
                    bool operand_type_mismatch = false;
                    for ( uint32_t i = 0; i < *num_operands; i++ )
                    {
                        auto& target_type = operand_types[ i ];

                        // If type is specified, and does not match
                        //
                        if ( target_type && target_type != instruction->operand_type( i ) )
                        {
                            // Flip flag to skip the instruction
                            //
                            operand_type_mismatch = true;
                            break;
                        }
                    }

                    // Skip instruction is flag flipped
                    if ( operand_type_mismatch )
                        continue;
                }

                // Try to match the instruction.
                // If matched, end the search, otherwise, continue searching
                //
                if ( match( instruction ) )
                    return this;
            }

            // No match found - return nullptr, indicating a failed chain.
            //
            return nullptr;
        }

    public:
        // Construct the analysis_context via an instruction_stream pointer.
        // The pointer must stay valid for the lifetime of the object.
        //
        analysis_context( instruction_stream* stream )
            : stream( stream ), expression( nullptr ), expression_register( X86_REG_INVALID ), tracked_registers{}, pushed_registers( nullptr ), popped_registers( nullptr )
        {}

        // Tracks the given registers along simple MOV / XCHG %reg, %reg instructions.
        // Updates the given registers on assignment during instruction step.
        //
        template <typename T>
        analysis_context* simple_track_registers( std::vector<x86_reg*> target_regs, T func )
        {
            if ( this == nullptr ) return nullptr;

            tracked_registers = target_regs;

            analysis_context* result = func();

            tracked_registers.clear();

            return result;
        }

        // Initializes the analysis context's arithmetic expression, and starts
        // recording the given register's arithmetic operations. Then invokes the
        // provided function, and removes the tracking for the expression after execution.
        //
        analysis_context* record_expression( x86_reg target_reg, arithmetic_expression* expr, std::function<analysis_context*()> func )
        {
            if ( this == nullptr ) return nullptr;

            expression_register = target_reg;
            expression = expr;

            analysis_context* result = func();

            expression_register = X86_REG_INVALID;
            expression = nullptr;

            return result;
        }

        // Tracks any stack pushes, appending their registers to the given vector.
        // Uses the EFLAGS registers for PUSHFQ/PUSHFD/PUSHF.
        //
        template <typename T>
        analysis_context* track_register_pushes( std::vector<x86_reg>* in_pushed_registers, T func )
        {
            if ( this == nullptr ) return nullptr;

            pushed_registers = in_pushed_registers;

            analysis_context* result = func();

            pushed_registers = nullptr;

            return result;
        }

        // Tracks any stack pops, appending their registers to the given vector.
        // Uses the EFLAGS registers for PUSHFQ/PUSHFD/PUSHF.
        //
        template <typename T>
        analysis_context* track_register_pops( std::vector<x86_reg>* in_popped_registers, T func )
        {
            if ( this == nullptr ) return nullptr;

            popped_registers = in_popped_registers;

            analysis_context* result = func();

            popped_registers = nullptr;

            return result;
        }


        // Attempts to dynamic_cast the object to the given type.
        //
        template <typename T>
        T cast()
        {
            return static_cast< T >( this );
        }

        // Aligns a given uint64_t to the given modulus.
        //
        analysis_context* align( uint64_t& val, uint64_t mod = 2 )
        {
            if ( this == nullptr ) return nullptr;

            uint64_t dif = val % mod;

            val += dif == 0 ? 0 : mod - dif;

            return this;
        }

        // Match via instruction id.
        // Optionally returns a non-owning pointer to the instruction.
        //
        analysis_context* id( x86_insn id, const instruction** ins = nullptr )
        {
            return match( [&]( const instruction* instruction )
                          {
                              bool match = instruction->ins.id == id;
                              
                              if ( match && ins )
                                  *ins = instruction;

                              return match;
                          } );
        }

        // Matches for a PUSH %reg instruction.
        // Constraints: %reg:   the register pushed.
        //
        analysis_context* push( inout<x86_reg> reg )
        {
            // PUSH %reg
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_PUSH )
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;

                              return true;
                          }, 1, { X86_OP_REG } );
        }

        // Matches for a generic instruciton with 1 register operand.
        // If argument match_bases is true, reigster comparison is done via bases. Otherwise, it is done via
        // a strict == comparison.
        // Constraints: id:     the instruction's id.
        //              reg:    the first operand's register. Comparison via base.
        //
        analysis_context* generic_reg( x86_insn id, inout<x86_reg> reg, bool match_bases )
        {
            // %id %reg, %reg1
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != id )
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( match_bases 
                                       ? !register_base_equal( instruction->operand( 0 ).reg, reg.first ) 
                                       : instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;

                              return true;
                          }, 1, { X86_OP_REG } );
        }

        // Templates for single register-operand instructions.
        //
        analysis_context* not_reg( inout<x86_reg> dst, bool match_bases = true )     { return generic_reg( X86_INS_NOT, dst, match_bases ); }
        analysis_context* div_reg( inout<x86_reg> dst, bool match_bases = true )     { return generic_reg( X86_INS_DIV, dst, match_bases ); }
        analysis_context* idiv_reg( inout<x86_reg> dst, bool match_bases = true )    { return generic_reg( X86_INS_IDIV, dst, match_bases ); }
        analysis_context* mul_reg( inout<x86_reg> dst, bool match_bases = true )     { return generic_reg( X86_INS_MUL, dst, match_bases ); }
        analysis_context* imul_reg( inout<x86_reg> dst, bool match_bases = true )    { return generic_reg( X86_INS_IMUL, dst, match_bases ); }

        // Matches for a generic instruciton with 2 register operands.
        // If argument match_bases is true, reigster comparison is done via bases. Otherwise, it is done via
        // a strict == comparison.
        // Constraints: id:     the instruction's id.
        //              reg:    the first operand's register. Comparison via base.
        //              reg1:   the second operand's register. Comparison via base.
        //
        analysis_context* generic_reg_reg( x86_insn id, inout<x86_reg> reg, inout<x86_reg> reg1, bool match_bases )
        {
            // %id %reg, %reg1
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != id )
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( match_bases
                                       ? !register_base_equal( instruction->operand( 0 ).reg, reg.first )
                                       : instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              // %reg1 == reg1
                              //
                              if ( reg1.second )
                                  if ( match_bases
                                       ? !register_base_equal( instruction->operand( 1 ).reg, reg1.first )
                                       : instruction->operand( 1 ).reg != reg1.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;
                              reg1.first = instruction->operand( 1 ).reg;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_REG } );
        }

        // Templates for double register-operand instructions.
        //
        analysis_context* mov_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_MOV, dst, src, match_bases ); }
        analysis_context* xor_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_XOR, dst, src, match_bases ); }
        analysis_context* add_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_ADD, dst, src, match_bases ); }
        analysis_context* shl_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_SHL, dst, src, match_bases ); }
        analysis_context* shr_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_SHR, dst, src, match_bases ); }
        analysis_context* or_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true)   { return generic_reg_reg( X86_INS_OR, dst, src, match_bases ); }
        analysis_context* and_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_AND, dst, src, match_bases ); }
        analysis_context* rcl_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_RCL, dst, src, match_bases ); }
        analysis_context* rcr_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, bool match_bases = true ) { return generic_reg_reg( X86_INS_RCR, dst, src, match_bases ); }

        // Matches for a generic instruciton with 3 register operands.
        // If argument match_bases is true, reigster comparison is done via bases. Otherwise, it is done via
        // a strict == comparison.
        // Constraints: id:     the instruction's id.
        //              reg:    the first operand's register. Comparison via base.
        //              reg1:   the second operand's register. Comparison via base.
        //              reg2:   the third operand's register. Comparison via base.
        //
        analysis_context* generic_reg_reg_reg( x86_insn id, inout<x86_reg> reg, inout<x86_reg> reg1, inout<x86_reg> reg2, bool match_bases )
        {
            // %id %reg, %reg1
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != id )
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( match_bases
                                       ? !register_base_equal( instruction->operand( 0 ).reg, reg.first )
                                       : instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              // %reg1 == reg1
                              //
                              if ( reg1.second )
                                  if ( match_bases
                                       ? !register_base_equal( instruction->operand( 1 ).reg, reg1.first )
                                       : instruction->operand( 1 ).reg != reg1.first )
                                      return false;

                              // %reg2 == reg2
                              //
                              if ( reg2.second )
                                  if ( match_bases
                                       ? !register_base_equal( instruction->operand( 2 ).reg, reg2.first )
                                       : instruction->operand( 2 ).reg != reg2.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;
                              reg1.first = instruction->operand( 1 ).reg;
                              reg2.first = instruction->operand( 2 ).reg;

                              return true;
                          }, 3, { X86_OP_REG, X86_OP_REG, X86_OP_REG } );
        }

        // Templates for triple register-operand instructions.
        //
        analysis_context* shld_reg_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, inout<x86_reg> shift, bool match_bases = true ) { return generic_reg_reg_reg( X86_INS_SHLD, dst, src, shift, match_bases ); }
        analysis_context* shrd_reg_reg_reg( inout<x86_reg> dst, inout<x86_reg> src, inout<x86_reg> shift, bool match_bases = true ) { return generic_reg_reg_reg( X86_INS_SHRD, dst, src, shift, match_bases ); }

        // Matches for a generic instruciton with 1 register and 1 immediate operand.
        // Constraints: id:     the instruction's id.
        //              reg:    the first operand's register.
        //              imm:    the second operand's imm value.
        //
        analysis_context* generic_reg_imm( x86_insn id, inout<x86_reg> reg, inout<uint64_t> imm, bool match_bases )
        {
            // %id %reg, %reg1
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != id )
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( match_bases
                                       ? !register_base_equal( instruction->operand( 0 ).reg, reg.first )
                                       : instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              // %imm == imm
                              //
                              if ( imm.second )
                                  if ( instruction->operand( 1 ).imm != imm.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;
                              imm.first = instruction->operand( 1 ).imm;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_IMM } );
        }

        // Matches for a mov / movzx of memory at a register into another register.
        // Constraints: dst:    the destination register.
        //              src:    the memory source register.
        //              size:   the size of the destination.
        //
        analysis_context* fetch_memory( inout<x86_reg> dst, inout<x86_reg> src, inout<size_t> size )
        {
            // mov(zx) %size:%dst, [%src]
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_MOV
                                && instruction->ins.id != X86_INS_MOVZX )
                                  return false;

                              // %dst == dst
                              //
                              if ( dst.second )
                                  if ( instruction->operand( 0 ).reg != dst.first )
                                      return false;

                              // %size:%dst == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 0 ).size != size.first )
                                      return false;

                              // %src == src
                              //
                              if ( src.second )
                                  if ( instruction->operand( 1 ).mem.base != src.first )
                                      return false;

                              if ( instruction->operand( 1 ).mem.disp != 0
                                || instruction->operand( 1 ).mem.index != X86_REG_INVALID )
                                  return false;

                              dst.first = instruction->operand( 0 ).reg;
                              size.first = instruction->operand( 0 ).size;
                              src.first = instruction->operand( 1 ).mem.base;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_MEM } );
        }

        // Matches for a mov / movzx of a register into memory at another register.
        // Constraints: dst:    the destination register.
        //              src:    the memory source register.
        //              size:   the size of the source.
        //
        analysis_context* store_memory( inout<x86_reg> dst, inout<x86_reg> src, inout<size_t> size )
        {
            // mov(zx) [%dst], %size:%src
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_MOV
                                && instruction->ins.id != X86_INS_MOVZX )
                                  return false;

                              // %dst == dst
                              //
                              if ( dst.second )
                                  if ( instruction->operand( 0 ).mem.base != dst.first )
                                      return false;

                              // %size: == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 1 ).size != size.first )
                                      return false;

                              // %src == src
                              //
                              if ( src.second )
                                  if ( instruction->operand( 1 ).reg != src.first )
                                      return false;

                              dst.first = instruction->operand( 0 ).mem.base;
                              size.first = instruction->operand( 1 ).size;
                              src.first = instruction->operand( 1 ).reg;

                              return true;
                          }, 2, { X86_OP_MEM, X86_OP_REG } );
        }

        // Matches for a push of memory at a register
        // Constraints: src:    the memory source register.
        //              size:   the size of the source.
        //
        analysis_context* push_memory( inout<x86_reg> src, inout<size_t> size )
        {
            // push %size:[%src]
            //
            return match( [&]( const instruction* instruction )
                          {
                              if ( instruction->ins.id != X86_INS_PUSH )
                                  return false;

                              if ( instruction->operand( 0 ).mem.disp != 0
                                || instruction->operand( 0 ).mem.scale != 1 )
                                  return false;

                              // %size: == size
                              //
                              if ( size.second )
                                  if ( instruction->operand( 0 ).size != size.first )
                                      return false;

                              // %src == src
                              //
                              if ( src.second )
                                  if ( instruction->operand( 0 ).mem.base != src.first )
                                      return false;

                              size.first = instruction->operand( 0 ).size;
                              src.first = instruction->operand( 0 ).mem.base;

                              return true;
                          }, 1, { X86_OP_MEM } );
        }
        // Matches for instructions that either increment or decrement the a given register.
        // via ADD or SUB instructions, using a immedaite value.
        // Constraints: id:             the id of the matched instruction (either ADD or SUB)
        //              reg:            the register that is incremented / decremented.
        //              offset:         the amount the vip is offseted by.
        //
        analysis_context* update_reg( inout<x86_insn> id, inout<x86_reg> reg, inout<uint64_t> offset )
        {
            // ADD %reg, %offset
            //      or
            // SUB %reg, %offset
            //  ^ %id
            //
            return match( [&]( const instruction* instruction )
                          {
                              // ins_id == ADD / SUB
                              //
                              if ( instruction->ins.id != X86_INS_ADD
                                   && instruction->ins.id != X86_INS_SUB )
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              // ins_id == constraint ADD / SUB
                              //
                              if ( id.second )
                                  if ( instruction->ins.id != ( x86_insn )instruction->ins.id )
                                      return false;

                              // %offset == offset
                              //
                              if ( offset.second )
                                  if ( instruction->operand( 1 ).imm != offset.first )
                                      return false;

                              id.first = ( x86_insn )instruction->ins.id;
                              offset.first = instruction->operand( 1 ).imm;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_IMM } );
        }

        // Matches for instructions that offset the given register via either a lea or add instruction.
        // Constraints: id:             the id of the matched instruction (either ADD or SUB)
        //              reg:            the register that is incremented / decremented.
        //              offset_reg:     the register the register is offseted by.
        //
        analysis_context* offset_reg( inout<x86_insn> id, inout<x86_reg> reg, inout<x86_reg> offset_reg )
        {
            // lea %reg, 8:[%reg + %offset_reg]
            //      or
            // add %reg, %offset_reg
            // ^ %id
            //
            return match( [&]( const instruction* instruction )
                          {
                              // lea %reg, 8:[%reg + %offset]
                              //
                              if ( ( !id.second || id.first == X86_INS_LEA ) && instruction->ins.id == X86_INS_LEA )
                              {
                                  // operand( 0 ) == reg && operand( 1 ) == mem
                                  //
                                  if ( instruction->operand( 0 ).type != X86_OP_REG
                                    || instruction->operand( 1 ).type != X86_OP_MEM)
                                      return false;

                                  // %reg == reg
                                  //
                                  if ( reg.second )
                                      if ( instruction->operand( 0 ).reg != reg.first )
                                          return false;

                                  // operand( 1 ).base == %reg && .index != invalid && .disp == 0 && .scale = 1
                                  //
                                  if ( instruction->operand( 1 ).mem.base != instruction->operand( 0 ).reg
                                    || instruction->operand( 1 ).mem.index == X86_REG_INVALID
                                    || instruction->operand( 1 ).mem.disp != 0
                                    || instruction->operand( 1 ).mem.scale != 1)
                                      return false;

                                  // operand( 1 ).index == offset_reg
                                  //
                                  if ( offset_reg.second )
                                      if ( instruction->operand( 1 ).mem.index != offset_reg.first )
                                          return false;

                                  id.first = ( x86_insn )instruction->ins.id;
                                  reg.first = instruction->operand( 0 ).reg;
                                  offset_reg.first = instruction->operand( 1 ).mem.index;

                                  return true;
                              }

                              // add %reg, %offset_reg
                              //
                              if ( ( !id.second || id.first == X86_INS_ADD ) && instruction->ins.id == X86_INS_ADD )
                              {
                                  // operand( 0 ) == reg && operand( 1 ) == reg
                                  //
                                  if ( instruction->operand( 0 ).type != X86_OP_REG
                                    || instruction->operand( 1 ).type != X86_OP_REG )
                                      return false;

                                  // %reg == reg
                                  //
                                  if ( reg.second )
                                      if ( instruction->operand( 0 ).reg != reg.first )
                                          return false;

                                  // operand( 1 ).reg == offset_reg
                                  //
                                  if ( offset_reg.second )
                                      if ( instruction->operand( 1 ).reg != offset_reg.first )
                                          return false;

                                  id.first = ( x86_insn )instruction->ins.id;
                                  reg.first = instruction->operand( 0 ).reg;
                                  offset_reg.first = instruction->operand( 1 ).reg;

                                  return true;
                              }

                              // No matches.
                              //
                              return false;
                          }, {}, {} );
        }

        // Matches for an instruction which begins an encryption/obfuscation sequence, by XORing the given register by the rolling key.
        // Constraints: reg:    the register for which the encryption is being tracked.
        //              rkey:   the register currently holding the rolling key.
        //                      NOTE: the rkey register returned is expanded into the largest architecture size.
        //
        analysis_context* begin_encryption( inout<x86_reg> reg, inout<x86_reg> rkey )
        {
            analysis_context* result = generic_reg_reg( X86_INS_XOR, reg, rkey, true );

            if ( result )
                rkey.first = get_largest_for_arch( rkey.first );

            return result;
        }

        // Matches for an instruction which ends an encryption/obfuscation sequence, by either 1) pushing the rolling key for it to later
        // be XORed, or 2) directly xoring the rolling key by the given register.
        // Constraints: reg:    the register for which the encryption is being tracked. Comparison via base.
        //                      NOTE: reg is only set if the encryption end type is not stack based.
        //              rkey:   the register currently holding the rolling key. Comparison via base.
        //                      NOTE: the rkey register returned is expanded into the largest architecture size.
        //
        analysis_context* end_encryption( inout<x86_reg> reg, inout<x86_reg> rkey )
        {
            // push %rkey
            //      or
            // xor %rkey, %reg
            //
            return match( [&]( const instruction* instruction )
                          {
                              // push %rkey
                              //
                              if ( instruction->ins.id == X86_INS_PUSH )
                              {
                                  // operand( 0 ) == reg
                                  //
                                  if ( instruction->operand( 0 ).type != X86_OP_REG )
                                      return false;

                                  // %rkey == rkey
                                  //
                                  if ( rkey.second )
                                      if ( !register_base_equal( instruction->operand( 0 ).reg, rkey.first ) )
                                          return false;

                                  rkey.first = get_largest_for_arch( instruction->operand( 0 ).reg );

                                  return true;
                              }

                              // xor %rkey, %reg
                              //
                              else if ( instruction->ins.id == X86_INS_XOR )
                              {
                                  // operand( 0 ) == reg && operand( 1 ) == reg
                                  //
                                  if ( instruction->operand( 0 ).type != X86_OP_REG
                                    || instruction->operand( 1 ).type != X86_OP_REG )
                                      return false;

                                  // %rkey == rkey
                                  //
                                  if ( rkey.second )
                                      if ( !register_base_equal( instruction->operand( 0 ).reg, rkey.first ) )
                                          return false;

                                  // %reg == reg
                                  //
                                  if ( reg.second )
                                      if ( !register_base_equal( instruction->operand( 1 ).reg, reg.first ) )
                                          return false;

                                  rkey.first = get_largest_for_arch( instruction->operand( 0 ).reg );
                                  reg.first = instruction->operand( 1 ).reg;

                                  return true;
                              }

                              // No matches.
                              //
                              return false;
                          }, {}, {} );
        }

        // Matches an instruction that fetches the encrypted vip ("stub") from the stack.
        // Constraints: reg:    the register the stub is written into.
        //              offset: the stack offset of the stub.
        //
        analysis_context* fetch_encrypted_vip( inout<x86_reg> reg, inout<uint64_t> offset )
        {
            // MOV %reg, 8: [RSP + %offset]
            //
            return match( [&]( const instruction* instruction )
                          {
                              // ins_id == MOV
                              //
                              if ( instruction->ins.id != X86_INS_MOV )
                                  return false;

                              // .base == rsp && .index = INVALID
                              //
                              if ( instruction->operand( 1 ).mem.base != X86_REG_RSP
                                   || instruction->operand( 1 ).mem.index != X86_REG_INVALID )
                                  return false;

                              // operand( 0 ).reg == reg
                              //
                              if ( reg.second )
                                  if ( instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              // operand( 1 ).disp == offset
                              //
                              if ( offset.second )
                                  if ( instruction->operand( 1 ).mem.disp != offset.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;
                              offset.first = instruction->operand( 1 ).mem.disp;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_MEM } );
        }

        // Matches an instruction that loads the "flow" (ie. the rip of the current instruction) into a register.
        // Constraints: reg:    the register the flow is written into.
        //              flow:   the rva of the flow.
        //
        analysis_context* set_flow( inout<x86_reg> reg, inout<uint64_t> flow )
        {
            // lea %reg, [%rip - {ins_len}]
            //
            return match( [&]( const instruction* instruction )
                          {
                              // ins_id == lea
                              //
                              if ( instruction->ins.id != X86_INS_LEA )
                                  return false;

                              // %reg == reg
                              //
                              if ( reg.second )
                                  if ( instruction->operand( 0 ).reg != reg.first )
                                      return false;

                              // operand( 1 ) is rip offsetted, without any other index.
                              // Disp is -( instruction length ).
                              //
                              if ( instruction->operand( 1 ).mem.base != X86_REG_RIP
                                   || instruction->operand( 1 ).mem.index != X86_REG_INVALID
                                   || instruction->operand( 1 ).mem.disp != -instruction->ins.size )
                                  return false;

                              // %rip - {ins_len} == flow
                              //
                              if ( flow.second )
                                  if ( instruction->ins.address + instruction->operand( 1 ).mem.disp != reg.first )
                                      return false;

                              reg.first = instruction->operand( 0 ).reg;
                              flow.first = instruction->ins.address + instruction->ins.size + instruction->operand( 1 ).mem.disp;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_MEM } );
        }

        // Matches an instruction that allocates the VM's stack by subtracting and immediate value from rsp.
        // Constraints: imm:    the immediate valued subtracted from rsp.
        //
        analysis_context* allocate_stack( inout<uint64_t> imm )
        {
            // sub rsp, %imm
            //
            return match( [&]( const instruction* instruction )
                          {
                              // ins_id == sub
                              //
                              if ( instruction->ins.id != X86_INS_SUB )
                                  return false;

                              // operand( 0 ).reg == rsp
                              //
                              if ( instruction->operand( 0 ).reg != X86_REG_RSP )
                                  return false;

                              // %im == imm
                              //
                              if ( imm.second )
                                  if ( instruction->operand( 1 ).imm == imm.first )
                                      return false;

                              imm.first = instruction->operand( 1 ).imm;

                              return true;
                          }, 2, { X86_OP_REG, X86_OP_IMM } );
        }
    };
}