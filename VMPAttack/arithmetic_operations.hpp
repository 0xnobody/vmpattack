#pragma once
#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include "arithmetic_operation_desc.hpp"
#include "instruction.hpp"

namespace vmpattack
{
    //
    // This file describes all of the arithmetic operations used for mutation by
    // VMProtect.
    //

    namespace arithmetic_descriptors
    {
        // Addition / Subtraction.
        //
        inline const arithmetic_operation_desc add = { X86_INS_ADD,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return d + a[ 0 ]; } };
        inline const arithmetic_operation_desc sub = { X86_INS_SUB,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return d - a[ 0 ]; } };

        // Bitwise Byte-Swaps.
        //
        //         inline const arithmetic_operation_desc bswap_64 = { X86_INS_BSWAP,  0, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return __bswap_64( d ); }, 8 };
        // inline const arithmetic_operation_desc bswap_32 = { X86_INS_BSWAP,  0, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return __bswap_32( ( uint32_t )d ); }, 4 };
        // inline const arithmetic_operation_desc bswap_16 = { X86_INS_BSWAP,  0, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return __bswap_16( ( uint16_t )d ); }, 2 };
        inline const arithmetic_operation_desc bswap_64 = { X86_INS_BSWAP,  0, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _byteswap_uint64( d );
#else
            return __bswap_64( d );
#endif
        }, 8 };
        inline const arithmetic_operation_desc bswap_32 = { X86_INS_BSWAP,  0, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _byteswap_ulong( ( uint32_t )d );
#else
            return __bswap_32( ( uint32_t )d );
#endif
        }, 4 };
        inline const arithmetic_operation_desc bswap_16 = { X86_INS_BSWAP,  0, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _byteswap_ushort( ( uint16_t )d );
#else
            return __bswap_16( ( uint16_t )d );
#endif
        }, 2 };

        // Incement / Decrement.
        //
        inline const arithmetic_operation_desc inc = { X86_INS_INC,    0, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return ++d; } };
        inline const arithmetic_operation_desc dec = { X86_INS_DEC,    0, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return --d; } };

        // Bitwise NOT / NEG / XOR.
        //
        inline const arithmetic_operation_desc bnot = { X86_INS_NOT,    0, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return ~d; } };
        inline const arithmetic_operation_desc bneg = { X86_INS_NEG,    0, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return ( uint64_t )-( int64_t )d; } };
        inline const arithmetic_operation_desc bxor = { X86_INS_XOR,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t { return d ^ a[ 0 ]; } };

        // Left Bitwise Rotations.
        //
        inline const arithmetic_operation_desc brol_64 = { X86_INS_ROL,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotl64( d, ( int )a[ 0 ] );
#else
            return __rolq( d, ( int )a[ 0 ] );
#endif
        }, 8 };
        inline const arithmetic_operation_desc brol_32 = { X86_INS_ROL,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotl( ( uint32_t )d, ( int )a[ 0 ] );
#else
            return __rold( ( uint32_t )d, ( int )a[ 0 ] );
#endif
        }, 4 };
        inline const arithmetic_operation_desc brol_16 = { X86_INS_ROL,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotl16( ( uint16_t )d, ( uint8_t )a[ 0 ] );
#else
            return __rolw( ( uint16_t )d, ( uint8_t )a[ 0 ] );
#endif
        }, 2 };
        inline const arithmetic_operation_desc brol_8 = { X86_INS_ROL,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotl8( ( uint8_t )d, ( uint8_t )a[ 0 ] );
#else
            return __rolb( ( uint8_t )d, ( uint8_t )a[ 0 ] );
#endif
        }, 1 };

        // Right Bitwise Rotations.
        //
        inline const arithmetic_operation_desc bror_64 = { X86_INS_ROR,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotr64( d, ( int )a[ 0 ] );
#else
            return __rorq( d, ( int )a[ 0 ] );
#endif
        }, 8 };
        inline const arithmetic_operation_desc bror_32 = { X86_INS_ROR,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotr( ( uint32_t )d, ( int )a[ 0 ] );
#else
            return __rord( ( uint32_t )d, ( int )a[ 0 ] );
#endif
        }, 4 };
        inline const arithmetic_operation_desc bror_16 = { X86_INS_ROR,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotr16( ( uint16_t )d, ( uint8_t )a[ 0 ] );
#else
            return __rorw( ( uint16_t )d, ( uint8_t )a[ 0 ] );
#endif
        }, 2 };
        inline const arithmetic_operation_desc bror_8 = { X86_INS_ROR,    1, []( uint64_t d, const uint64_t a[] ) -> uint64_t {
#ifdef _WIN32
            return _rotr8( ( uint8_t )d, ( uint8_t )a[ 0 ] );
#else
            return __rorb( ( uint8_t )d, ( uint8_t )a[ 0 ] );
#endif
        }, 1 };

        // List of all operation descriptors.
        //
        inline const arithmetic_operation_desc* all[] =
        {
            &add, &sub,
            &bswap_64, &bswap_32, &bswap_16,
            &inc, &dec,
            &bnot, &bneg, &bxor,
            &brol_64, &brol_32, &brol_16, &brol_8,
            &bror_64, &bror_32, &bror_16, &bror_8
        };
    }

    // Fetches the appropriate arithmetic operation descriptor for the given instruction, or nullptr otherwise.
    //
    inline const arithmetic_operation_desc* operation_desc_from_instruction( const instruction* instruction )
    {
        // Loop through full operation descriptor list.
        //
        for ( auto descriptor : arithmetic_descriptors::all )
        {
            // Check if the descriptor target instruction is equal to the instruction given.
            //
            if ( descriptor->insn == instruction->ins.id )
            {
                // If the descriptor has a specified input size, ensure it is equal to the input operand, which
                // is always the first operand.
                //
                if ( descriptor->input_size.has_value() 
                     && descriptor->input_size.value() != instruction->ins.detail->x86.operands[ 0 ].size )
                {
                    // If not equal, continue search.
                    continue;
                }

                return descriptor;
            }
        }

        // Nothing found; return nullptr.
        //
        return nullptr;
    }
}