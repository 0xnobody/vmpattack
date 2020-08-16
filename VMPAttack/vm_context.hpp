#pragma once
#include <cstdint>
#include <memory>
#include <vtil/utility>
#include "vm_state.hpp"

namespace vmpattack
{
    // This class describes the virtual machine's execution at any single moment. 
    //
    class vm_context
    {
    public:
        // An owning pointer to the current state.
        //
        std::unique_ptr<vm_state> state;

        // The current value of the rolling key.
        //
        uint64_t rolling_key;

        // The current absolute value of the virtual instruction pointer.
        //
        uint64_t vip;

        // Constructor. Takes ownership of state.
        //
        vm_context( std::unique_ptr<vm_state> state, uint64_t rolling_key, uint64_t vip )
            : state( std::move( state ) ), rolling_key( rolling_key ), vip( vip )
        {}

        // Fetches an arbitrarily-sized value from the current virtual instruction
        // pointer, and increments/decrements it by that size.
        // Size given in bytes.
        //
        template <typename T>
        T fetch( size_t size )
        {
            // Make sure fetched bytes can fit in result
            //
            fassert( sizeof( T ) >= size && "Provided return type size must be equal or greater than size given in parameter." );

            // If direction is going upwards, we must first decrement the vip
            // because we are not on the correct position currently.
            //
            if ( state->direction == vm_direction_up )
                vip -= size;

            // Zero-initialize the read value, then populate it via a copy from the vip stream.
            //
            T read_value = {};
            memcpy( &read_value, ( void* )vip, size );

            // If direction is going downwards, we must update the vip AFTER the read
            // is complete.
            //
            if ( state->direction == vm_direction_down )
                vip += size;

            return read_value;
        }
    };
}