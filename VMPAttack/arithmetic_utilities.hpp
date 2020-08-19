#pragma once

namespace vmpattack
{
    // Dynamically casts the integral value to the specified byte count.
    //
    template <typename T>
    inline T dynamic_size_cast( T value, size_t bytes )
    {
        if ( bytes == sizeof( T ) )
            return value;

        T mask = ( 1ull << ( bytes * 8ull ) ) - 1ull;

        return value & mask;
    }
}