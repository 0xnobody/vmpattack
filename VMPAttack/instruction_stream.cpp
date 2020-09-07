#include "instruction_stream.hpp"

namespace vmpattack
{
    // Advances the stream, incrementing index and returning the
    // instruction ptr.
    //
    const instruction* instruction_stream::next()
    {
        // Check if within bounds.
        //
        if ( begin + index > end )
            return nullptr;

        // Fetch instruction.
        //
        auto& ins = instructions[ begin + index ];

        // Increment index.
        //
        index++;

        // Return a non-owning pointer to the instruction.
        //
        return ins.get();
    }
}