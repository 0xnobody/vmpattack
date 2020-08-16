#pragma once
#include <cstdint>
#include <capstone/capstone.h>

namespace vmpattack
{
    // Specifies the direction of the Fetch->Decode->Execute loop.
    //
    enum vm_direction : uint8_t
    {
        // Specified that the vip is decremented after instruction.
        // execution (ie. via SUB)
        //
        vm_direction_up,

        // Specified that the vip is incremented after instruction
        // execution (ie. via ADD).
        //
        vm_direction_down,
    };

    // This struct describes the current translation state of the virtual machine
    // ie. the assignation of registers, the vip direction, and the handler offset base.
    //
    struct vm_state
    {
        // The virtual stack register.
        //
        x86_reg stack_reg;

        // The virtual instruction pointer.
        //
        x86_reg vip_reg;

        // The virtual context register.
        //
        x86_reg context_reg;

        // The rolling decryption key register.
        //
        x86_reg rolling_key_reg;

        // The absolute EIP / RIP that the handlers are offseted from.
        //
        x86_reg flow_reg;

        // The current fetch direction.
        //
        vm_direction direction;

        // The absolute EIP / RIP of the block's base, by which the handlers are
        // offseted by.
        //
        uint64_t flow;

        // Full constructor.
        //
        vm_state( x86_reg stack_reg, x86_reg vip_reg, x86_reg context_reg, x86_reg rolling_key_reg, x86_reg flow_reg, vm_direction direction, uint64_t flow )
            : stack_reg( stack_reg ), vip_reg( vip_reg ), context_reg( context_reg ), rolling_key_reg( rolling_key_reg ), flow_reg( flow_reg ), direction( direction ), flow( flow )
        {}
    };
}