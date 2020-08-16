#pragma once
#include <cstdint>
#include <memory>
#include "arithmetic_expression.hpp"
#include "instruction_stream.hpp"
#include "vm_state.hpp"
#include "vm_context.hpp"

namespace vmpattack
{
    struct vm_handler;

    // This struct represents the virtual machine handler and entry "bridge", which
    // is responsible for advancing the context by computing the next handler and
    // branching to it.
    //
    struct vm_bridge
    {
        // The RVA of the bridge in image space
        //
        const uint64_t rva;

        // The arithmetic chain used to decrypt the next handler's offset
        //
        const std::unique_ptr<arithmetic_expression> handler_expression;

        // Constructor.
        //
        vm_bridge( uint64_t rva, std::unique_ptr<arithmetic_expression> handler_expression )
            : rva( rva ), handler_expression( std::move( handler_expression ) )
        {}

        // Computes the next handler from the bridge, updating the context in respect.
        // Returns the next handler's rva.
        //
        uint64_t advance( vm_context* context ) const;

        // Construct a vm_bridge from an initial state and its instruction stream.
        // If the operation fails, returns empty {}.
        //
        static std::optional<std::unique_ptr<vm_bridge>> from_instruction_stream( const vm_state* state, const instruction_stream* stream );
    };
}