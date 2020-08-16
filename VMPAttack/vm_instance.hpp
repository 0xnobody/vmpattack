#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <mutex>
#include "vm_state.hpp"
#include "arithmetic_expression.hpp"
#include "vm_bridge.hpp"
#include "vm_handler.hpp"

namespace vmpattack
{
    // This class describes a single VMProtect virtual machine instance.
    //
    class vm_instance
    {
    public:
        // The RVA of the first instruction of the virtual machine's VMEntry.
        //
        const uint64_t rva;

        // The bridge of the VMEntry.
        //
        const std::unique_ptr<vm_bridge> bridge;

        // Specifies the registers that were pushed at VMEntry in what order.
        //
        const std::vector<vtil::register_desc> entry_frame;

    private:
        // A mutex used to access the handlers vector.
        //
        std::mutex handlers_mutex;
        
        // An vector of all vm_handlers owned by the vm_instance.
        //
        std::vector<std::unique_ptr<vm_handler>> handlers;

        // The initial vm_state as initialized by the vm_instance.
        //
        const std::unique_ptr<vm_state> initial_state;

        // The arithmetic expression used to decrypt the VMEntry stub to the initial vip.
        //
        const std::unique_ptr<arithmetic_expression> vip_expression;

    public:
        // Constructor.
        //
        vm_instance( uint64_t rva, std::unique_ptr<vm_state> initial_state, const std::vector<vtil::register_desc>& entry_frame, std::unique_ptr<arithmetic_expression> vip_expression, std::unique_ptr<vm_bridge> bridge )
            : rva( rva ), initial_state( std::move( initial_state ) ), entry_frame( entry_frame ), vip_expression( std::move( vip_expression ) ), bridge( std::move( bridge ) )
        {}

        // Creates an initial vm_context for this instance, given an entry stub and the image's load delta.
        // The vm_context is initialized at just before this vm_instance's VMEntry bridge.
        //
        std::unique_ptr<vm_context> initialize_context( uint64_t stub, int64_t load_delta ) const;

        // Adds a handler to the vm_instace.
        //
        void add_handler( std::unique_ptr<vm_handler> handler );

        // Attempts to find a handler, given an rva.
        //
        std::optional<vm_handler*> find_handler( uint64_t rva );

        // Attempts to construct a vm_instance from the VMEntry instruction stream.
        // If fails, returns empty {}.
        //
        static std::optional<std::unique_ptr<vm_instance>> from_instruction_stream( const instruction_stream* stream );
    };
}