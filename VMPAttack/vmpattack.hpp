#pragma once
#include "vm_instance.hpp"
#include "vmentry.hpp"
#include <vtil/arch>
#include <mutex>
#include <vtil/formats>

namespace vmpattack
{
    // This class is the root object, controlling all other interfaces.
    //
    class vmpattack
    {
    private:
        // The PE image descriptor.
        //
        const vtil::pe_image image;

        // The mapped PE image buffer.
        //
        const std::vector<uint8_t> mapped_image;

        // The image's preferred image base.
        //
        const uint64_t preferred_image_base;

        // A pointer to the loaded image in memory's base.
        //
        const uint64_t image_base;

        // A mutex to handle shared writes to the cached instances vector.
        //
        std::mutex instances_mutex;

        // A vector of all cached vm_instances.
        //
        std::vector<std::unique_ptr<vm_instance>> instances;

        // Attempts to find a vm_instance for the specified rva. If succeeded, returns
        // said instance. Otherwise returns nullptr.
        //
        vm_instance* lookup_instance( uint64_t rva );

        // Adds the specified vm_instance to the cached list, exersizing thread-safe behaviour
        // in doing so.
        //
        void add_instance( std::unique_ptr<vm_instance> instance );

        // Lifts a single basic block, given the appropriate information.
        //
        bool lift_block( vm_instance* instance, vtil::basic_block* block, vm_context* context, uint64_t first_handler_rva, std::vector<vtil::vip_t> explored_blocks );

        // Performs the specified lifting job, returning a raw, unoptimized vtil routine.
        // Optionally takes in a previous block to fork. If null, creates a new block via a new routine.
        // If the passed previous block is not completed, it is completed with a jmp to the newly created block.
        //
        std::optional<vtil::routine*> lift_internal( uint64_t rva, uint64_t stub, vtil::basic_block* block );

        // Scans the given instruction vector for VM entries.
        // Returns a list of results, of [root rva, lifting_job]
        //
        std::vector<scan_result> scan_for_vmentry( const std::vector<std::unique_ptr<instruction>>& instructions ) const;

    public:
        // Constructor.
        //
        vmpattack( uint64_t preferred_image_base, uint64_t image_base )
            : preferred_image_base( preferred_image_base ), image_base( image_base )
        {}

        // Construct from raw image bytes vector.
        //
        vmpattack( const std::vector<uint8_t>& raw_image_bytes );

        // Performs the specified lifting job, returning a raw, unoptimized vtil routine.
        //
        std::optional<vtil::routine*> lift( const lifting_job& job );

        // Performs an analysis on the specified vmentry stub rva, returning relevant information.
        //
        std::optional<vmentry_analysis_result> analyze_entry_stub( uint64_t rva ) const;

        // Scans the given code section for VM entries.
        // Returns a list of results, of [root rva, lifting_job]
        //
        std::vector<scan_result> scan_for_vmentry( const std::string& section_name ) const;

        // Scans all executable sections for VM entries.
        // Returns a list of results, of [root rva, lifting_job]
        //
        std::vector<scan_result> scan_for_vmentry() const;
    };
}