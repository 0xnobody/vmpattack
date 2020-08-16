#pragma once
#include "instruction.hpp"
#include <optional>

namespace vmpattack
{
    // This struct represents a single routine to be lifted.
    //
    struct lifting_job
    {
        // An encrypted pointer to the vip instruction stream.
        //
        uint64_t entry_stub;

        // The RVA of the function's vmentry.
        //
        uint64_t vmentry_rva;

        // Constructor.
        //
        lifting_job( uint64_t entry_stub, uint64_t vmentry_rva )
            : entry_stub( entry_stub ), vmentry_rva( vmentry_rva )
        {}
    };

    // Describes data retrieved from a code scan.
    //
    struct scan_result
    {
        // The code RVA followed to create the job.
        //
        uint64_t rva;

        // The retrieved lifting job.
        //
        lifting_job job;

        // Constructor.
        //
        scan_result( uint64_t rva, lifting_job job )
            : rva( rva ), job( job )
        {}
    };

    // This struct represents the information returned by vmentry stub analysis.
    //
    struct vmentry_analysis_result
    {
        // Optional instruction that caused the vm-exit.
        //
        std::optional<std::shared_ptr<instruction>> exit_instruction;

        // The lifting job described by the vmentry stub.
        //
        lifting_job job;

        vmentry_analysis_result( std::shared_ptr<instruction> exit_instruction, lifting_job job )
            : exit_instruction( exit_instruction ), job( job )
        {}

        vmentry_analysis_result( lifting_job job )
            : exit_instruction{}, job( job )
        {}
    };
}