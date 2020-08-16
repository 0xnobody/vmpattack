
#include <windows.h>
#include <cstdint>

#include "vmpattack.hpp"

#include <vtil/compiler>
#include <fstream>

#pragma comment(linker, "/STACK:34359738368")

using namespace vtil;
using namespace vtil::optimizer;
using namespace vtil::logger;

namespace vmpattack
{
    // Still hate c++
    //
    std::vector<BYTE> read_file( const char* filename )
    {
        // open the file:
        std::ifstream file( filename, std::ios::binary );

        // Stop eating new lines in binary mode!!!
        file.unsetf( std::ios::skipws );

        // get its size:
        std::streampos fileSize;

        file.seekg( 0, std::ios::end );
        fileSize = file.tellg();
        file.seekg( 0, std::ios::beg );

        // reserve capacity
        std::vector<BYTE> vec;
        vec.reserve( fileSize );

        // read the data:
        vec.insert( vec.begin(),
                    std::istream_iterator<BYTE>( file ),
                    std::istream_iterator<BYTE>() );

        return vec;
    }

    extern "C" int main( int argc, const char* args[])
    {
        //vtil::debug::dump( vtil::load_routine( args[ 1 ] ) );
        //Sleep( -1 );

        //read_file( "C:\\Users\\adamn\\OneDrive\\Documents\\reversing\\eft\\Dumps\\BEDaisy.sys" ); //"C:\\Users\\adamn\\OneDrive\\Documents\\reversing\\valorant\\vgk.sys" );//
        std::vector<uint8_t> buffer = read_file( "C:\\Users\\adamn\\OneDrive\\Documents\\GitHub\\vmpattack\\vmpattack\\x64\\Release\\VMPAttack_Tester.vmp.exe" );

        log<CON_GRN>( "** Loaded raw image buffer @ 0x%p of size 0x%llx\r\n", buffer.data(), buffer.size() );

        vmpattack instance( buffer );

        std::vector<scan_result> scan_results = instance.scan_for_vmentry( ".text" );

        log<CON_GRN>( "** Found %u virtualized routines:\r\n", scan_results.size() );

        for ( const scan_result& scan_result : scan_results )
            log<CON_CYN>( "\t** RVA 0x%llx VMEntry 0x%llx Stub 0x%llx\r\n", scan_result.rva, scan_result.job.vmentry_rva, scan_result.job.entry_stub );

        log( "\r\n" );

        std::vector<vtil::routine*> lifted_routines;

        //auto rtn = instance.lift( { 0x773F14F9, 0x223758 } );
        //spawn_state<optimizer::stack_pinning_pass>{}( *rtn );
        //spawn_state<optimizer::istack_ref_substitution_pass>{}( *rtn );
        //spawn_state<optimizer::bblock_extension_pass>{}( *rtn );
        //spawn_state<optimizer::local_pass<optimizer::stack_propagation_pass>>{}( *rtn );
        //spawn_state<optimizer::local_pass<optimizer::dead_code_elimination_pass>>{}( *rtn );
        //spawn_state<optimizer::local_pass<optimizer::mov_propagation_pass>>{}( *rtn );
        //spawn_state<optimizer::local_pass<optimizer::register_renaming_pass>>{}( *rtn );
        //spawn_state<optimizer::local_pass<optimizer::dead_code_elimination_pass>>{}( *rtn );
        //spawn_state<optimizer::symbolic_rewrite_pass<1>>{}( *rtn );
        //spawn_state<optimizer::branch_correction_pass>{}( *rtn );
        //spawn_state<optimizer::stack_propagation_pass>{}( *rtn );
        //spawn_state<optimizer::local_pass<optimizer::mov_propagation_pass>>{}( *rtn );
        //spawn_state<optimizer::local_pass<optimizer::dead_code_elimination_pass>>{}( *rtn );
        //
        //vtil::debug::dump( *rtn );
        //
        //vtil::optimizer::apply_all_profiled( *rtn );
        //
        //vtil::debug::dump( *rtn );

        //auto block = ( *rtn )->find_block( 0x14016c147 );
        //auto ins = std::next( block->begin(), 81 );
        //
        //vtil::cached_tracer tracer;
        //
        //tracer.rtrace_p( { ins, vtil::REG_FLAGS } );
        //
        //spawn_state<optimizer::mov_propagation_pass>{}( *rtn );

        for ( const scan_result& scan_result : scan_results )
        {
            log<CON_YLW>( "** Devirtualizing routine @ 0x%llx...\r\n", scan_result.rva );

            std::optional<vtil::routine*> routine = instance.lift( scan_result.job );

            if ( routine )
            {
                log<CON_GRN>( "\t** Lifting success\r\n" );
                lifted_routines.push_back( *routine );

                vtil::optimizer::apply_all_profiled( *routine );

                log<CON_GRN>( "\t** Optimization success\r\n" );

                vtil::debug::dump( *routine );

                //std::string save_path = vtil::format::str( "C:\\Users\\adamn\\OneDrive\\Documents\\reversing\\eft\\Dumps\\BEDaisy-VTIL\\0x%llx.vtil", scan_result.rva );
                //vtil::save_routine( *routine, save_path );

                //log<CON_GRN>( "\t** Saved to %s\r\n", save_path );
            }
            else
                log<CON_RED>( "\t** Lifting failed\r\n" );
        }

        for ( vtil::routine* lifted_routine : lifted_routines )
        {
            log<CON_YLW>( "** Optimizing routine @ 0x%llx...\r\n", lifted_routine->entry_point->entry_vip );

            vtil::optimizer::apply_all( lifted_routine );
            
            vtil::debug::dump( lifted_routine );
        }
        //( *routine )->routine_convention = vtil::amd64::preserve_all_convention;

        system( "pause" );
    }
}