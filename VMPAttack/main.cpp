#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdint>

#include "vmpattack.hpp"

#include <vtil/compiler>
#include <fstream>
#include <filesystem>

#ifdef _MSC_VER
#pragma comment(linker, "/STACK:34359738368")
#endif

using namespace vtil;
using namespace vtil::optimizer;
using namespace vtil::logger;

namespace vmpattack
{
    using std::uint8_t;

    // Still hate c++
    //
    std::vector<uint8_t> read_file( const char* filename )
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
        std::vector<uint8_t> vec;
        vec.reserve( fileSize );

        // read the data:
        vec.insert( vec.begin(),
                    std::istream_iterator<uint8_t>( file ),
                    std::istream_iterator<uint8_t>() );

        return vec;
    }

    extern "C" int main( int argc, const char* args[])
    {
        std::filesystem::path input_file_path = { args[ 1 ] };

        // Create an output directory.
        //
        std::filesystem::path output_path = input_file_path;
        output_path.remove_filename();
        output_path /= "VMPAttack-Output";

        // Create the directory if it doesn't exist already.
        //
        std::filesystem::create_directory( output_path );

        std::vector<uint8_t> buffer = read_file( input_file_path.string().c_str() );

        log<CON_GRN>( "** Loaded raw image buffer @ 0x%p of size 0x%llx\r\n", buffer.data(), buffer.size() );

        vmpattack instance( buffer );

        std::vector<scan_result> scan_results = instance.scan_for_vmentry( ".text" );

        log<CON_GRN>( "** Found %u virtualized routines:\r\n", scan_results.size() );

        for ( const scan_result& scan_result : scan_results )
            log<CON_CYN>( "\t** RVA 0x%llx VMEntry 0x%llx Stub 0x%llx\r\n", scan_result.rva, scan_result.job.vmentry_rva, scan_result.job.entry_stub );

        log( "\r\n" );

        std::vector<vtil::routine*> lifted_routines;

        for ( const scan_result& scan_result : scan_results )
        {
            log<CON_YLW>( "** Devirtualizing routine @ 0x%llx...\r\n", scan_result.rva );

            std::optional<vtil::routine*> routine = instance.lift( scan_result.job );

            if ( routine )
            {
                log<CON_GRN>( "\t** Lifting success\r\n" );
                lifted_routines.push_back( *routine );

                std::string save_path = vtil::format::str( "%s\\0x%llx.vtil", output_path.string().c_str(), scan_result.rva );
                vtil::save_routine( *routine, save_path );

                log<CON_GRN>( "\t** Unoptimized Saved to %s\r\n", save_path );

                vtil::optimizer::apply_all_profiled( *routine );

                log<CON_GRN>( "\t** Optimization success\r\n" );

#ifdef _DEBUG
                vtil::debug::dump( *routine );
#endif

                std::string optimized_save_path = vtil::format::str( "%s\\0x%llx-Optimized.vtil", output_path.string().c_str(), scan_result.rva );
                vtil::save_routine( *routine, optimized_save_path );

                log<CON_GRN>( "\t** Optimized Saved to %s\r\n", save_path );
            }
            else
                log<CON_RED>( "\t** Lifting failed\r\n" );
        }

        system( "pause" );
    }
}