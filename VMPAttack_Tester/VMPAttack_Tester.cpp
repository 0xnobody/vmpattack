// VMPAttack_Tester.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <intrin.h>

extern "C" void __vmpfnc();

#pragma pack(push, 1)
struct much_complex_object
{
	uint32_t a;
	uint8_t b;
	uint8_t c;
	uint16_t d;

	__declspec( noinline ) int32_t wow()
	{
		return c * b + a;
	}
};
#pragma pack(pop)

int main( int argc, const char* args[] )
{
	

	while ( r >= 0x50 )
	{
		r *= 0x43;
		r /= getchar();
		r <<= 7;
		r = _rotl( r, getchar() );
		r ^= __rdtsc();
	}

	return r;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
