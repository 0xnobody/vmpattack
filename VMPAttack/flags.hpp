#pragma once
#include <vtil/arch>

namespace vmpattack::flags
{
	// Individual flag registers
	//
	inline static const vtil::register_desc CF = { vtil::register_physical | vtil::register_flags, 0, 1, 0 };
	inline static const vtil::register_desc PF = { vtil::register_physical | vtil::register_flags, 0, 1, 2 };
	inline static const vtil::register_desc AF = { vtil::register_physical | vtil::register_flags, 0, 1, 4 };
	inline static const vtil::register_desc ZF = { vtil::register_physical | vtil::register_flags, 0, 1, 6 };
	inline static const vtil::register_desc SF = { vtil::register_physical | vtil::register_flags, 0, 1, 7 };
	inline static const vtil::register_desc IF = { vtil::register_physical | vtil::register_flags, 0, 1, 9 };
	inline static const vtil::register_desc DF = { vtil::register_physical | vtil::register_flags, 0, 1, 10 };
	inline static const vtil::register_desc OF = { vtil::register_physical | vtil::register_flags, 0, 1, 11 };
}