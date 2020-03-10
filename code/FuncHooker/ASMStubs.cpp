#include <cassert>
#include "ASMStubs.h"

#ifdef _MSC_VER
# pragma warning(disable : 4355)
#endif

namespace
{
	template<typename T>
	static T GetOffset(const void* from, const void* to, uint32_t instrSize)
	{
		intptr_t offset = reinterpret_cast<intptr_t>(to) - reinterpret_cast<intptr_t>(from) - instrSize;
		T castedOffset = static_cast<T>(offset);
		assert(offset == castedOffset && "Offset too large for given type");

		return castedOffset;
	}
}

namespace ASM
{
	namespace X86
	{
		ModRM::ModRM(uint8_t mod, uint8_t reg, uint8_t rm) : modRM(((mod & 0x3) << 6) | ((reg & 0x7) << 3) | (rm & 0x7)) {}
		ModRM::ModRM(uint8_t value) : modRM(value) {}

		SIB::SIB(uint8_t scale, uint8_t index, uint8_t base) : sib(((scale & 0x3) << 6) | ((index & 0x7) << 3) | (base & 0x7)) {}
		SIB::SIB(uint8_t value) : sib(value) {}

		PushU32::PushU32(uint32_t value) : value(value) {}

		Jmp::Jmp(const void* from, const void* to) : relativeOffset(GetOffset<int32_t>(from, to, sizeof(Jmp))) {}
		Jmp::Jmp(int32_t offset) : relativeOffset(offset) {}

		SJmp::SJmp(const void* from, const void* to) : offset(GetOffset<int8_t>(from, to, sizeof(SJmp))) {}
		SJmp::SJmp(int8_t offset) : offset(offset) {}

		MovToReg::MovToReg(uint32_t value, uint8_t reg) : movOpcode(0xB8 + (reg & 0x7)), value(value) {}
	}

	namespace X64
	{
		REX::REX(bool _64bit, bool regPrefix, bool indexPrefix, bool rmBasePrefix) : rex(0x40 | (_64bit << 3) | (regPrefix << 2) | (indexPrefix << 1) | (rmBasePrefix))) {}
		REX::REX(uint8_t value) : rex(value) {}

		PushU64::PushU64(uint64_t value) : lowVal(static_cast<uint32_t>(value)), highVal(static_cast<uint32_t>(value >> 32)) {}

		LJmp::LJmp(const void* addr) : addr(reinterpret_cast<uint64_t>(addr)) {}

		MovToReg::MovToReg(uint64_t value, uint8_t reg) : rex(true, false, false, reg >= REG::R8), movOpcode(0xB8 + (reg & 0x7)), value(value) {}
	}
}
