#pragma once

#include <cstdint>

#ifdef _MSC_VER
# define PACK_ATTR
#else
# define PACK_ATTR  __attribute__((__packed__))
#endif

#ifdef _MSC_VER
# pragma pack(push, 1)
#endif //#ifdef _MSC_VER

namespace ASM
{
	namespace detail
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

	namespace X86
	{
		namespace REG
		{
			enum SIMD : uint8_t
			{
				XMM0,
				XMM1,
				XMM2,
				XMM3,
				XMM4,
				XMM5,
				XMM6,
				XMM7,
				XMM8,
				XMM9,
				XMM10,
				XMM11,
				XMM12,
				XMM13,
				XMM14,
				XMM15
			};

			enum CPU86 : uint8_t
			{
				EAX,
				ECX,
				EDX,
				EBX,
				ESP,
				EBP,
				ESI,
				EDI,
			};
		}

		enum class MOD
		{
			PTR,
			PTR_DISP8,
			PTR_DISP32,
			VAL
		};

		/* A ModR/M uint8_t is decoded as follows:

		MOD<7-6>, REG<5-3>, R/M<2-0>

		MOD:
		- 00 (0 - PTR):
		- R/M = 100: Register indirect addresing mode / SIB with no displacement
		- R/M = 101: Displacement only addressing mode
		- 01 (1 - PTR_DISP8): int8_t displacement follows addressing uint8_t(s) (SIB)
		- 10 (2 - PTR_DISP32): int32_t displacement follows addressing uint8_t(s) (SIB)
		- 11 (3 - VAL): Register addressing mode

		REG:
		- Source or destination register, depending on opcode

		R/M:
		- The operand. Often a register
		*/
		struct ModRM
		{
			const uint8_t modRM;

			ModRM(uint8_t mod, uint8_t reg, uint8_t rm) : modRM(((mod & 0x3) << 6) | ((reg & 0x7) << 3) | (rm & 0x7)) {}
			explicit ModRM(uint8_t value) : modRM(value) {}
		} PACK_ATTR;

		/* Paired with ModR/M as addressing mode bytes (Scaled Indexed addressing mode Byte)

		SCALE<7-6>, INDEX<5-3>, BASE<2-0>

		Address = BASE + INDEX*(2^SCALE);
		BASE:
		- Register
		- 101: Displacement only if MOD of ModR/M = 00, EBP otherwise

		INDEX:
		- Register
		- 100 illegal
		*/
		struct SIB
		{
			const uint8_t sib;

			SIB(uint8_t scale, uint8_t index, uint8_t base) : sib(((scale & 0x3) << 6) | ((index & 0x7) << 3) | (base & 0x7)) {}
			explicit SIB(uint8_t value) : sib(value) {}
		} PACK_ATTR;

		struct PushU32
		{
			const uint8_t opcode = 0x68;
			uint32_t value;

			PushU32() = default;
			explicit PushU32(uint32_t value) : value(value) {}
		} PACK_ATTR;

		struct NOP
		{
			const uint8_t nopOpcode = 0x90;
		};

		struct Return
		{
			const uint8_t retOpcode = 0xC3;
		} PACK_ATTR;

		struct Jmp
		{
			const uint8_t opcode = 0xE9;
			int32_t relativeOffset;

			Jmp(const void* from, const void* to) : relativeOffset(detail::GetOffset<int32_t>(from, to, sizeof(Jmp))) {}
			explicit Jmp(int32_t offset) : relativeOffset(offset) {}

			void SetAddr(const void* from, const void* to)
			{
				relativeOffset = detail::GetOffset<int32_t>(from, to, sizeof(Jmp));
			}
		} PACK_ATTR;

		struct SJmp
		{
			const uint8_t opcode = 0xEB;
			int8_t offset;

			SJmp(const void* from, const void* to) : offset(detail::GetOffset<int8_t>(from, to, sizeof(SJmp))) {}
			explicit SJmp(int8_t offset) : offset(offset) {}
		} PACK_ATTR;

		struct MovToReg
		{
			const uint8_t movOpcode;
			uint32_t value;

			MovToReg(uint32_t value, uint8_t reg=REG::EAX) : movOpcode(0xB8 + (reg & 0x7)), value(value) {}
		} PACK_ATTR;
	}

	namespace X64
	{
		namespace REG
		{
			using namespace X86::REG;

			enum CPU64 : uint8_t
			{
				RAX,
				RCX,
				RDX,
				RBX,
				RSP,
				RBP,
				RSI,
				RDI,
				R8,
				R9,
				R10,
				R11,
				R12,
				R13,
				R14,
				R15
			};
		}

		using X86::MOD;
		using X86::ModRM;
		using X86::SIB;

		struct REX
		{
			const uint8_t rex;

			REX(bool _64bit, bool regPrefix, bool indexPrefix, bool rmBasePrefix) : rex(0x40 | (_64bit << 3) | (regPrefix << 2) | (indexPrefix << 1) | (rmBasePrefix << 0)) {}
			explicit REX(uint8_t value) : rex(value) {}
		} PACK_ATTR;

		using X86::PushU32;

		struct PushU64
		{
			PushU32 lowVal;
			const uint8_t movOpcode = 0xC7; // The push operation only takes a 32 bit value, but actually
			const ModRM modRM{ (uint8_t)MOD::PTR_DISP8, 0, REG::RSP };  // pushes 8 bytes on the stack. So after the push, we need to
			const SIB sib{ 0, REG::RSP, REG::RSP };      // mov the upper 4 bytes into the correct position
			const uint8_t rspOffset = 4;
			uint32_t highVal;

			PushU64() = default;
			explicit PushU64(uint64_t value) : lowVal(static_cast<uint32_t>(value)), highVal(static_cast<uint32_t>(value >> 32)) {}

			uint64_t GetValue() const
			{
				return (static_cast<uint64_t>(highVal) << 32) | lowVal.value;
			}

			void SetValue(uint64_t value)
			{
				highVal = static_cast<uint32_t>(value >> 32);
				lowVal.value = static_cast<uint32_t>(value);
			}
		} PACK_ATTR;

		using X86::Return;
		using X86::NOP;

		/* A jump to an absolute address cannot be done with an immediate value
		and we don't want to touch a register. The solution is to push the
		lower half of the value, then move the upper half on top of, then return

		This is only for use in 64 bit code.
		*/
		struct LJmp
		{
			PushU64 addr;
			const Return ret{};

			explicit LJmp(const void* addr) : addr(reinterpret_cast<uint64_t>(addr)) {};
		} PACK_ATTR;


		struct MovToReg
		{
			const REX rex;
			const uint8_t movOpcode;
			uint64_t value;

			MovToReg(uint64_t value, uint8_t reg=REG::RAX) : rex(true, false, false, reg >= REG::R8), movOpcode(0xB8 + (reg & 0x7)), value(value) {}
		} PACK_ATTR;
	}
}

#ifdef _MSC_VER
# pragma pack(pop)
#endif //#ifdef _MSC_VER

#undef PACK_ATTR
