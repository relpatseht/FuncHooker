#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "Zydis/Zydis.h"
#include "ASMStubs.h"
#include "FuncHooker.h"

namespace
{
	template<size_t PtrSize>
	struct InjectionStubImpl;
	template<>
	struct InjectionStubImpl<8>
	{
		uint8_t funcHeader[128]; // All code rewrites considered, the absolute worst case scenario (a 14 byte long jump overwriting a table of 7 conditional short jumps each of which then need to be rewritten into long jumps) yields a maximum header size of 126 bytes. 2 bytes for padding because I like round numbers.
		ASM::X64::LJmp executeInjectee;
		ASM::X64::LJmp executeInjector;
	};

	template<>
	struct InjectionStubImpl<4>
	{
		uint8_t funcHeader[32]; // All code rewrites considered, the absolute worst case scenario (a 5 byte jump overwriting a table of 2 conditional short jumps each of which then need to be rewritten into regular conditional jumps) then a 13 byte instruction yields a maximum header size of 23 bytes. A few bytes for padding because I like round numbers.
		ASM::X86::Jmp executeInjectee;
		ASM::X86::Jmp executeInjector;
	};

	using InjectionStub = InjectionStubImpl<sizeof(void*)>;

	struct FreeList
	{
		FreeList* next;
	};

	static uint8_t* FindFunctionBody(ZydisDecoder *disasm, Hook_FuncPtr Func)
	{
		// The function pointer may just be to a jump statement (IAT in
		// the case of a DLL). We want to modify the actual function,
		// so we're going to follow any jumps until we don't see a jump
		// which, by process of elimination, would hopefully mean we are
		// in the actual function.

		uint8_t* lastBodyPtr = nullptr;
		uint8_t* bodyPtr = reinterpret_cast<uint8_t*>(Func);
		for (;;)
		{
			static constexpr unsigned MAX_INSTRUCTION = 256;

			ZydisDecodedInstruction inst;
			ZyanStatus stat;
			
			try
			{
				stat = ZydisDecoderDecodeBuffer(disasm, bodyPtr, MAX_INSTRUCTION, &inst);
			}
			catch (...)
			{
				if (bodyPtr == reinterpret_cast<uint8_t*>(Func))
					bodyPtr = lastBodyPtr;
				break;
			}

			if (!ZYAN_SUCCESS(stat))
			{
				if (bodyPtr == reinterpret_cast<uint8_t*>(Func))
					bodyPtr = lastBodyPtr;
				break;
			}

			if (inst.mnemonic == ZYDIS_MNEMONIC_JMP)
			{
				const ZydisDecodedOperand& op = inst.operands[0];
				uintptr_t absAddr;

				assert(inst.operand_count == 1);

				switch (op.type)
				{
					case ZYDIS_OPERAND_TYPE_POINTER:
						absAddr = (static_cast<uint64_t>(op.ptr.segment) << 4) + op.ptr.offset;
					break;
					case ZYDIS_OPERAND_TYPE_IMMEDIATE:
						absAddr = reinterpret_cast<intptr_t>(bodyPtr) + inst.length + op.imm.value.s;
					break;
					default:
						goto body_found;
				}

				lastBodyPtr = bodyPtr;
				bodyPtr = reinterpret_cast<uint8_t*>(absAddr);
			}
			else
			{
				break;
			}

		}
	body_found:

		return bodyPtr;
	}
}

struct FuncHooker
{
	FreeList* freeStubs;
	ZydisDecoder disasm;

	
};

struct FuncHook
{
	InjectionStub* stub;
	void* injectionJumpTarget;

	uint8_t overwriteSize;
};

extern "C"
{
	struct FuncHooker* Hook_CreateContext(void)
	{
		FuncHooker* const ctx = (FuncHooker*)VirtualAlloc(nullptr, 64 * 1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if constexpr (sizeof(void*) == 8)
			ZydisDecoderInit(&ctx->disasm, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
		else
			ZydisDecoderInit(&ctx->disasm, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);

	}

	struct FuncHook* Hook_Create(struct FuncHooker* ctx, Hook_FuncPtr FunctionPtr, Hook_FuncPtr InjectionPtr)
	{
		FuncHook* outHook;
		unsigned created = Hook_CreateMany(ctx, &FunctionPtr, &InjectionPtr, 1, &outHook);

		if (created)
			return outHook;

		return nullptr;
	}

	unsigned Hook_CreateMany(struct FuncHooker* ctx, Hook_FuncPtr* FunctionPtrs, Hook_FuncPtr* InjectionPtrs, unsigned count, struct FuncHook** outPtrs)
	{

		


	}

	bool Hook_Install(struct FuncHook* funcHooker);
	unsigned Hook_InstallMany(struct FuncHook** funcHookers, unsigned count);

	bool Hook_Uninstall(struct FuncHook* funcHooker);
	unsigned Hook_UninstallMany(struct FuncHook** funcHookers, unsigned count);

	typedef void (*Hook_FuncPtr)(void);
	const Hook_FuncPtr Hook_GetTrampoline(struct FuncHook* funcHooker);
	unsigned Hook_GetTrampolines(struct FuncHook** funcHookers, unsigned count, const void** outPtrs);

	void Hook_Destroy(struct FuncHooker* ctx, struct FuncHook* funcHooker);
	unsigned Hook_DestroyMany(struct FuncHooker* ctx, struct FuncHook** funcHookers, unsigned count);

	struct FuncHooker* Hook_DestroyContext(void);
}