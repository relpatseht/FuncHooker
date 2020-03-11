#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cmath>
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

	static void* FindFunctionBody(ZydisDecoder *disasm, Hook_FuncPtr Func)
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

	// Lets get tricky. We want to overwrite as few bytes of the function as possible.
	// Unfortunately, a long jump is 5 bytes on x86 and on x64 could be 14 in the worst
	// case scenario. Solution: often in memory functions will be preceded by NOPs, INT 3's
	// (breakpoints), and other instructions which don't actually alter things in any way
	// (which makes sense, because the instruction pointer should never get there). for 
	// padding purposes. A short jump is only 2 bytes long. So, let's count the number of free 
	// bytes we have before the function and, if it is enough, use a short jump to jump 
	// backward to our long jump stored just before the function begins.
	static const void* FindDeadzone(const uint8_t* start, unsigned delta, unsigned minSize)
	{
		// Unfortunately, disassemblers can't work in reverse, we'll have to simply look at bytes
		// one at a time and determine if they are a type of uint8_t we can view as a nop. Fortunately
		// all these NOP instruction types are only 1 uint8_t long.
		static constexpr uint8_t nop = 0x90;
		static constexpr uint8_t int3 = 0xCC;

		const uintptr_t startAddr = reinterpret_cast<uintptr_t>(start);
		const uint8_t* const pageStart = reinterpret_cast<uint8_t*>(startAddr & ~0xFFF); // Going over a page boundary could trigger a page fault. For safety...
		const uint8_t* const pageEnd = reinterpret_cast<uint8_t*>((startAddr + 4095) & ~0xFFF);
		const uint8_t* prefixStart = start - 1;

		while (prefixStart >= pageStart && start - prefixStart <= minSize && (*prefixStart == nop || *prefixStart == int3))
			--prefixStart;

		const unsigned prefixBytes = (start - prefixStart) - 1;
		if (prefixBytes >= minSize)
			return prefixStart + 1;

		return nullptr;
	}

	static bool InitializeStub(Hook_FuncPtr InjectionFunc, void* funcBody, InjectionStub* outStub)
	{
		const uint8_t* const stubMem = reinterpret_cast<uint8_t*>(outStub);
		const uint8_t* const funcMem = reinterpret_cast<uint8_t*>(funcBody);
		const uint8_t* const injectMem = reinterpret_cast<uint8_t*>(InjectionFunc);

		// For starters, we need to find out exactly how far we'll need to jump
		// to get to our InjectionFunction from their function. If this distance
		// is greater than 2gb, we might need to use a 14 uint8_t 64 bit jump instead
		// of a 5 uint8_t regular jump. We want to minimize the number of bytes we're
		// overwritting with our jump to our InjectionFunction.
		const intptr_t injectDist = injectMem - funcMem;
		const intptr_t stubDist = stubMem - funcMem;

		// Now we look for deadzones, or areas in code which are just NOPs or INT 3s.
		// If we can find one of these which is large enough within 127 bytes, we'll
		// be able to do a 2 uint8_t short jump to a proxy jump to our InjectionFunction.
		const unsigned deadZoneMinSize = [&]()
		{
			if constexpr (sizeof(void*) == 8)
			{
				// We only need to find the full 14 bytes for a long jump if our InjectionFunction
				// is over 2gb away and our stub code is over 2gb away. Otherwise our proxy only
				// needs to be 5 bytes for a regular jump.
				if (std::abs(stubDist) > (1u << 31) - 1 && std::abs(injectDist) > (1u << 31) - 1)
					return sizeof(ASM::X64::LJmp);
			}

			return sizeof(ASM::X86::Jmp); // Otherwise, we just need 5 bytes for a regular jump.
		}();
		const void* const deadZone = FindDeadzone(funcMem, 127, deadZoneMinSize);
		unsigned overwriteSize;

		// If we found a deadzone, we can setup a proxy, yay!
		if (deadZone)
		{
			overwriteSize = sizeof(ASM::X86::SJmp);
			
		}
	}
}

struct FuncHooker
{
	FreeList* freeStubs;

	
};

struct FuncHook
{
	InjectionStub* stub;
	Hook_FuncPtr InjectionFunc;
	void* injectionJumpTarget;
	void* funcBody;

	uint8_t overwriteSize;
};

extern "C"
{
	struct FuncHooker* Hook_CreateContext(void)
	{
		FuncHooker* const ctx = (FuncHooker*)VirtualAlloc(nullptr, 64 * 1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (ctx)
		{

		}

		return ctx;
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
		unsigned createdHooks = 0;
		ZydisDecoder disasm;

		if constexpr (sizeof(void*) == 8)
			ZydisDecoderInit(&disasm, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
		else
			ZydisDecoderInit(&disasm, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);

		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			void* const funcBody = FindFunctionBody(&disasm, FunctionPtrs[hookIndex]);

			if (funcBody)
			{
				FuncHook* const hook = AllocateHook(ctx);

				hook->stub = AllocateStub(ctx);

				hook->funcBody = funcBody;
				hook->InjectionFunc = InjectionPtrs[hookIndex];
				hook->injectionJumpTarget = nullptr;
				hook->overwriteSize = 0;

				outPtrs[hookIndex] = hook;
				++createdHooks;
			}
			else
			{
				outPtrs[hookIndex] = nullptr;
			}
		}
		
		return createdHooks;
	}

	bool Hook_Install(struct FuncHook* funcHooker)
	{
		return Hook_InstallMany(&funcHooker, 1) == 1;
	}

	unsigned Hook_InstallMany(struct FuncHook** funcHookers, unsigned count)
	{

	}

	bool Hook_Uninstall(struct FuncHook* funcHooker);
	unsigned Hook_UninstallMany(struct FuncHook** funcHookers, unsigned count);

	typedef void (*Hook_FuncPtr)(void);
	const Hook_FuncPtr Hook_GetTrampoline(struct FuncHook* funcHooker);
	unsigned Hook_GetTrampolines(struct FuncHook** funcHookers, unsigned count, const void** outPtrs);

	void Hook_Destroy(struct FuncHooker* ctx, struct FuncHook* funcHooker);
	unsigned Hook_DestroyMany(struct FuncHooker* ctx, struct FuncHook** funcHookers, unsigned count);

	struct FuncHooker* Hook_DestroyContext(void);
}