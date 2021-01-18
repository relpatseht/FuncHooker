#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <cmath>
#include <cstring>
#include <numeric>
#include <algorithm>
#include <atomic>
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

		InjectionStubImpl(const uint8_t* funcMem, const Hook_FuncPtr InjectionPtr, unsigned overwriteSize) :
			executeInjectee(funcMem + overwriteSize), // Absolute address :) 
			executeInjector(InjectionPtr)			  // This is only ever used if we needed a long proxy
		{
			static constexpr uint8_t nop = ASM::X86::NOP{}.nopOpcode;
			std::memset(funcHeader, nop, sizeof(funcHeader));
		}
	};

	template<>
	struct InjectionStubImpl<4>
	{
		uint8_t funcHeader[32]; // All code rewrites considered, the absolute worst case scenario (a 5 byte jump overwriting a table of 2 conditional short jumps each of which then need to be rewritten into regular conditional jumps) then a 13 byte instruction yields a maximum header size of 23 bytes. A few bytes for padding because I like round numbers.
		ASM::X86::Jmp executeInjectee;

		InjectionStubImpl(const uint8_t* funcMem, const Hook_FuncPtr InjectionPtr, unsigned overwriteSize) :
			executeInjectee(reinterpret_cast<uint8_t*>(this) + offsetof(InjectionStubImpl<4>, executeInjectee),
				funcMem + overwriteSize)  // Offset FuntionPtr by overwriteSize so we don't infinite loop our header function
		{
			((void)InjectionPtr);

			static constexpr uint8_t nop = ASM::X86::NOP{}.nopOpcode;
			std::memset(funcHeader, nop, sizeof(funcHeader));
		}
	};

	using InjectionStub = InjectionStubImpl<sizeof(void*)>;

	namespace mem
	{
		struct Allocator;
	}
}

struct FuncHook
{
	InjectionStub* stub;
	Hook_FuncPtr InjectionFunc;
	const void* injectionJumpTarget;
	void* funcBody;

	bool hotpatchable;
	bool isInstalled;
	uint8_t overwriteSize;
	uint8_t proxyBackupSize;
	uint8_t proxyBackup[sizeof(ASM::X64::LJmp)];
	uint8_t headderBackup[32]; // overwriteSize. 32 since max instruction size is 15 bytes, so allow space for 2 then round numbers are nice...
	uint8_t headerOverwrite[32]; // overwriteSize.  32 since max instruction size is 15 bytes, so allow space for 2 then round numbers are nice...
};

static constexpr const size_t funcHookSize = sizeof(FuncHook);

struct FuncHooker
{
	mem::Allocator* stubAlloc;
	mem::Allocator* hookAlloc;
};

namespace
{
	namespace list
	{
		template<bool ReusePermute = true, typename PermuteIt, typename OutIt>
		static void apply_permutation(PermuteIt permute, OutIt data, size_t count)
		{
			typedef typename std::iterator_traits<PermuteIt>::value_type index_type;

			for (index_type index = 0; index < count; ++index)
			{
				index_type currentPosition = index;
				index_type target = permute[index];

				if (target >= count)
					continue;

				while (target != index)
				{
					std::swap(data[currentPosition], data[target]);

					permute[currentPosition] = ~target;
					currentPosition = target;
					target = permute[currentPosition];
				}

				permute[currentPosition] = ~target;
			}

			if constexpr (ReusePermute)
			{
				for (index_type index = 0; index < count; ++index)
				{
					permute[index] = ~permute[index];
				}
			}
		}
	}

	namespace alloca_helper
	{
		static constexpr size_t STACK_ALIGN = sizeof(size_t) << 1;

		static __forceinline void* MarkStack(void* addr)
		{
			*reinterpret_cast<uint8_t*>(addr) = 1;

			return reinterpret_cast<uint8_t*>(addr) + STACK_ALIGN;
		}

		static __forceinline void* MarkHeap(void* addr)
		{
			*reinterpret_cast<uint8_t*>(addr) = 0;

			return reinterpret_cast<uint8_t*>(addr) + STACK_ALIGN;
		}
	}
#define valloca(X) (((X)+alloca_helper::STACK_ALIGN) < 1024 ? _alloca((X)+alloca_helper::STACK_ALIGN) : VirtualAlloc(nullptr, (X)+alloca_helper::STACK_ALIGN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

	static void vfreea(void* addr)
	{
		uint8_t* const mem = reinterpret_cast<uint8_t*>(addr);

		if (mem)
		{
			if (!*(mem - alloca_helper::STACK_ALIGN))
				VirtualFree(mem, 0, MEM_RELEASE);
		}
	}

	namespace mem
	{
		static constexpr size_t ALLOC_RESERVE_SIZE = 1 * 1024 * 1024; // 1mb
		static constexpr size_t ALLOC_PAGE_SIZE = 4 * 1024; // 4kb
		static constexpr size_t TWO_GB = 2u * 1024u * 1024u * 1024u;

		struct FreeList
		{
			FreeList* next;
		};

		struct Allocator
		{
			Allocator* next;
			FreeList* freeList;
			uintptr_t start;
			uintptr_t pageCur;
			uintptr_t pageEnd;
			uintptr_t end;
		};

		static Allocator* InitAllocator(void* mem);

		namespace alloc
		{

			static __forceinline uintptr_t RoundDownPageBoundary(uintptr_t val)
			{
				static constexpr uintptr_t PAGE_MASK = ~(ALLOC_PAGE_SIZE - 1);

				return val & PAGE_MASK;
			}

			static __forceinline uintptr_t RoundUpPageBoundary(uintptr_t val)
			{
				return RoundDownPageBoundary(val + (ALLOC_PAGE_SIZE - 1));
			}

			static Allocator* AllocAllocator()
			{
				void* const allocAddr = VirtualAlloc(nullptr, ALLOC_RESERVE_SIZE, MEM_RESERVE, PAGE_NOACCESS);

				if (allocAddr)
				{
					void* const curPage = VirtualAlloc(allocAddr, ALLOC_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);

					assert(curPage == allocAddr);

					return InitAllocator(curPage);
				}

				return nullptr;
			}

			static Allocator* AllocAllocatorWithin2GB(const void* addr)
			{
				static constexpr size_t PAGES_PER_RESERVE = ALLOC_RESERVE_SIZE / ALLOC_PAGE_SIZE;
				const void* const lowAddr = reinterpret_cast<const uint8_t*>(addr) - (TWO_GB - ALLOC_PAGE_SIZE);
				const void* const highAddr = reinterpret_cast<const uint8_t*>(addr) + (TWO_GB - ALLOC_RESERVE_SIZE);
				const uint8_t* const pageAddr = reinterpret_cast<uint8_t*>(RoundDownPageBoundary(reinterpret_cast<uintptr_t>(addr)));
				uint8_t* curLowAddr = const_cast<uint8_t*>(pageAddr - ALLOC_RESERVE_SIZE);
				uint8_t* curHighAddr = const_cast<uint8_t*>(pageAddr + ALLOC_PAGE_SIZE);
				void* allocAddr;

				do
				{
					allocAddr = VirtualAlloc(curLowAddr, ALLOC_RESERVE_SIZE, MEM_RESERVE, PAGE_NOACCESS);

					if (allocAddr)
						break;
					else
					{
						allocAddr = VirtualAlloc(curHighAddr, ALLOC_RESERVE_SIZE, MEM_RESERVE, PAGE_NOACCESS);

						if (allocAddr)
							break;
						else
						{
							curLowAddr -= ALLOC_PAGE_SIZE;
							curHighAddr += ALLOC_PAGE_SIZE;
						}
					}
				} while (curLowAddr >= lowAddr && curHighAddr <= highAddr);

				if (allocAddr)
				{
					void* const curPage = VirtualAlloc(allocAddr, ALLOC_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);

					assert(curPage == allocAddr);
					assert(allocAddr >= lowAddr && allocAddr <= highAddr);

					return InitAllocator(curPage);
				}

				return nullptr;
			}

			static void AddFreeListEntries(Allocator* alloc, size_t entrySize, unsigned entryCount)
			{
				const size_t requestedMemory = entrySize * entryCount;
				size_t pageRemaining = alloc->pageEnd - alloc->pageCur;

				assert(alloc->pageEnd >= alloc->pageCur);

				if (pageRemaining < requestedMemory && alloc->pageEnd < alloc->end)
				{
					const size_t availableMemory = alloc->end - alloc->pageEnd;
					const size_t neededMemory = requestedMemory - pageRemaining;
					const size_t neededPageMemory = RoundUpPageBoundary(neededMemory);
					const size_t allocSize = std::min(neededPageMemory, availableMemory);
					void* const newMem = VirtualAlloc(reinterpret_cast<void*>(alloc->pageEnd), allocSize, MEM_COMMIT, PAGE_READWRITE);

					if (newMem)
					{
						pageRemaining += allocSize;
						alloc->pageEnd += allocSize;
						assert(alloc->pageEnd <= alloc->end);
					}
				}

				while (pageRemaining >= entrySize)
				{
					FreeList* const newEntry = reinterpret_cast<FreeList*>(alloc->pageCur);

					alloc->pageCur += entrySize;
					newEntry->next = alloc->freeList;
					alloc->freeList = newEntry;
					pageRemaining -= entrySize;
				}
			}

			template<typename T>
			static unsigned Allocate(Allocator* alloc, T** outPtrs, unsigned count)
			{
				unsigned allocated = 0;
				while (alloc->freeList && allocated < count)
				{
					outPtrs[allocated] = reinterpret_cast<T*>(alloc->freeList);
					std::memset(outPtrs[allocated], 0, sizeof(T));
					++allocated;

					alloc->freeList = alloc->freeList->next;
				}

				if (allocated < count)
				{
					AddFreeListEntries(alloc, sizeof(T), count - allocated);

					while (alloc->freeList && allocated < count)
					{
						outPtrs[allocated++] = reinterpret_cast<T*>(alloc->freeList);
						alloc->freeList = alloc->freeList->next;
					}
				}

				return allocated;
			}

			template<typename T>
			static unsigned AllocateMany(Allocator** allocHeadPtr, T** outPtrs, unsigned count)
			{
				Allocator* const allocHead = *allocHeadPtr;
				Allocator* curAlloc = allocHead;
				unsigned allocated = 0;

				while (curAlloc && allocated < count)
				{
					allocated += alloc::Allocate<T>(curAlloc, outPtrs + allocated, count - allocated);
					curAlloc = curAlloc->next;
				}

				while (allocated < count)
				{
					curAlloc = alloc::AllocAllocator();

					if (!curAlloc)
						break;
					else
					{
						curAlloc->next = allocHead;
						*allocHeadPtr = curAlloc;

						allocated += alloc::Allocate<T>(curAlloc, outPtrs + allocated, count - allocated);
					}
				}

				return allocated;
			}

			static unsigned GatherStubIndicesWithin2GBOfAllocator(Allocator* alloc, InjectionStub** stubs, void** hintAddrs, unsigned stubCount, unsigned* outIndices)
			{
				unsigned validCount = 0;

				for (unsigned stubIndex = 0; stubIndex < stubCount; ++stubIndex)
				{
					if (!stubs[stubIndex])
					{
						const uintptr_t stubAddr = reinterpret_cast<uintptr_t>(hintAddrs[stubIndex]);
						const uintptr_t lowAddr = stubAddr - TWO_GB;
						const uintptr_t highAddr = stubAddr + TWO_GB;

						if (alloc->start >= lowAddr && alloc->end < highAddr)
						{
							outIndices[validCount++] = stubIndex;
						}
					}
				}

				return validCount;
			}
		}

		namespace protect
		{
			static void UnprotectStubAllocator(const Allocator* curAlloc)
			{
				void* const memStart = reinterpret_cast<void*>(curAlloc->start);
				const size_t length = curAlloc->pageEnd - curAlloc->start;
				DWORD oldProtect;

				bool success = VirtualProtect(memStart, length, PAGE_READWRITE, &oldProtect);
				assert(success && "Mem unprotection failed.");
			}

			static void ProtectStubAllocator(const Allocator* curAlloc)
			{
				void* const memStart = reinterpret_cast<void*>(curAlloc->start);
				const size_t length = curAlloc->pageEnd - curAlloc->start;
				DWORD oldProtect;

				bool success = VirtualProtect(memStart, length, PAGE_EXECUTE_READ, &oldProtect);
				assert(success && "Mem protection failed.");
			}
		}

		namespace free
		{
			template<typename T>
			static void Free(Allocator* headAlloc, T** list, unsigned count)
			{
				std::sort(list, list + count);

				for (unsigned listIndex = 0; listIndex < count;)
				{
					void* listCur = list[listIndex];

					if (listCur)
					{
						Allocator* curAlloc = headAlloc;
						const uintptr_t listCurAddr = reinterpret_cast<uintptr_t>(listCur);

						while (curAlloc)
						{
							if (listCurAddr >= curAlloc->start && listCurAddr < curAlloc->end)
								break;
						}

						assert(curAlloc && "List item not from any allocator");

						do
						{
							FreeList* const newFreeItem = reinterpret_cast<FreeList*>(listCur);
							newFreeItem->next = curAlloc->freeList;
							curAlloc->freeList = newFreeItem;

							listCur = list[++listIndex];
						} while (listIndex < count && reinterpret_cast<uintptr_t>(listCur) < curAlloc->end);
					}
				}
			}
		}

		static Allocator* InitAllocator(void* mem)
		{
			Allocator* const allocator = reinterpret_cast<Allocator*>(mem);

			allocator->start = reinterpret_cast<uintptr_t>(mem);
			allocator->pageCur = allocator->start + sizeof(Allocator);
			allocator->pageEnd = allocator->start + ALLOC_PAGE_SIZE;
			allocator->end = allocator->start + ALLOC_RESERVE_SIZE;
			allocator->next = nullptr;
			allocator->freeList = nullptr;

			return allocator;
		}

		static unsigned AllocateHooks(Allocator** hookAllocHeadPtr, FuncHook** outHooks, unsigned count)
		{
			return alloc::AllocateMany(hookAllocHeadPtr, outHooks, count);
		}

		static unsigned AllocateStubs(Allocator** stubAllocHeadPtr, InjectionStub** outStubs, void** hintAddrs, unsigned count)
		{
			unsigned* allocIndices = (unsigned*)valloca(sizeof(unsigned) * count);
			InjectionStub** tempStubs = (InjectionStub**)valloca(sizeof(InjectionStub*) * count);
			Allocator* const stubAllocHead = *stubAllocHeadPtr;
			Allocator* curAlloc = stubAllocHead;
			unsigned allocated = 0;

			std::memset(outStubs, 0, sizeof(InjectionStub*) * count);

			while (curAlloc && allocated < count)
			{
				const unsigned validCount = alloc::GatherStubIndicesWithin2GBOfAllocator(curAlloc, outStubs, hintAddrs, count, allocIndices);

				if (validCount > 0)
				{
					protect::UnprotectStubAllocator(curAlloc);
					const unsigned allocedStubs = alloc::Allocate<InjectionStub>(curAlloc, tempStubs, validCount);

					// Don't reprotect allocated stubs, since they'll be written to soon anyway. Reprotect after write
					if (allocedStubs == 0)
						protect::ProtectStubAllocator(curAlloc);
					else
					{
						for (unsigned tempIndex = 0; tempIndex < allocedStubs; ++tempIndex)
						{
							InjectionStub* const newStub = tempStubs[tempIndex];
							const unsigned stubIndex = allocIndices[tempIndex];

							assert(outStubs[stubIndex] == nullptr);
							outStubs[stubIndex] = newStub;
						}

						allocated += allocedStubs;
					}
				}

				curAlloc = curAlloc->next;
			}

			if (allocated < count)
			{
				for (unsigned stubIndex = 0; stubIndex < count; ++stubIndex)
				{
					if (!outStubs[stubIndex])
					{
						curAlloc = alloc::AllocAllocatorWithin2GB(hintAddrs[stubIndex]);

						if (curAlloc)
						{
							const unsigned validCount = alloc::GatherStubIndicesWithin2GBOfAllocator(curAlloc, outStubs, hintAddrs, count, allocIndices);
							const unsigned allocedStubs = alloc::Allocate<InjectionStub>(curAlloc, tempStubs, validCount);

							assert(validCount > 0 && "Allocator designed for stub did not apply to it");
							assert(allocedStubs > 0 && "New allocate couldn't be allocated from");

							curAlloc->next = stubAllocHead;
							*stubAllocHeadPtr = curAlloc;

							for (unsigned tempIndex = 0; tempIndex < allocedStubs; ++tempIndex)
							{
								InjectionStub* const newStub = tempStubs[tempIndex];
								const unsigned realStubIndex = allocIndices[tempIndex];

								assert(outStubs[realStubIndex] == nullptr);
								outStubs[realStubIndex] = newStub;
							}

							allocated += allocedStubs;
						}
					}
				}

				if (allocated < count)
				{
					// Now try to allocate from anywhere. Give up on being within 2GB
					const unsigned allocedStubs = alloc::AllocateMany(stubAllocHeadPtr, tempStubs, count - allocated);

					if (allocedStubs > 0)
					{
						unsigned tempIndex = 0;
						for (unsigned stubIndex = 0; stubIndex < count; ++stubIndex)
						{
							if (!outStubs[stubIndex])
							{
								outStubs[stubIndex] = tempStubs[tempIndex++];
								if (tempIndex >= allocedStubs)
									break;
							}
						}

						allocated += allocedStubs;
					}
				}
			}

			assert(allocated <= count);

			vfreea(tempStubs);
			vfreea(allocIndices);

			return allocated;
		}

		static unsigned GatherUniqueAllocators(Allocator* headAlloc, Allocator** outAllocs, InjectionStub** list, unsigned count)
		{
			unsigned uniqueAllocCount = 0;

			std::sort(list, list + count);

			for (unsigned listIndex = 0; listIndex < count;)
			{
				const void* listCur = list[listIndex];

				if (listCur)
				{
					Allocator* curAlloc = headAlloc;
					const uintptr_t listCurAddr = reinterpret_cast<uintptr_t>(listCur);

					while (curAlloc)
					{
						if (listCurAddr >= curAlloc->start && listCurAddr < curAlloc->end)
							break;
					}

					assert(curAlloc && "List item not from any allocator");

					do
					{
						listCur = list[++listIndex];
					} while (listIndex < count && reinterpret_cast<uintptr_t>(listCur) < curAlloc->end);

					outAllocs[uniqueAllocCount++] = curAlloc;
				}
			}

			return uniqueAllocCount;
		}

		static void ProtectStubAllocList(Allocator** stubAllocs, unsigned stubAllocCount)
		{
			for (unsigned allocIndex = 0; allocIndex < stubAllocCount; ++allocIndex)
				protect::ProtectStubAllocator(stubAllocs[allocIndex]);
		}

		static void UnprotectStubAllocList(Allocator** stubAllocs, unsigned stubAllocCount)
		{
			for (unsigned allocIndex = 0; allocIndex < stubAllocCount; ++allocIndex)
				protect::UnprotectStubAllocator(stubAllocs[allocIndex]);
		}

		static void DeallocateHooks(Allocator* hookAlloc, FuncHook** hooks, unsigned count)
		{
			free::Free(hookAlloc, hooks, count);
		}

		static void DeallocateStubs(Allocator* stubAlloc, InjectionStub** stubs, unsigned count)
		{
			free::Free(stubAlloc, stubs, count);
		}

		static void FreeAllocatorList(Allocator** headPtr)
		{
			Allocator* curAlloc = *headPtr;

			while (curAlloc)
			{
				mem::Allocator* const nextAlloc = curAlloc->next;
				VirtualFree(curAlloc, mem::ALLOC_RESERVE_SIZE, MEM_RELEASE);

				curAlloc = nextAlloc;
			}

			*headPtr = nullptr;
		}
	}

	namespace create
	{
		static bool DecodeInstruction(const ZydisDecoder& disasm, const void* addr, ZydisDecodedInstruction* outInst)
		{
			static constexpr unsigned MAX_INSTRUCTION = 256;
			ZyanStatus stat;

			try
			{
				stat = ZydisDecoderDecodeBuffer(&disasm, addr, MAX_INSTRUCTION, outInst);
			}
			catch (...)
			{
				return false;
			}

			return ZYAN_SUCCESS(stat);
		}

		static void* FindFunctionBody(const ZydisDecoder& disasm, Hook_FuncPtr Func)
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

				ZydisDecodedInstruction inst;

				if (!DecodeInstruction(disasm, bodyPtr, &inst))
				{
					if (bodyPtr == reinterpret_cast<uint8_t*>(Func))
						bodyPtr = lastBodyPtr;

					break;
				}

				if (inst.mnemonic == ZYDIS_MNEMONIC_JMP)
				{
					const ZydisDecodedOperand& op = inst.operands[0];
					uintptr_t absAddr;

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
		static const void* FindDeadzone(const uint8_t* start, unsigned minSize)
		{
			// Unfortunately, disassemblers can't work in reverse, we'll have to simply look at bytes
			// one at a time and determine if they are a type of uint8_t we can view as a nop. Fortunately
			// all these NOP instruction types are only 1 uint8_t long.
			static constexpr uint8_t nop = ASM::X86::NOP{}.nopOpcode;
			static constexpr uint8_t int3 = 0xCC;

			const uintptr_t startAddr = reinterpret_cast<uintptr_t>(start);
			const uint8_t* const pageStart = reinterpret_cast<uint8_t*>(startAddr & ~0xFFF); // Going over a page boundary could trigger a page fault. For safety...
			const uint8_t* prefixStart = start - 1;

			while (prefixStart >= pageStart && start - prefixStart <= minSize && (*prefixStart == nop || *prefixStart == int3))
				--prefixStart;

			const unsigned prefixBytes = static_cast<unsigned>((start - prefixStart) - 1);
			if (prefixBytes >= minSize)
				return prefixStart + 1;

			return nullptr;
		}

		static __forceinline intptr_t RelocateOffset(intptr_t offset, const uint8_t* from, const uint8_t* to)
		{
			const intptr_t diff = to - from;
			return offset + diff;
		}

		static bool RelocateCopyInstruction(const ZydisDecodedInstruction& inst, const uint8_t* baseFromAddr, const uint8_t* baseFromEndAddr, const uint8_t** curFromAddrPtr, uint8_t** curToAddrPtr)
		{
			uint8_t* curToAddr = *curToAddrPtr;
			const uint8_t* curFromAddr = *curFromAddrPtr;

			for (unsigned opIndex = 0; opIndex < inst.operand_count; ++opIndex)
			{
				const ZydisDecodedOperand& op = inst.operands[opIndex];

				if (op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
				{
					/* We know an operation can only have 1 operand we care about.
				   Thanks to that, we don't need to store modifications from previous
				   operands and can return as soon as 1 modification takes place.
				   This really simplifies the code, as we can assume no modifications
				   have taken place yet. */
					switch (op.type)
					{
					case ZYDIS_OPERAND_TYPE_IMMEDIATE:
						if (op.imm.is_relative) // Relative offset (loops, jumps, calls)
						{
							const intptr_t offset = op.imm.is_signed ? op.imm.value.s : (intptr_t)op.imm.value.u;
							const intptr_t movedOffset = RelocateOffset(offset, curFromAddr, curToAddr);
							const int64_t farOffset64 = (1ll << 31) - 1;
							const intptr_t farOffset = static_cast<intptr_t>(farOffset64);
							const uint8_t* const offsetTarget = curFromAddr + inst.length + offset;

							if (offsetTarget >= baseFromAddr && offsetTarget < baseFromEndAddr) // Move a relative instruction targeting our move area
							{
								// We only care about relative calls here, which mean we need they
								// are storing an instruction pointer which we will need to alter.
								if (inst.mnemonic == ZYDIS_MNEMONIC_CALL)
								{
									if (offset < 0)
										return false; // Negative rleative calls within the target aren't supported
									else
									{
										assert(inst.length == 5);

										// The call to 0 or just jumping a nop. Change it to a push and be done with it.
										new (curToAddr) ASM::X86::PushU32(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(curFromAddr)) + 5); // 5 is the size of the relative call
										curToAddr += sizeof(ASM::X86::PushU32);

										if (offset > 127) // need a regular jump
										{
											new (curToAddr) ASM::X86::Jmp(curToAddr, curToAddr + offset);
											curToAddr += sizeof(ASM::X86::Jmp);
										}
										else if (offset >= 2) // A short jump will do
										{
											new (curToAddr) ASM::X86::SJmp(static_cast<int8_t>(offset));
											curToAddr += sizeof(ASM::X86::SJmp);
										}
									}
								}
							}
							else if (std::abs(movedOffset) > farOffset) // Move a relative instruction far
							{
								// Should only be possible in 64 bit code
								if constexpr (sizeof(void*) == 8)
								{
									switch (inst.mnemonic)
									{
									case ZYDIS_MNEMONIC_CALL:
									{
										// A call is just a push and a jump. So push our new return address (just past the long jump)
										const uint64_t returnAddr = reinterpret_cast<uint64_t>(curToAddr) + sizeof(ASM::X64::PushU64) + sizeof(ASM::X64::LJmp);
										new (curToAddr) ASM::X64::PushU64(returnAddr);
										curToAddr += sizeof(ASM::X64::PushU64);
									}
									break;
									case ZYDIS_MNEMONIC_JMP:
										// Unconditional jump. This trivial case only requires a long jump, so do nothing here
										break;
									default:
										// All other jumps are on some condition. Lets just be a little tricky.
										// We'll change these jumps offsets to be jumping to our long jump over
										// an unconditional short jump which jumps over the long jump. That way,
										// if the condition is satisfied, we jump, otherwise, we skip it.

										std::memcpy(curToAddr, curFromAddr, inst.length);                  // Start by just copying the operaion over
										curToAddr += inst.length;

										// All 32 bit conditional jumps follow a pattern. Their only difference
										// from their 8 bit sisters are they are preceeded by a 0x0F byte and
										// their opcode is 0x10 larger. Lets convert 32 bit operations to 8 bit
										// if we can for efficiencies sake.
										if (op.size == 32)
										{
											curToAddr -= sizeof(uint32_t) + 1; // Back up to the operand
											uint8_t operand = *curToAddr--;    // Grab the operand and shift back to the 0xF byte.
											*curToAddr = operand - 0x10;       // Write in the 8bit operand
											curToAddr += 2;                    // Shift curTo to where it would have been had we read an 8bit jmp from the start
										}

										*(curToAddr - 1) = sizeof(ASM::X86::SJmp);         // And make it a jump over a single short jump

										new (curToAddr) ASM::X86::SJmp(sizeof(ASM::X64::LJmp)); // Add in our unconditional jump over the long jump
										curToAddr += sizeof(ASM::X86::SJmp);
									}

									// Now that we've gotten the clever hacks out of the way, we can preform our long jump.
									new (curToAddr) ASM::X64::LJmp(curFromAddr + offset); // And make an absolute address out of it.
								}
							}
							else if (op.size == 8) // Move a short relative instruction far
							{
								const intptr_t oldOffset = op.imm.value.s;
								const intptr_t newOffset = oldOffset + (curToAddr - curFromAddr);

								switch (inst.mnemonic)
								{
								case ZYDIS_MNEMONIC_JMP:
									new (curToAddr) ASM::X86::Jmp(static_cast<int32_t>(newOffset)); // Converting a short jump to a regular jump is trivial.
									curToAddr += sizeof(ASM::X86::Jmp);
									break;
								case ZYDIS_MNEMONIC_JCXZ: case ZYDIS_MNEMONIC_JRCXZ: case ZYDIS_MNEMONIC_JECXZ:
								case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE: case ZYDIS_MNEMONIC_LOOPNE:
									// All these instructions are conditional jumps with no 32 bit counterpart.
									// Let's instead made them jump to a jump to our new offset right over a
									// jump past our jump to the new offset, thus keeping the condititon and
									// getting a jump with larger range.

									std::memcpy(curToAddr, curFromAddr, inst.length); // Start by copying over the operation
									curToAddr += inst.length;

									*(curToAddr - 1) = sizeof(ASM::X86::SJmp);        // Then change the offset to be over a short jump and to our regular jump

									new (curToAddr) ASM::X86::SJmp(sizeof(ASM::X86::Jmp)); // If our condition failed, jump over our regular jump
									curToAddr += sizeof(ASM::X86::SJmp);

									new (curToAddr) ASM::X86::Jmp(static_cast<int32_t>(newOffset)); // Now, we can safely jump to our new offset only if the condition succeeded.
									curToAddr += sizeof(ASM::X86::Jmp);
									break;
								default:
									// All other 8 bit conditional jumps share a pattern. To get to their 32
									// bit counterpart, all you need to do is preceed the opcode with a 0x0F
									// byte and add 0x10 to the opcode itself.

									std::memcpy(curToAddr, curFromAddr, inst.length);// Copy over the operation (to save any potential prefix bytes)
									curToAddr += inst.length;

									curToAddr -= 2;                     // Backup our write pointer to the opcode.
									uint8_t opcode = *curToAddr + 0x10; // Make the new 32 bit opcode

									*curToAddr++ = 0x0F;                // Write in the 0xF byte.
									*curToAddr++ = opcode;              // Then the 32 bit version of the opcode.

									*((int32_t*)curToAddr++) = static_cast<int32_t>(newOffset); // Now we can safely write in our offset
								}
							}
							else // Moving sone other relative instruction (no special handling)
							{
								const intptr_t oldOffset = op.imm.value.s;
								const intptr_t newOffset = oldOffset + (curToAddr - curFromAddr);

								std::memcpy(curToAddr, curFromAddr, inst.length); // Copy over the operation
								curToAddr += inst.length;

								curToAddr -= sizeof(int32_t);  // Backup curTo to where we write the address.

								*((int32_t*)curToAddr++) = static_cast<int32_t>(newOffset); // And write in the new address
							}
						}
						break;
					case ZYDIS_OPERAND_TYPE_MEMORY: // Register + offset ptr (eg: [RIP+0x2])
						if (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.index == ZYDIS_REGISTER_RIP) // Handle RIP relative addressing.
						{
							const int32_t offset = static_cast<int32_t>(op.mem.disp.value);
							const int32_t scale = (op.mem.index == ZYDIS_REGISTER_RIP) ? (1 << op.mem.scale) : 1;
							const intptr_t target = reinterpret_cast<intptr_t>(curFromAddr) * scale + offset;
							const intptr_t newOffset = target - reinterpret_cast<intptr_t>(curToAddr);

							// Sadly, our new offset is just to big. We cannot relate to this new address.
							if (std::abs(newOffset) > (1u << 31) - 1)
								return false;

							// I really should recompile the instruction, but for that I would
							// basically have to build and integrate an assembler, which I believe
							// wouldn't be worth the effort.
							// Instead, I'll just copy over the instruction and look for the old
							// offset starting from the back. When (if) I find it, I'll overwrite
							// it with the new one.

							const uint8_t* const offsStart = curToAddr + 1;
							std::memcpy(curToAddr, curFromAddr, inst.length);
							curToAddr += inst.length;

							// We can add only go to 2 bytes after the start of the operation,
							// as because of the REX prefix and the opcode we're guaranteed
							// those CANNOT be our offset.
							uint8_t* curPos;
							for (curPos = curToAddr - sizeof(int32_t); curPos > offsStart; --curPos)
							{
								if (*((int32_t*)curPos) == offset)
								{
									*((int32_t*)curPos) = static_cast<int32_t>(newOffset);
									break;
								}
							}

							if (curPos <= offsStart)
								return false; // If we got here, we didn't find our offset.
						}
						break;
					}

					if (curToAddr != *curToAddrPtr) // We've copied the instruction
						break;
				}
			}

			if (curToAddr == *curToAddrPtr) // this instruction still needs to be copied
			{
				std::memcpy(curToAddr, curFromAddr, inst.length);
				curToAddr += inst.length;
			}

			*curToAddrPtr = curToAddr;
			*curFromAddrPtr += inst.length;
			return true;
		}

		static uint8_t RelocateHeader(const ZydisDecoder& disasm, unsigned minOverwriteSize, const FuncHook& hook, unsigned* outOptMovedInstructions)
		{
			const uint8_t* const baseFromAddr = reinterpret_cast<uint8_t*>(hook.funcBody);
			const uint8_t* const baseFromAddrEnd = baseFromAddr + minOverwriteSize;
			const uint8_t* fromAddr = baseFromAddr;
			uint8_t* toAddr = reinterpret_cast<uint8_t*>(hook.stub->funcHeader);
			const unsigned minMoveSize = minOverwriteSize;
			unsigned moveSize = 0;
			unsigned movedInstructions = 0;

			while (moveSize < minMoveSize)
			{
				ZydisDecodedInstruction inst;

				if (!DecodeInstruction(disasm, fromAddr, &inst))
					return 0;
				else
				{
					const unsigned instSize = inst.length;

					if (!RelocateCopyInstruction(inst, baseFromAddr, baseFromAddrEnd, &fromAddr, &toAddr))
						return 0;

					moveSize += instSize;
					++movedInstructions;
				}
			}

			if (outOptMovedInstructions)
				*outOptMovedInstructions = movedInstructions;

			assert(moveSize < 256 && "Move size won't fit in u8");

			return static_cast<uint8_t>(moveSize);
		}

		static bool InitializeHook(const ZydisDecoder& disasm, Hook_FuncPtr InjectionFunc, void* funcBody, void* stubMemPtr, FuncHook* outHook)
		{
			const uint8_t* const stubMem = reinterpret_cast<uint8_t*>(stubMemPtr);
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
			const unsigned deadZoneMinSize = [&]() -> unsigned
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
			const void* const deadZone = FindDeadzone(funcMem, deadZoneMinSize);

			std::memset(outHook, 0, sizeof(*outHook));

			// If we found a deadzone, we can setup a proxy, yay!
			unsigned minOverwriteSize;
			if (deadZone)
			{
				minOverwriteSize = sizeof(ASM::X86::SJmp);
				outHook->injectionJumpTarget = deadZone;

				// Make a copy of the (deadzone) region we'll be overwriting,
				// so we can restore it on unhook (just for cleanliness)
				outHook->proxyBackupSize = static_cast<uint8_t>(deadZoneMinSize);
				std::memcpy(outHook->proxyBackup, deadZone, deadZoneMinSize);
			}
			else
			{
				// No deadzone. Can't write a 2 byte proxy. Determine overwrite size.

				outHook->proxyBackupSize = 0;
				minOverwriteSize = sizeof(ASM::X86::Jmp);
				outHook->injectionJumpTarget = InjectionFunc;

				if constexpr (sizeof(void*) == 8)
				{
					if (std::abs(injectDist) > (1u << 31) - 1)
					{
						// We only need 14 bytes if both our stub code (for a long proxy) and our
						// InjectionFunctiton are over 2gb away
						if (std::abs(injectDist) > (1u << 31) - 1)
							outHook->overwriteSize = sizeof(ASM::X64::LJmp);
						else
							outHook->injectionJumpTarget = stubMem + offsetof(InjectionStub, executeInjector); // If our stub code is close, jump there instead.
					}
				}
			}

			// Get the actual overwrite size by counting the number of instructions our jump will displace
			unsigned movedInstructions;
			outHook->overwriteSize = RelocateHeader(disasm, minOverwriteSize, *outHook, &movedInstructions);
			assert(outHook->overwriteSize <= sizeof(outHook->headerOverwrite));

			// RelocateHeader returns 0 on failure
			if (outHook->overwriteSize)
			{
				static constexpr uint8_t nopOpcode = 0x90;
				static constexpr uint8_t int3Opcode = 0xCC;
				static constexpr size_t LONG_JUMP = sizeof(ASM::X64::LJmp);
				static constexpr size_t JUMP = sizeof(ASM::X86::Jmp);
				static constexpr size_t SHORT_JUMP = sizeof(ASM::X86::SJmp);

				// Copy over the header of the function that we'll be overwriting
				std::memcpy(outHook->headderBackup, funcMem, outHook->overwriteSize);
				std::memset(outHook->headerOverwrite, nopOpcode, outHook->overwriteSize);

				// Just for safety, fill our buffers with int3 (break)
				std::memset(outHook->headderBackup + outHook->overwriteSize, int3Opcode, sizeof(outHook->headderBackup) - outHook->overwriteSize);
				std::memset(outHook->headerOverwrite + outHook->overwriteSize, int3Opcode, sizeof(outHook->headerOverwrite) - outHook->overwriteSize);

				// Write out jump into the overwrite to save on ops later when the hook is actually installed
				switch (minOverwriteSize)
				{
				case LONG_JUMP:
					new (outHook->headerOverwrite) ASM::X64::LJmp(outHook->injectionJumpTarget);
					break;
				case JUMP:
					new (outHook->headerOverwrite) ASM::X86::Jmp(funcBody, outHook->injectionJumpTarget);
					break;
				case SHORT_JUMP:
					new (outHook->headerOverwrite) ASM::X86::SJmp(funcBody, outHook->injectionJumpTarget);
					break;
				default:
					assert(0 && "Unknown hook overwrite size");
				}

				new (stubMemPtr) InjectionStub(funcMem, InjectionFunc, outHook->overwriteSize);
				outHook->stub = reinterpret_cast<InjectionStub*>(stubMemPtr);
				outHook->InjectionFunc = InjectionFunc;
				outHook->funcBody = funcBody;

				// If we've only moved 1 instruction, and that instruction was a width that can be written to atomicly,
				// then we can patch the function hook in without having to worry about threads being in the middle
				// of an instruction, meaning we don't need to pause threads or worry about relocating instruction
				// pointers
				outHook->hotpatchable = movedInstructions == 1 && (
					(outHook->overwriteSize == sizeof(uint16_t) && std::atomic_uint16_t::is_always_lock_free) ||
					(outHook->overwriteSize == sizeof(uint32_t) && std::atomic_uint32_t::is_always_lock_free) ||
					(outHook->overwriteSize == sizeof(uint64_t) && std::atomic_uint64_t::is_always_lock_free)
					);

				return true;
			}

			return false;
		}
	}

	namespace modify
	{
		static unsigned GatherPrivilegePages(FuncHook** hookPtrs, unsigned count, bool forInstall, const void** outPages)
		{
			unsigned validCount = 0;

			for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
			{
				const FuncHook* const hook = hookPtrs[hookIndex];

				if (hook && hook->isInstalled == !forInstall)
				{
					const uint8_t* const funcMemStart = reinterpret_cast<uint8_t*>(hook->funcBody) - hook->proxyBackupSize;
					const uintptr_t funcAddrStart = reinterpret_cast<uintptr_t>(funcMemStart);
					const uintptr_t funcPageAddr = funcAddrStart & ~0xFFF;

					outPages[validCount] = reinterpret_cast<void*>(funcPageAddr);
					++validCount;
				}
			}

			// Remove duplicates
			std::sort(outPages, outPages + validCount);
			const void** newEnd = std::unique(outPages, outPages + validCount);

			assert(newEnd - outPages <= validCount && newEnd >= outPages);
			return static_cast<unsigned>(newEnd - outPages);
		}

		struct RAIIReadWriteBlock
		{
			const void** pages;
			DWORD* oldPrivs;
			unsigned count;

			RAIIReadWriteBlock(const void** pages, DWORD* oldPrivs, unsigned count) : pages(pages), oldPrivs(oldPrivs), count(count)
			{
				for (unsigned pageIndex = 0; pageIndex < count; ++pageIndex)
				{
					VirtualProtect(const_cast<LPVOID>(pages[pageIndex]), 4096, PAGE_EXECUTE_READWRITE, &oldPrivs[pageIndex]);
				}
			}

			~RAIIReadWriteBlock()
			{
				DWORD curPrivelege;
				for (unsigned pageIndex = 0; pageIndex < count; ++pageIndex)
				{
					VirtualProtect(const_cast<LPVOID>(pages[pageIndex]), 4096, oldPrivs[pageIndex], &curPrivelege);
				}
			}

			RAIIReadWriteBlock(const RAIIReadWriteBlock&) = delete;
			RAIIReadWriteBlock& operator=(const RAIIReadWriteBlock&) = delete;
		};

		struct RAIITimeCriticalBlock
		{
			HANDLE thread;
			int oldPriority;

			explicit RAIITimeCriticalBlock(bool setOnInit) : thread(GetCurrentThread()), oldPriority(GetThreadPriority(thread))
			{
				if (setOnInit)
					SetTimeCritical();
			}

			RAIITimeCriticalBlock() : RAIITimeCriticalBlock(true)
			{}

			~RAIITimeCriticalBlock()
			{
				SetThreadPriority(thread, oldPriority);
			}

			void SetTimeCritical()
			{
				SetThreadPriority(thread, THREAD_PRIORITY_TIME_CRITICAL);
			}

			RAIITimeCriticalBlock(const RAIITimeCriticalBlock&) = delete;
			RAIITimeCriticalBlock& operator=(const RAIITimeCriticalBlock&) = delete;
		};

		namespace single_thread
		{
			namespace win_internal
			{
				typedef __kernel_entry NTSTATUS(*QuerySysInfoPtr)(
					IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
					OUT PVOID                   SystemInformation,
					IN ULONG                    SystemInformationLength,
					OUT PULONG                  ReturnLength
					); // NtQuerySystemInformation

				typedef enum _KWAIT_REASON
				{
					Executive,
					FreePage,
					PageIn,
					PoolAllocation,
					DelayExecution,
					Suspended,
					UserRequest,
					WrExecutive,
					WrFreePage,
					WrPageIn,
					WrPoolAllocation,
					WrDelayExecution,
					WrSuspended,
					WrUserRequest,
					WrEventPair,
					WrQueue,
					WrLpcReceive,
					WrLpcReply,
					WrVirtualMemory,
					WrPageOut,
					WrRendezvous,
					Spare2,
					Spare3,
					Spare4,
					Spare5,
					Spare6,
					WrKernel,
					MaximumWaitReason
				} KWAIT_REASON, * PKWAIT_REASON;

				typedef struct _SYSTEM_THREAD_INFORMATION
				{
					LARGE_INTEGER KernelTime;
					LARGE_INTEGER UserTime;
					LARGE_INTEGER CreateTime;
					ULONG WaitTime;
					PVOID StartAddress;
					CLIENT_ID ClientId;
					KPRIORITY Priority;
					LONG BasePriority;
					ULONG ContextSwitches;
					ULONG ThreadState;
					KWAIT_REASON WaitReason;
				} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

				typedef struct _SYSTEM_PROCESS_INFORMATION
				{
					ULONG uNext;
					ULONG uThreadCount;
					LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
					ULONG HardFaultCount; // since WIN7
					ULONG NumberOfThreadsHighWatermark; // since WIN7
					ULONGLONG CycleTime; // since WIN7
					LARGE_INTEGER CreateTime;
					LARGE_INTEGER UserTime;
					LARGE_INTEGER KernelTime;
					UNICODE_STRING ImageName;
					KPRIORITY BasePriority;
					HANDLE uUniqueProcessId;
					HANDLE InheritedFromUniqueProcessId;
					ULONG HandleCount;
					ULONG SessionId;
					ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
					SIZE_T PeakVirtualSize;
					SIZE_T VirtualSize;
					ULONG PageFaultCount;
					SIZE_T PeakWorkingSetSize;
					SIZE_T WorkingSetSize;
					SIZE_T QuotaPeakPagedPoolUsage;
					SIZE_T QuotaPagedPoolUsage;
					SIZE_T QuotaPeakNonPagedPoolUsage;
					SIZE_T QuotaNonPagedPoolUsage;
					SIZE_T PagefileUsage;
					SIZE_T PeakPagefileUsage;
					SIZE_T PrivatePageCount;
					LARGE_INTEGER ReadOperationCount;
					LARGE_INTEGER WriteOperationCount;
					LARGE_INTEGER OtherOperationCount;
					LARGE_INTEGER ReadTransferCount;
					LARGE_INTEGER WriteTransferCount;
					LARGE_INTEGER OtherTransferCount;
					SYSTEM_THREAD_INFORMATION Threads[1];
				} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

				static constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xC0000004UL;
				static constexpr NTSTATUS STATUS_SUCCESS = 0x00000000UL;

				template<typename T>
				static T GetNtDLLFuncPtr(const char* funcName)
				{
					const HMODULE ntdll = LoadLibraryA("ntdll.dll");
					return (T)GetProcAddress(ntdll, funcName);
				}

				static NTSTATUS QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
				{
					static const QuerySysInfoPtr QuerySysInfo = GetNtDLLFuncPtr<QuerySysInfoPtr>("NtQuerySystemInformation");

					return QuerySysInfo(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);;
				}
			}

			static bool ProcInfoSnapshot(void** inoutMemPtr, unsigned* inoutMemLen)
			{
				void* memPtr = *inoutMemPtr;
				DWORD memLen = *inoutMemLen;

				for (;;)
				{
					DWORD requiredMemLen;
					NTSTATUS queryStat = win_internal::QuerySystemInformation(SystemProcessInformation, memPtr, memLen, &requiredMemLen);

					if (queryStat == win_internal::STATUS_INFO_LENGTH_MISMATCH)
					{
						VirtualFree(memPtr, 0, MEM_RELEASE);

						// Reserve extra memory, as process/thread count can be growing
						memLen = ((requiredMemLen + (requiredMemLen >> 2)) + 0xFFFF) & ~0xFFFF;
						memPtr = VirtualAlloc(nullptr, memLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

						*inoutMemPtr = memPtr;
						*inoutMemLen = memLen;
					}
					else if (queryStat == win_internal::STATUS_SUCCESS)
					{
						return true;
					}
					else
					{
						break;
					}
				}

				return false;
			}

			static bool GatherProcessThreads(const DWORD procId, const void* procInfoSnapshotMem, HANDLE** inoutThreadList, unsigned* inoutMaxThreadCount, unsigned* inoutThreadCount)
			{
				const win_internal::SYSTEM_PROCESS_INFORMATION* procInfoSnapshot = reinterpret_cast<const win_internal::SYSTEM_PROCESS_INFORMATION*>(procInfoSnapshotMem);
				const HANDLE procIdHandle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(procId));

				while (procInfoSnapshot && procInfoSnapshot->uUniqueProcessId != procIdHandle)
				{
					const uint8_t* const byteProcInfo = reinterpret_cast<const uint8_t*>(procInfoSnapshot);
					const uint8_t* const byteNextProcInfo = byteProcInfo + procInfoSnapshot->uNext;

					procInfoSnapshot = reinterpret_cast<const win_internal::SYSTEM_PROCESS_INFORMATION*>(byteNextProcInfo);
				}

				if (procInfoSnapshot)
				{
					const win_internal::SYSTEM_PROCESS_INFORMATION& procInfo = *procInfoSnapshot;
					const unsigned inThreadListCount = *inoutThreadCount;
					const unsigned threadCount = procInfo.uThreadCount;
					unsigned maxThreadCount = *inoutMaxThreadCount;
					HANDLE* threadList = *inoutThreadList;

					if (threadCount > maxThreadCount)
					{
						const unsigned requiredThreadMem = (threadCount + inThreadListCount) * sizeof(HANDLE);
						const unsigned alignedRequiredThreadMem = (requiredThreadMem + 0xFFFF) & ~0xFFFF;
						HANDLE* const newThreadList = (HANDLE*)VirtualAlloc(nullptr, alignedRequiredThreadMem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

						std::memcpy(newThreadList, threadList, inThreadListCount * sizeof(HANDLE));
						VirtualFree(threadList, 0, MEM_RELEASE);

						threadList = newThreadList;
						maxThreadCount = alignedRequiredThreadMem / sizeof(HANDLE);
						*inoutMaxThreadCount = maxThreadCount;
						*inoutThreadList = threadList;
					}

					unsigned outThreadIndex = inThreadListCount;
					HANDLE* const threadListEnd = threadList + outThreadIndex;
					for (unsigned threadIndex = 0; threadIndex < threadCount; ++threadIndex)
					{
						const win_internal::SYSTEM_THREAD_INFORMATION& threadInfo = procInfo.Threads[threadIndex];
						const DWORD threadId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(threadInfo.ClientId.UniqueThread));
						const HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, threadId);

						assert(threadInfo.ClientId.UniqueProcess == procIdHandle);

						if (threadHandle)
						{
							if (!std::binary_search(threadList, threadListEnd, threadHandle))
							{
								assert(outThreadIndex < maxThreadCount);

								threadList[outThreadIndex] = threadHandle;
								++outThreadIndex;
							}
							else
							{
								CloseHandle(threadHandle);
							}
						}
					}

					*inoutThreadCount = outThreadIndex;
					return true;
				}

				return false;
			}
		}

		struct RAIISingleThreadBlock
		{
			const DWORD procId;
			const HANDLE thisThread;
			HANDLE* threadList;
			unsigned threadCount;
			unsigned maxThreadCount;

			explicit RAIISingleThreadBlock(bool pauseOnInit) : procId(GetCurrentProcessId()), thisThread(GetCurrentThread()), threadList(nullptr), threadCount(0), maxThreadCount(0)
			{
				if (pauseOnInit)
					PauseAnyNewThreads();
			}

			RAIISingleThreadBlock() : RAIISingleThreadBlock(true)
			{
			}

			~RAIISingleThreadBlock()
			{
				for (unsigned threadIndex = 0; threadIndex < threadCount; ++threadIndex)
				{
					if (threadList[threadIndex] != thisThread)
						ResumeThread(threadList[threadIndex]);

					CloseHandle(threadList[threadIndex]);
				}

				VirtualFree(threadList, 0, MEM_RELEASE);
			}

			void PauseAnyNewThreads()
			{
				void* procInfoMem = nullptr;
				unsigned procInfoMemLen = 0;
				unsigned oldThreadCount;

				// Threads could be created while the gather/suspend process is happening, so do in a loop
				do
				{
					oldThreadCount = threadCount;

					if (single_thread::ProcInfoSnapshot(&procInfoMem, &procInfoMemLen))
					{
						if (single_thread::GatherProcessThreads(procId, procInfoMem, &threadList, &maxThreadCount, &threadCount))
						{
							// Suspend newly gathered threads;
							for (unsigned threadIndex = oldThreadCount; threadIndex < threadCount; ++threadIndex)
							{
								if (threadList[threadIndex] != thisThread)
									SuspendThread(threadList[threadIndex]);
							}

							// Gather process threads requires a sorted list for a binary search, so do that now.
							std::sort(threadList, threadList + threadCount);
						}
					}
				} while (oldThreadCount != threadCount);

				VirtualFree(procInfoMem, 0, MEM_RELEASE); // Don't forget to free the snapshot mem
			}
		};

		static __forceinline uintptr_t* ContextIP(CONTEXT* context)
		{
#ifdef _X86_
			return &context->Eip;
#else //#ifdef _X86_
			return &context->Rip;
#endif //#else //#ifdef _X86_
		}


		template<typename T>
		static __forceinline void InstallHookAtomicly(void *funcBodyMem, void *overwrite)
		{
			std::atomic<T>* const funcBody = reinterpret_cast<std::atomic<T>*>(funcBodyMem);
			const T overwriteOps = *reinterpret_cast<const T*>(overwrite);

			static_assert(std::is_unsigned_v<T> && std::is_integral_v<T> && std::atomic<T>::is_always_lock_free, "Invalid atomic hook type");

			funcBody->store(overwriteOps, std::memory_order_seq_cst);
		}

#if 0
		static unsigned AttemptClearVolatileIPs(RAIISingleThreadBlock* inoutThreadBlock, const FuncHook** hooks, unsigned hookCount)
		{
			struct VolatileRange
			{
				uintptr_t start;
				uintptr_t end;
			};
			unsigned threadCount = inoutThreadBlock->threadCount;
			unsigned* const threadIndices = (unsigned*)valloca(threadCount * sizeof(unsigned));
			uintptr_t* const threadIPs = (uintptr_t*)valloca(threadCount * sizeof(uintptr_t));
			VolatileRange* const volatileRanges = (VolatileRange*)valloca(hookCount * sizeof(VolatileRange));

			// Find the volatile range of all the hooks
			std::iota(threadIndices, threadIndices + threadCount, 0);
			for (unsigned hookIndex = 0; hookIndex < hookCount; ++hookIndex)
			{
				const FuncHook& hook = *hooks[hookIndex];

				volatileRanges[hookIndex].start = reinterpret_cast<uintptr_t>(hook.funcBody);
				volatileRanges[hookIndex].end = volatileRanges[hookIndex].start + hook.overwriteSize;
			}

			// Sort them (should be no overlaps)
			std::sort(volatileRanges, volatileRanges + hookCount, [](const VolatileRange& a, const VolatileRange& b)
			{
				return a.start < b.start;
			});

			// Gather all thread IPs
			for (unsigned threadIndex = 0; threadIndex < threadCount; ++threadIndex)
			{
				CONTEXT threadContext{};

				threadContext.ContextFlags = CONTEXT_CONTROL;
				GetThreadContext(inoutThreadBlock->threadList[threadIndex], &threadContext);

				threadIPs[threadIndex] = ContextIP(threadContext);
			}

			// Sort indices by IP
			std::sort(threadIndices, threadIndices + threadCount, [&](unsigned a, unsigned b)
			{
				return threadIPs[a] < threadIPs[b];
			});

			// Sort IPs by IP
			list::apply_permutation(threadIndices, threadIPs, threadCount);

			// Partition thread indices. Those at the start have an IP in a volatile range
			unsigned* inThreadIndexCur = threadIndices;
			const uintptr_t* inThreadIPCur = threadIPs;
			const uintptr_t* const inThreadIPEnd = threadIPs + threadCount;
			unsigned* outThreadIndices = threadIndices;

			for (unsigned hookIndex = 0; hookIndex < hookCount; ++hookIndex)
			{
				const VolatileRange& curVolatileRange = volatileRanges[hookIndex];

				while (*inThreadIPCur < curVolatileRange.start)
				{
					if (++inThreadIPCur < inThreadIPEnd)
						goto threads_partitioned;
					else
						++inThreadIndexCur;
				}

				while (*inThreadIPCur >= curVolatileRange.start && *inThreadIPCur < curVolatileRange.end)
				{
					std::swap(*outThreadIndices, *inThreadIndexCur);
					++outThreadIndices;
					++inThreadIndexCur;

					if (++inThreadIPCur < inThreadIPEnd)
						goto threads_partitioned;
				}
			}
		threads_partitioned:

			const unsigned volatileThreadCount = static_cast<unsigned>(outThreadIndices - threadIndices);

			if (volatileThreadCount)
			{
				// Sort all threads by the partition
				list::apply_permutation(threadIndices, inoutThreadBlock->threadList, threadCount);

				// Briefly resume volatile threads
				for (unsigned threadIndex = 0; threadIndex < volatileThreadCount; ++threadIndex)
					ResumeThread(inoutThreadBlock->threadList[threadIndex]);

				Sleep(0);

				// Suspend volatile threads again
				for (unsigned threadIndex = 0; threadIndex < volatileThreadCount; ++threadIndex)
					SuspendThread(inoutThreadBlock->threadList[threadIndex]);

				threadCount = volatileThreadCount;
			}
		}
#endif

		static void RelocateMovedIPs(HANDLE* threadList, unsigned threadCount, FuncHook** hooks, unsigned hookCount)
		{
			for (unsigned threadIndex = 0; threadIndex < threadCount; ++threadIndex)
			{
				HANDLE thread = threadList[threadIndex];
				CONTEXT threadContext{};
				uintptr_t* const ctxIP = ContextIP(&threadContext);

				threadContext.ContextFlags = CONTEXT_CONTROL;
				GetThreadContext(thread, &threadContext);

				const uintptr_t ip = *ctxIP;

				for (unsigned hookIndex = 0; hookIndex < hookCount; ++hookIndex)
				{
					const FuncHook& hook = *hooks[hookIndex];

					if (!hook.hotpatchable)
					{
						const uintptr_t overwriteStart = reinterpret_cast<uintptr_t>(hook.funcBody);
						const uintptr_t overwriteEnd = overwriteStart + hook.overwriteSize;

						if (ip >= overwriteStart && ip < overwriteEnd)
						{
							const uintptr_t destStart = reinterpret_cast<uintptr_t>(hook.stub);
							const uintptr_t destOffset = ip - overwriteStart;

							*ctxIP = destStart + destOffset;
							SetThreadContext(thread, &threadContext);
							break;
						}
					}
				}
			}
		}
	}
}

extern "C"
{
	struct FuncHooker* Hook_CreateContext(void)
	{
		uint8_t* const ctxMemStart = (uint8_t*)VirtualAlloc(nullptr, mem::ALLOC_RESERVE_SIZE, MEM_RESERVE, PAGE_NOACCESS);
		uint8_t* memCur = (uint8_t*)VirtualAlloc(ctxMemStart, mem::ALLOC_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);

		if (memCur)
		{
			FuncHooker* const ctx = (FuncHooker*)memCur;

			assert(memCur == ctxMemStart && "Virtual alloc commit off reserve.");

			// Since we're offseting the mem for allocator init, we need to 
			// pull the page end and end back to page aligned
			ctx->hookAlloc = mem::InitAllocator(memCur + sizeof(FuncHooker));
			ctx->hookAlloc->pageEnd -= sizeof(FuncHooker);
			ctx->hookAlloc->end -= sizeof(FuncHooker);

			assert((ctx->hookAlloc->pageEnd & ~(mem::ALLOC_PAGE_SIZE - 1)) == ctx->hookAlloc->pageEnd);
			assert((ctx->hookAlloc->end & ~(mem::ALLOC_PAGE_SIZE - 1)) == ctx->hookAlloc->end);

			ctx->stubAlloc = nullptr;

			return ctx;
		}

		return nullptr;
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

		void** const funcBodies = (void**)valloca(sizeof(void*) * count);
		FuncHook** const hooks = (FuncHook**)valloca(sizeof(FuncHook*) * count);
		InjectionStub** const stubs = (InjectionStub**)valloca(sizeof(InjectionStub*) * count);
		InjectionStub** const failedStubs = (InjectionStub**)valloca(sizeof(InjectionStub*) * count);
		FuncHook** const failedHooks = hooks;

		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			funcBodies[hookIndex] = create::FindFunctionBody(disasm, FunctionPtrs[hookIndex]);
		}

		mem::AllocateHooks(&ctx->hookAlloc, hooks, count);
		const unsigned stubCount = mem::AllocateStubs(&ctx->stubAlloc, stubs, funcBodies, count);

		unsigned failedHookCount = 0;
		unsigned failedStubCount = 0;
		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			FuncHook* const hook = hooks[hookIndex];
			InjectionStub* const stub = stubs[hookIndex];

			if (!(hook || stub))
			{
				if (hook)
					failedHooks[failedHookCount++] = hook;
				else
					failedStubs[failedStubCount++] = stub;

				outPtrs[hookIndex] = nullptr;
			}
			else
			{
				if (!create::InitializeHook(disasm, InjectionPtrs[hookIndex], funcBodies[hookIndex], stub, hook))
				{
					failedHooks[failedHookCount++] = hook;
					failedStubs[failedStubCount++] = stub;
					outPtrs[hookIndex] = nullptr;
				}
				else
				{
					outPtrs[hookIndex] = hook;
					++createdHooks;
				}
			}
		}

		mem::DeallocateHooks(ctx->hookAlloc, failedHooks, failedHookCount);
		mem::DeallocateStubs(ctx->stubAlloc, failedStubs, failedStubCount);

		mem::Allocator** const stubAllocs = (mem::Allocator**)valloca(sizeof(mem::Allocator*) * stubCount);
		const unsigned stubAllocCount = mem::GatherUniqueAllocators(ctx->stubAlloc, stubAllocs, stubs, stubCount);
		mem::ProtectStubAllocList(stubAllocs, stubAllocCount);

		vfreea(stubAllocs);
		vfreea(failedStubs);
		vfreea(stubs);
		vfreea(hooks);
		vfreea(funcBodies);
		return createdHooks;
	}

	bool Hook_Install(struct FuncHook* funcHooker)
	{
		return Hook_InstallMany(&funcHooker, 1) == 1;
	}

	unsigned Hook_InstallMany(struct FuncHook** funcHooks, unsigned count)
	{
		const void** const privAddrs = (const void**)valloca(sizeof(void**) * count);
		const unsigned privAddrCount = modify::GatherPrivilegePages(funcHooks, count, true, privAddrs);
		DWORD* const oldPrivileges = (DWORD*)valloca(sizeof(DWORD) * privAddrCount);
		bool allHotpatchable = true;

		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			if (!funcHooks[hookIndex]->hotpatchable)
			{
				allHotpatchable = false;
				break;
			}
		}

		// We need to make every function page read/writeable, then make sure none of the
		// functions are executing while we install the hooks. It's best to do that ASAP,
		// so make our thread time critical while we do it.
		// If all the hooks were hotpatchable, we don't need to worry about pausing all other 
		// threads or being time critical.
		// Note: If you're being nefarious and don't want to be detected, you should pause
		//       all threads anyway, since otherwise setting page privellege could set off
		//       red flags.
		modify::RAIITimeCriticalBlock raiiTimeCritical(!allHotpatchable);
		modify::RAIISingleThreadBlock raiiSingleThreaded(!allHotpatchable);
		modify::RAIIReadWriteBlock raiiReadWrite(privAddrs, oldPrivileges, count);

		// Make sure any thread IPs within the moved range are relocated to the stub
		modify::RelocateMovedIPs(raiiSingleThreaded.threadList, raiiSingleThreaded.threadCount, funcHooks, count);

		unsigned installedHooks = 0;
		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			static constexpr uint8_t nopOpcode = 0x90;
			static constexpr size_t LONG_JUMP = sizeof(ASM::X64::LJmp);
			static constexpr size_t JUMP = sizeof(ASM::X86::Jmp);
			static constexpr size_t SHORT_JUMP = sizeof(ASM::X86::SJmp);
			FuncHook* const hook = funcHooks[hookIndex];

			if (hook && !hook->isInstalled)
			{
				try
				{
					if (hook->hotpatchable)
					{
						static constexpr size_t U16 = sizeof(uint16_t);
						static constexpr size_t U32 = sizeof(uint32_t);
						static constexpr size_t U64 = sizeof(uint64_t);

						switch (hook->overwriteSize)
						{
						case U16: modify::InstallHookAtomicly<uint16_t>(hook->funcBody, hook->headerOverwrite); break;
						case U32: modify::InstallHookAtomicly<uint32_t>(hook->funcBody, hook->headerOverwrite); break;
						case U64: modify::InstallHookAtomicly<uint64_t>(hook->funcBody, hook->headerOverwrite); break;
						default:
							assert(0 && "Unknown overwrite size for hotpatchable hook");
						}
					}
					else
					{
						std::memcpy(hook->funcBody, hook->headerOverwrite, hook->overwriteSize);
					}

					hook->isInstalled = true;
					++installedHooks;
				}
				catch (...)
				{
				}
			}
		}

		return installedHooks;
	}

	bool Hook_Uninstall(struct FuncHook* funcHook)
	{
		return Hook_UninstallMany(&funcHook, 1) == 1;
	}

	unsigned Hook_UninstallMany(struct FuncHook** funcHooks, unsigned count)
	{
		const void** const privAddrs = (const void**)valloca(sizeof(void**) * count);
		const unsigned privAddrCount = modify::GatherPrivilegePages(funcHooks, count, false, privAddrs);
		DWORD* const oldPrivileges = (DWORD*)valloca(sizeof(DWORD) * privAddrCount);

		// We need to make every function page read/writeable, then make sure none of the
		// functions are executing while we install the hooks. It's best to do that ASAP,
		// so make our thread time critical while we do it.
		modify::RAIIReadWriteBlock raiiReadWrite(privAddrs, oldPrivileges, count);
		modify::RAIITimeCriticalBlock raiiTimeCritical;
		modify::RAIISingleThreadBlock raiiSingleThreaded;

		unsigned removedHooks = 0;
		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			FuncHook* const hook = funcHooks[hookIndex];

			if (hook->isInstalled)
			{
				try
				{
					std::memcpy(hook->funcBody, hook->proxyBackup, hook->proxyBackupSize);
					hook->isInstalled = false;
					++removedHooks;
				}
				catch (...)
				{
				}
			}
		}

		return removedHooks;
	}

	const Hook_FuncPtr Hook_GetTrampoline(const struct FuncHook* funcHook)
	{
		Hook_FuncPtr out;
		if (Hook_GetTrampolines(&funcHook, 1, &out) == 1)
			return out;

		return nullptr;
	}

	unsigned Hook_GetTrampolines(const struct FuncHook** funcHooks, unsigned count, Hook_FuncPtr* outPtrs)
	{
		unsigned trampolineCount = 0;
		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			const FuncHook* const hook = funcHooks[hookIndex];

			if (hook && hook->isInstalled && hook->stub)
			{
				outPtrs[hookIndex] = reinterpret_cast<Hook_FuncPtr>(hook->stub);
				++trampolineCount;
			}
			else
			{
				outPtrs[hookIndex] = nullptr;
			}
		}

		return trampolineCount;
	}

	bool Hook_Destroy(struct FuncHooker* ctx, struct FuncHook* funcHook)
	{
		return Hook_DestroyMany(ctx, &funcHook, 1) == 1;
	}

	unsigned Hook_DestroyMany(struct FuncHooker* ctx, struct FuncHook** funcHooks, unsigned count)
	{
		InjectionStub** const stubs = (InjectionStub**)valloca(sizeof(InjectionStub*) * count);
		uintptr_t* const proxyTargets = (uintptr_t*)valloca(sizeof(uintptr_t) * count);
		unsigned stubCount = 0;
		unsigned proxyTargetCount = 0;

		// If any of the hooks are still installed, be sure to uninstall them
		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			FuncHook* const hook = funcHooks[hookIndex];

			if (hook && hook->isInstalled)
			{
				Hook_UninstallMany(funcHooks, count);
				break;
			}
		}

		for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
		{
			FuncHook* const hook = funcHooks[hookIndex];

			if (hook)
			{
				if (hook->proxyBackupSize)
				{
					proxyTargets[proxyTargetCount++] = mem::alloc::RoundDownPageBoundary(reinterpret_cast<uintptr_t>(hook->injectionJumpTarget));
				}

				if (hook->stub)
				{
					stubs[stubCount++] = hook->stub;
				}
			}
		}

		mem::Allocator** const stubAllocList = (mem::Allocator**)valloca(sizeof(mem::Allocator*) * stubCount);
		const unsigned stubAllocCount = mem::GatherUniqueAllocators(ctx->stubAlloc, stubAllocList, stubs, stubCount);

		mem::UnprotectStubAllocList(stubAllocList, stubAllocCount);
		mem::DeallocateStubs(ctx->stubAlloc, stubs, stubCount);
		mem::ProtectStubAllocList(stubAllocList, stubAllocCount);

		std::sort(proxyTargets, proxyTargets + proxyTargetCount);
		proxyTargetCount = static_cast<unsigned>(std::unique(proxyTargets, proxyTargets + proxyTargetCount) - proxyTargets);
		DWORD* const oldPrivs = (DWORD*)valloca(sizeof(DWORD) * proxyTargetCount);

		{
			// We need to make every function page read/writeable, then make sure none of the
			// functions are executing while we install the hooks. It's best to do that ASAP,
			// so make our thread time critical while we do it.
			modify::RAIITimeCriticalBlock raiiTimeCritical;
			modify::RAIISingleThreadBlock raiiSingleThreaded;
			modify::RAIIReadWriteBlock raiiReadWrite(reinterpret_cast<const void**>(proxyTargets), oldPrivs, proxyTargetCount);

			for (unsigned hookIndex = 0; hookIndex < count; ++hookIndex)
			{
				FuncHook* const hook = funcHooks[hookIndex];

				if (hook && hook->proxyBackupSize)
				{
					std::memcpy(const_cast<void*>(hook->injectionJumpTarget), hook->proxyBackup, hook->proxyBackupSize);
				}
			}
		}

		mem::DeallocateHooks(ctx->hookAlloc, funcHooks, count);

		vfreea(stubAllocList);
		vfreea(proxyTargets);
		vfreea(stubs);

		return count;
	}

	void Hook_DestroyContext(struct FuncHooker* ctx)
	{
		mem::FreeAllocatorList(&ctx->hookAlloc);
		mem::FreeAllocatorList(&ctx->stubAlloc);
	}
}
