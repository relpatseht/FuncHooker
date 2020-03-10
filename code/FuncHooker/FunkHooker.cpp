#include "ASMStubs.h"
#include "FunkHooker.h"

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

struct FunkHooker
{
	FreeList* freeStubs;

	
};

struct FunkHook
{
	InjectionStub* stub;
	void* injectionJumpTarget;

	uint8_t overwriteSize;
};

struct FunkHooker* Hook_CreateContext(void);

struct FunkHook* Hook_Create(struct FunkHooker* ctx, const void* FunctionPtr, const void* InjectionPtr);
unsigned Hook_CreateMany(struct FunkHooker* ctx, const void** FunctionPtrs, const void** InjectionPtrs, unsigned count, struct FunkHooker** outPtrs);

bool Hook_Install(struct FunkHook* funkHooker);
unsigned Hook_InstallMany(struct FunkHook** funkHookers, unsigned count);

bool Hook_Uninstall(struct FunkHook* funkHooker);
unsigned Hook_UninstallMany(struct FunkHook** funkHookers, unsigned count);

typedef void (*Hook_FuncPtr)(void);
const Hook_FuncPtr Hook_GetTrampoline(struct FunkHook* funkHooker);
unsigned Hook_GetTrampolines(struct FunkHook** funkHookers, unsigned count, const void** outPtrs);

void Hook_Destroy(struct FunkHooker* ctx, struct FunkHook* funkHooker);
unsigned Hook_DestroyMany(struct FunkHooker* ctx, struct FunkHook** funkHookers, unsigned count);

struct FunkHooker* Hook_DestroyContext(void);
