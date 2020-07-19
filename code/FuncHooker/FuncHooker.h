#pragma once

#if FUNCHOOKER_DLL
# if defined(WIN32) || defined(WIN64)
#  ifdef BUILDING_DLL
#   define FUNCHOOKER_DLLAPI __declspec(dllexport)
#  else // #  ifdef BUILDING_DLL
#   define FUNCHOOKER_DLLAPI __declspec(dllimport)
#  endif // #  else // #  ifdef BUILDING_DLL
#  define FUNCHOOKER_DLLCALL __cdecl
# else // # if defined(WIN32) || defined(WIN64)
#  define FUNCHOOKER_DLLAPI extern
#  define FUNCHOOKER_DLLCALL 
# endif //# else // # if defined(WIN32) || defined(WIN64)
#else //#if FUNCHOOKER_DLL
# define FUNCHOOKER_DLLAPI
# define FUNCHOOKER_DLLCALL
#endif //#else //#if FUNCHOOKER_DLL

#ifdef __cplusplus
extern "C"
{
#endif //#ifdef __cplusplus
	typedef void (*Hook_FuncPtr)(void);

	FUNCHOOKER_DLLAPI struct FuncHooker* FUNCHOOKER_DLLCALL Hook_CreateContext(void);

	FUNCHOOKER_DLLAPI struct FuncHook* FUNCHOOKER_DLLCALL Hook_Create(struct FuncHooker *ctx, Hook_FuncPtr FunctionPtr, Hook_FuncPtr InjectionPtr);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_CreateMany(struct FuncHooker* ctx, Hook_FuncPtr* FunctionPtrs, Hook_FuncPtr* InjectionPtrs, unsigned count, struct FuncHook **outPtrs);

	FUNCHOOKER_DLLAPI bool FUNCHOOKER_DLLCALL Hook_Install(struct FuncHook* funcHook);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_InstallMany(struct FuncHook** funcHooks, unsigned count);

	FUNCHOOKER_DLLAPI bool FUNCHOOKER_DLLCALL Hook_Uninstall(struct FuncHook* funcHook);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_UninstallMany(struct FuncHook** funcHooks, unsigned count);

	FUNCHOOKER_DLLAPI const Hook_FuncPtr FUNCHOOKER_DLLCALL Hook_GetTrampoline(const struct FuncHook* funcHook);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_GetTrampolines(const struct FuncHook** funcHooks, unsigned count, Hook_FuncPtr *outPtrs);

	FUNCHOOKER_DLLAPI bool FUNCHOOKER_DLLCALL Hook_Destroy(struct FuncHooker* ctx, struct FuncHook* funcHook);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_DestroyMany(struct FuncHooker* ctx, struct FuncHook** funcHooks, unsigned count);

	FUNCHOOKER_DLLAPI struct FuncHooker* FUNCHOOKER_DLLCALL Hook_DestroyContext(void);
#ifdef __cplusplus
}

#endif //#ifdef __cplusplus
