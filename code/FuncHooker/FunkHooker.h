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
	FUNCHOOKER_DLLAPI struct FunkHooker* FUNCHOOKER_DLLCALL Hook_CreateContext(void);

	FUNCHOOKER_DLLAPI struct FunkHook* FUNCHOOKER_DLLCALL Hook_Create(struct FunkHooker *ctx, const void* FunctionPtr, const void* InjectionPtr);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_CreateMany(struct FunkHooker* ctx, const void** FunctionPtrs, const void** InjectionPtrs, unsigned count, struct FunkHooker **outPtrs);

	FUNCHOOKER_DLLAPI bool FUNCHOOKER_DLLCALL Hook_Install(struct FunkHook* funkHooker);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_InstallMany(struct FunkHook** funkHookers, unsigned count);

	FUNCHOOKER_DLLAPI bool FUNCHOOKER_DLLCALL Hook_Uninstall(struct FunkHook* funkHooker);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_UninstallMany(struct FunkHook** funkHookers, unsigned count);

	typedef void (*Hook_FuncPtr)(void);
	FUNCHOOKER_DLLAPI const Hook_FuncPtr FUNCHOOKER_DLLCALL Hook_GetTrampoline(struct FunkHook* funkHooker);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_GetTrampolines(struct FunkHook** funkHookers, unsigned count, const void **outPtrs);

	FUNCHOOKER_DLLAPI void FUNCHOOKER_DLLCALL Hook_Destroy(struct FunkHooker* ctx, struct FunkHook* funkHooker);
	FUNCHOOKER_DLLAPI unsigned FUNCHOOKER_DLLCALL Hook_DestroyMany(struct FunkHooker* ctx, struct FunkHook** funkHookers, unsigned count);


	FUNCHOOKER_DLLAPI struct FunkHooker* FUNCHOOKER_DLLCALL Hook_DestroyContext(void);
#ifdef __cplusplus
}

#endif //#ifdef __cplusplus
