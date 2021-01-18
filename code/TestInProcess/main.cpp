#include <iostream>
#include "Hookees.h"
#include "../FuncHooker/FuncHooker.h"

namespace hooks
{
	static FuncHooker* s_hooker;
	static FuncHook* s_hook1;
	static FuncHook* s_hook2;

	void Hooker1()
	{
		typedef void (*FuncType)(void);
		static const FuncType HookedFunc = reinterpret_cast<FuncType>(Hook_GetTrampoline(s_hook1));

	}

	void Hooker2(int a)
	{
		typedef int (*FuncType)(int);
		static const FuncType HookedFunc = reinterpret_cast<FuncType>(Hook_GetTrampoline(s_hook2));

	}
}

int main()
{
	hooks::s_hooker = Hook_CreateContext();
	Hook_FuncPtr Hookees[] = { (Hook_FuncPtr)Hookee1, (Hook_FuncPtr)Hookee2 };
	Hook_FuncPtr Hookers[] = { (Hook_FuncPtr)hooks::Hooker1, (Hook_FuncPtr)hooks::Hooker2 };
	static constexpr size_t hookCount = sizeof(Hookees) / sizeof(Hookees[0]);
	FuncHook* hooks[hookCount];

	static_assert(sizeof(Hookers) == sizeof(Hookees), "Hookee/hooker count mismatch");

	Hookee1();
	std::cout << "Hookee2: " << Hookee2(1) << std::endl;

	Hook_CreateMany(hooks::s_hooker, Hookees, Hookers, hookCount, hooks);
	hooks::s_hook1 = hooks[0];
	hooks::s_hook2 = hooks[1];

	Hookee1();
	std::cout << "Hookee2: " << Hookee2(2) << std::endl;

	Hook_InstallMany(hooks, hookCount);

	Hookee1();
	std::cout << "Hookee2: " << Hookee2(3) << std::endl;

	Hook_UninstallMany(hooks, hookCount);

	Hookee1();
	std::cout << "Hookee2: " << Hookee2(4) << std::endl;

	Hook_InstallMany(hooks, hookCount);

	Hookee1();
	std::cout << "Hookee2: " << Hookee2(5) << std::endl;

	Hook_DestroyMany(hooks::s_hooker, hooks, hookCount);

	Hookee1();
	std::cout << "Hookee2: " << Hookee2(6) << std::endl;

	Hook_DestroyContext(hooks::s_hooker);

	Hookee1();
	std::cout << "Hookee2: " << Hookee2(7) << std::endl;

	return 0;
}
