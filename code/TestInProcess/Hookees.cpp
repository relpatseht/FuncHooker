#include <iostream>

void Hookee1()
{
	std::cout << "In Hookee1" << std::endl;
}

int Hookee2(int a)
{
	std::cout << "In Hookee2 with " << a << " (ret " << a * 2 << ")" << std::endl;
	return a * 2;
}
