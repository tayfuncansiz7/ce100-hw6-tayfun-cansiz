#ifdef _DEBUG
#pragma comment(lib, "../Debug/ce100-hw6-algo-lib-cs.lib")
#else
#pragma comment(lib, "../Release/ce100-hw6-algo-lib-cs.lib") 
#endif
#include "pch.h"
#include "CppUnitTest.h"
#include "ce100-hw6-algo-lib-cs.h"
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ce100hw6algotestcs
{
	TEST_CLASS(ce100hw6algotestcs)
	{
	public:
		
		TEST_METHOD(TestMethod1)
		{
			unsigned char K[20] = { 0x0b,0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
			Assert::AreEqual(HOTP(K, 171009),171009);
		}
	};
}
