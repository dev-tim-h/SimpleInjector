// SimpleInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"

#include "SimpleInjector.h"


//#include <Scanner.h>




int SimpleInjector::getFunctionLength(void* _functionAddress)
{
	int length = 0;
	for (length = 0; *((UINT32*)(&((unsigned char*)_functionAddress)[length])) != 0xCCCCCCCC; ++length);
	return length;
}


//void* SimpleInjector::CreateScratchMemory(size_t _startAddress = 0, size_t  _endAddress = 10000, size_t _range = MAXDWORD32)
void* SimpleInjector::CreateScratchMemory(size_t _startAddress=0, size_t _range= MAXDWORD32)
{
	MEM_ADDRESS_REQUIREMENTS requirement = { 0 };
	MEM_EXTENDED_PARAMETER extended = { 0 };
	void* _ScratchMem;
	requirement.LowestStartingAddress = (LPVOID)(_startAddress - _range);
	requirement.HighestEndingAddress = (LPVOID)(_startAddress + _range);
	requirement.Alignment = pow(1024, 2);
	extended.Type = MemExtendedParameterAddressRequirements;
	extended.Pointer = &requirement;
	
	_ScratchMem = VirtualAlloc2(m_targetProcess, NULL, 1024,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &extended, 1);

	if (!m_ScratchMem)
	{
		printf("VirtualAlloc2 Error # %d\n", GetLastError());
	}
	return _ScratchMem;
}

void SimpleInjector::setupPatchFunctionMemory()
{

	/*MEM_ADDRESS_REQUIREMENTS requirement = { 0 };
	MEM_EXTENDED_PARAMETER extended = { 0 };

	requirement.LowestStartingAddress = (LPVOID)(m_hookAddr - 10,000);
	requirement.HighestEndingAddress = (LPVOID)(m_hookAddr + 10,000);
	requirement.Alignment = pow(1024, 2);

	extended.Type = MemExtendedParameterAddressRequirements;
	extended.Pointer = &requirement;*/

	m_FuncLength = getFunctionLength(m_pInjectFunc);

	m_ScratchMem = CreateScratchMemory(m_hookAddr, MAXDWORD32);
	//hook_addr = (size_t)_pProgramScratchMem - 1024;
	if (debug)
	{
		if (!m_ScratchMem)
		{
			printf("VirtualAlloc2 Error # %d\n", GetLastError());
		}

		std::cout << "\n[pFuncMem ]: " << std::uppercase << std::hex << m_ScratchMem << std::endl;
		std::cout << "[hook_addr]: " << std::uppercase << std::hex << (void*)m_hookAddr << std::endl;
		std::cout << "[Distance ]: " << std::uppercase << std::hex << (void*)(m_hookAddr - (size_t)m_ScratchMem) << std::endl;

		//printf("[injector::setupPatchFunctionMemory] test_func Address -> %zx\n", &test_func);
		printf("[injector::setupPatchFunctionMemory] Successfully Setup Scratch Memory at -> %zx\n", m_ScratchMem);
	}

	int diff = ((size_t)m_ScratchMem - m_hookAddr);

	//printf("Jump Difference %zx\n", diff);

	if (diff > MININT32) { //Setup FF 24 25 Jump
		m_jmpType = JMP_REL_64;
		m_JumpLength = 7;
	}
	else {
		m_jmpType = JMP_REL_32;
		m_JumpLength = 5;
	}
	printf("Scratch Memory Setup at %zx\n", (uintptr_t)m_ScratchMem);
}

void SimpleInjector::injectFunction(uintptr_t _targetAddress, void* injection_function)
{
	m_hookAddr = _targetAddress;
	m_pInjectFunc = injection_function;

	setupPatchFunctionMemory();

	printf("***********Starting Injection***********\n");

	/* Get Minimal Length of Target Function Bytes to overwrite */
	ud_t u;
	uint8_t og_bytes[16];
	int code_len = sizeof(og_bytes);
	uint8_t total = 0;

	printf("\tReading Process Memory for Function %zx\n", m_hookAddr);
	ReadProcessMemory(m_targetProcess, (LPCVOID)m_hookAddr, og_bytes, code_len, NULL);


	ud_init(&u);
	ud_set_input_buffer(&u, og_bytes, code_len);
	ud_set_mode(&u, 64);
	ud_set_syntax(&u, UD_SYN_INTEL); //UD_SYN_ATT //UD_SYN_INTEL
	printf("Running Disassembler\n");


	for (int c : og_bytes) std::cout << std::hex << std::uppercase << c << ' ';
	std::cout << '\n';
	//std::cout << std::hex << std::uppercase << og_bytes << std::endl;
	while (size_t _len = ud_disassemble(&u))
	{
		total += _len;
		printf("%zx\t%s\n", _len, ud_insn_asm(&u));
		if (total >= m_JumpLength) break;
	}
	m_hookLength = total;
	printf("Minimal Insertion Length: %d", total);


	/* Copy Target Function Bytes*/
	WriteProcessMemory(m_targetProcess, m_ScratchMem, og_bytes, m_hookLength, NULL);
	//memcpy(m_ScratchMem, og_bytes, m_hookLength);
	//ReadProcessMemory(TargetProcess, m_hookAddr, m_pInjectFunc, m_FuncLength, NULL);
	//WriteProcessMemory(TargetProcess, m_ScratchMem, og_bytes, m_hookLength, NULL);


	/* -------------------- 5. Copy function to target process memory -------------------- */
	bool run = true;

	_ip = (size_t)m_ScratchMem + m_hookLength;
	uintptr_t addr = (uintptr_t)m_ScratchMem;
	WriteProcessMemory(m_targetProcess, (void*)(addr + m_hookLength), m_pInjectFunc, m_FuncLength, NULL);
	_ip += m_FuncLength;
	//printf("Successfully Injected ex_increment_ammo [PROGRAM_NAME] at %zx\n", m_ScratchMem);
	if (run) {
		cleanFunctionEntrance();

		//setupPatchFunctionMemory();


		CreateReturnJump();
		CreateJump();
	}

}

void SimpleInjector::CreateReturnJump()
{

	if (m_jmpType == JMP_REL_64) // Setup FF 24 25 Jump
	{

		//if (debug) printf("Distance Larger than 32 bits, Difference of %zd\n", (m_addr - hook_addr));


		unsigned char jmp_back[7] = { 0xFF, 0x24, 0x25 };
		uintptr_t return_address = (uintptr_t)m_hookAddr + m_hookLength;
		void* pJumpbackAddr = VirtualAlloc2(m_targetProcess, NULL, 8, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, NULL, NULL);
		printf("Jump Back Pointer %zx\n", pJumpbackAddr);
		if (debug)  std::cout << "[pJumpbackAddr]: " << std::uppercase << std::hex << pJumpbackAddr << std::endl;


		//WriteProcessMemory(TargetProcess, pJumpbackAddr, (LPVOID)((uintptr_t)m_hookAddr+m_hookLength), 8, NULL);
		WriteProcessMemory(m_targetProcess, pJumpbackAddr, &return_address, 8, NULL);

		memcpy(&jmp_back[3], &pJumpbackAddr, 4);
		WriteProcessMemory(m_targetProcess, (LPVOID)_ip, &jmp_back, sizeof jmp_back, NULL);

	}
	if (m_jmpType == JMP_REL_32) // Setup E9 Jump	
	{

		//if (debug) printf("Distance Smaller than 32 bits, Difference of %zd\n", (hook_addr - m_addr));

		unsigned char jmp_back[5] = { 0xE9 };
		signed int returnaddr = (m_hookAddr - _ip) + 6;
		memcpy(&jmp_back[1], &returnaddr, 4);

		if (debug) printf("Writing Return Address (%x) at %zx\n", returnaddr, _ip);

		WriteProcessMemory(m_targetProcess, (LPVOID)_ip, &jmp_back, sizeof jmp_back, NULL);
		/*unsigned char jmp_to[5] = { 0xE9 };
		signed int jumpto_addr = 0;
		memset(&jmp_to[1], 0x00, 4);
		jumpto_addr = ((m_addr - (signed long long)hook_addr) - 5);
		memcpy(&jmp_to[1], &jumpto_addr, 4);
		WriteProcessMemory(TargetProcess, (LPVOID)((size_t)pFuncMem + func_length), &jmp_to, sizeof jmp_to, NULL);*/

	}
}

void SimpleInjector::CreateJump()
{
	if (m_jmpType == JMP_REL_64) // Setup FF 24 25 Jump
	{
		//std::cout << "[CreateJump]: SUING JMP_REL_64" << std::endl;
		unsigned char jmp_to[7] = { 0xFF, 0x24, 0x25 };
		void* pJumpToAddr = VirtualAlloc2(m_targetProcess, NULL, 8, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, NULL, NULL);
		printf("Jump To Pointer %zx\n", pJumpToAddr);
		//std::cout << "[pJumpToAddr]  : " << std::uppercase << std::hex << pJumpToAddr << std::endl;

		uintptr_t a = (uintptr_t)m_ScratchMem;
		printf("m_ScratchMem %zx\n", a);
		WriteProcessMemory(m_targetProcess, pJumpToAddr, &a, 8, NULL);

		memcpy(&jmp_to[3], &pJumpToAddr, 4);
		WriteProcessMemory(m_targetProcess, (LPVOID)m_hookAddr, &jmp_to, 8, NULL);
	}
	if (m_jmpType == JMP_REL_32) // Setup FF 24 25 Jump
	{
		//std::cout << "[CreateJump]: SUING JMP_REL_32" << std::endl;
		//printf("Distance Smaller than 32 bits, Difference of %zd\n", (hook_addr - m_addr));

		unsigned char jmp_to[5] = { 0xE9 };
		//signed int funcAddress = (m_hookAddr - _ip) + 6;
		signed int funcAddress = (size_t)m_ScratchMem - m_hookAddr - m_JumpLength;
		memcpy(&jmp_to[1], &funcAddress, 4);
		printf("Writing Return Address (%x) at %zx\n", funcAddress, _ip);

		//WriteProcessMemory(TargetProcess, (LPVOID)_ip, &jmp_to, sizeof jmp_to, NULL);
		WriteProcessMemory(m_targetProcess, (LPVOID)m_hookAddr, &jmp_to, sizeof jmp_to, NULL);
	}
}

void SimpleInjector::cleanFunctionEntrance()
{
	//size_t hook_addr = 0x1401531F1;
	//hook_addr = 0x00937B30;
	//unsigned char og_code[]{ 0x42, 0x89, 0x2C, 0xB1, 0x48, 0x8D, 0x8B, 0x08, 0xFC, 0xFF, 0xFF };

	/*-------NOP Original Code--------*/
	char hook_nop[m_hookLength];
	memset(hook_nop, 0x90, m_hookLength);
	WriteProcessMemory(m_targetProcess, (LPVOID)m_hookAddr, &hook_nop, m_hookLength, NULL);

	if (debug)
	{
		printf("Successfuly Cleaned Function for Jump Instruction");
	}
}

