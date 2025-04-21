#pragma once

#include <cmath>
#include <csignal>
#include <cstdio>
#include <Windows.h>

#include <iostream>
#include "../udis86/udis86.h"

#define JMP_REL_32 0
#define JMP_REL_64 1

class SimpleInjector
{
public:
	int getFunctionLength(void*);

	void getModFunctionInstructions();
	void getTargetFunctionInstructions();
	void restoreFunctionInstructions();
	void saveFunctionInstructions();

	void setupPatchFunctionMemory();
	void injectFunction(uintptr_t, void*);
	void CreateReturnJump();
	void CreateJump();
	void cleanFunctionEntrance();
	void* CreateScratchMemory(size_t, size_t);

	uintptr_t _program = 0;
	uintptr_t m_hookAddr = 0;
	void* m_pInjectFunc = 0;
	int m_jmpType = 0;
	int m_JumpLength = 0;
	int m_hookLength = 0;
	void* m_ScratchMem = 0;
	int m_FuncLength = 0;
	uintptr_t _ip = 0;
	bool debug = false;
	HANDLE m_targetProcess;
	DWORD  m_targetId;


private:
	//HANDLE m_targetProcess;
	//DWORD  m_targetId;
	//module TargetModule;

};