#include <Windows.h>
#include <stdio.h>
#include <iostream>

// g++ trampoline.cpp -o trampoline.exe -masm=intel

int counter = 0;
FARPROC address;
DWORD oldProtect;
BYTE opcode;

LONG WINAPI Exceptioner(_EXCEPTION_POINTERS *ExceptionInfo)
{
	// save context
	__asm("mov r10, rcx");
    counter++;
	// do whatever
	
	// restore context
    ExceptionInfo->ContextRecord->Rip = (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress+1;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{

    address = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtDelayExecution");
    printf("Opcode instruction: 0x%x\n", *(PBYTE)(address));
    
	printf("Original Opcode instruction: ");
    for(int i = 0; i < 3; ++i)
    {
        printf("0x%02x ", *(PBYTE)(address+i));
    }
	printf("\n");
    VirtualProtect((LPVOID)address, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(PBYTE)(address) = 0xCC; // int3 instruction
    *(PBYTE)(address+1) = 0x90;
	*(PBYTE)(address+2) = 0x90;
	
	printf("Original Opcode instruction: ");
    for(int i = 0; i < 3; ++i)
    {
        printf("0x%02x ", *(PBYTE)(address+i));
    }
	printf("\n");
	
    VirtualProtect((LPVOID)address, 3, oldProtect, &oldProtect);
    
    AddVectoredExceptionHandler(1, Exceptioner);

    LARGE_INTEGER interval;
    interval.QuadPart = -2 * (1e7);  // sleep for 2 seconds
        
    Sleep(1000); 	/* 
					put any argument here and the execution 
					will be as long as that function sleeps 
					proving that this hook works
					*/
    printf("Counter: %d\n", counter);
}
