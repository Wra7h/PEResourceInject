# PEResourceInject
A way to avoid using VirtualAllocEx/WriteProcessMemory to inject shellcode into a process. 

- Write shellcode to the target's .rsrc as a bitmap using the UpdateResource APIs
- Spawn the exe suspended
- Calculate the shellcode location by parsing the PE header
- Change memory protections
- Get/SetThreadContext to execute

## Usage  
`PEResourceInject.exe -exe <C:\path\to\target.exe> -bin <C:\Path\to\raw\shellcode.bin>`

## References/APIs:  
[A dive into the PE file format by 0xRick](https://0xrick.github.io/win-internals/pe8/)  
    
[BeginUpdateResource](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-beginupdateresourcea)  
[UpdateResource](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-updateresourcea)  
[EndUpdateResource](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-endupdateresourcea)  
