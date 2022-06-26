# PEResourceInject
A way to avoid using VirtualAllocEx/WriteProcessMemory to inject shellcode into a process. You need access to modify the target executable.  

If the target exe has a .rsrc section already, it is overwritten with the new resource. However if the exe did not have a .rsrc, the section is added before being spawned.

- Write shellcode to the target's .rsrc as a bitmap using the UpdateResource APIs
- Spawn the exe suspended
- Calculate the shellcode location by parsing the PE header
- VirtualProtectEx to RX
- Get/SetThreadContext to execute

## Usage (x64 only)  
`PEResourceInject.exe -exe <C:\path\to\target.exe> -bin <C:\Path\to\raw\shellcode.bin>`

Tested with:  
- MS Office/VLC/FireFox 
- Shellcode: MSFVenom/Apollo

### References/APIs:  
[A dive into the PE file format by 0xRick](https://0xrick.github.io/win-internals/pe8/)  
    
[BeginUpdateResource](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-beginupdateresourcea)  
[UpdateResource](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-updateresourcea)  
[EndUpdateResource](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-endupdateresourcea)  
