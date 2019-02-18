# [IN PROGRESS] PyPE
Yet another Python PE File parsing library

PyPE is essentially just a simple struct abusing library to parse Windows PE files.
It builds a couple dictionaries holding a struct fmt for each field in each header.
Then it unpacks a binary stream using struct.unpack and stuffs the data into self documenting objects.

Usage:
```
> ./test.py --help
usage: test.py [-h] [--file FILE]

optional arguments:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  PE filename
```

Example of run:
```
DOS header '/home/kh3m/VMSharedFolder/windows_binaries/wmplayer.exe'
>./test.py --file ../../../chrome.exe 
[*] parsing '../../../chrome.exe'...
DOS header '../../../chrome.exe'
	|- e_magic =>       [0x5a4d]
	|- e_cblp =>          [0x78]
	|- e_cp =>             [0x1]
	|- e_crlc =>           [0x0]
	|- e_cparhdr =>        [0x4]
	|- e_minalloc =>       [0x0]
	|- e_maxalloc =>       [0x0]
	|- e_ss =>             [0x0]
	|- e_sp =>             [0x0]
	|- e_csum =>           [0x0]
	|- e_ip =>             [0x0]
	|- e_lfarlc =>         [0x0]
	|- e_ovno =>          [0x40]
	|- e_res =>            [0x0]
	|- e_oemid =>          [0x0]
	|- e_oeminfo =>        [0x0]
	|- e_res2 =>           [0x0]
	|- e_lfanew =>[0x7800000000]

	PE header '../../../chrome.exe'
	|- Signature =>        [0x785a4d]
	|- Machine =>               [0x1]
	|- NumberOfSections =>      [0x0]
	|- TimeDateStamp =>         [0x4]
	|- PointerToSymbolTable =>  [0x0]
	|- NumberOfSymbols =>       [0x0]
	|- SizeOfOptionalHeader =>  [0x0]
	|- Characteristics =>       [0x0]

		PE Image Optional Header
		|- Magic =>     [0x10b : 32 bit binary]
		|- LinkerVersion =>     [0xe : 14]
		|- SizeOfCode =>     [0xecc00 : 969728]
		|- SizeOfInitalizedData =>     [0x87c00 : 556032]
		|- SizeOfUninitializedData =>     [0x0 : 0]
		|- AddressOfEntryPoint =>     [0xcb180 : 831872]
		|- BaseOfCode =>     [0x1000 : 4096]
		|- BaseOfData =>     [0x0 : 0]
		|- ImageBase =>     [0x400000 : 4194304]
		|- SectionAlignment =>     [0x1000 : 4096]
		|- FileAlignment =>     [0x200 : 512]
		|- MajorOperatingSystemVersion =>     [0x10005 : 65541]
		|- ImageVersion =>     [0x0 : 0]
		|- SubSystemVersion =>     [0x10005 : 65541]
		|- Reserved_1 =>     [0x0 : 0]
		|- SizeOfImage =>     [0x180000 : 1572864]
		|- SizeOfHeader =>     [0x600 : 1536]
		|- Checksum =>     [0x17a79e : 1550238]
		|- SubSystem =>     [0x2 : IMAGE_SUBSYSTEM_WINDOWS_GUI ]
		|- DLLCharacteristics =>     [0xc140 : 49472]
			|-- [IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE]
			|-- [IMAGE_DLLCHARACTERISTICS_NX_COMPAT]
			|-- [IMAGE_DLLCHARACTERISTICS_GUARD_CF]
			|-- [IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE]
		|- SizeOfStackReserve =>     [0x100000 : 1048576]
		|- SizeOfStackCommit =>     [0x1000 : 4096]
		|- SizeOfHeapReserve =>     [0x100000 : 1048576]
		|- SizeOfHeapCommit =>     [0x1000 : 4096]

```
