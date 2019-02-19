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
[*] parsing '[binary].exe...'
DOS header  '[binary].exe...'
	|- e_magic =>       [0x5a4d]
	|- e_cblp =>          [0x90]
	|- e_cp =>             [0x3]
	|- e_crlc =>           [0x0]
	|- e_cparhdr =>        [0x4]
	|- e_minalloc =>       [0x0]
	|- e_maxalloc =>    [0xffff]
	|- e_ss =>             [0x0]
	|- e_sp =>            [0xb8]
	|- e_csum =>           [0x0]
	|- e_ip =>             [0x0]
	|- e_lfarlc =>         [0x0]
	|- e_ovno =>          [0x40]
	|- e_res =>            [0x0]
	|- e_oemid =>          [0x0]
	|- e_oeminfo =>        [0x0]
	|- e_res2 =>           [0x0]
	|- e_lfanew =>[0xe800000000]

	PE header '[binary].exe'
	|- Signature =>                   [0x4550]
	|- Machine =>                        [ 34404:'IMAGE_FILE_MACHINE_AMD64 ' ]
	|- NumberOfSections =>               [0x5]
	|- TimeDateStamp =>           [0x50bd9489]
	|- PointerToSymbolTable =>           [0x0]
	|- NumberOfSymbols =>                [0x0]
	|- SizeOfOptionalHeader =>          [0xf0]
	Characteristics:
		|-- [IMAGE_FILE_RELOCS_STRIPPED]
		|-- [IMAGE_FILE_EXECUTABLE_IMAGE]
		|-- [IMAGE_FILE_LARGE_ADDRESS_AWARE]

		PE Image Optional Header
		|- Magic =>     [0x20b : 64 bit binary]
		|- LinkerVersion =>     [0x8 : 8]
		|- SizeOfCode =>     [0xf400 : 62464]
		|- SizeOfInitalizedData =>     [0x13400 : 78848]
		|- SizeOfUninitializedData =>     [0x0 : 0]
		|- AddressOfEntryPoint =>     [0x2590 : 9616]
		|- BaseOfCode =>     [0x1000 : 4096]
		|- BaseOfData =>     [0x40000000 : 1073741824]
		|- ImageBase =>     [0x1 : 1]
		|- SectionAlignment =>     [0x1000 : 4096]
		|- FileAlignment =>     [0x200 : 512]
		|- MajorOperatingSystemVersion =>     [0x4 : 4]
		|- ImageVersion =>     [0x0 : 0]
		|- SubSystemVersion =>     [0x20005 : 131077]
		|- Reserved_1 =>     [0x0 : 0]
		|- SizeOfImage =>     [0x28000 : 163840]
		|- SizeOfHeader =>     [0x400 : 1024]
		|- Checksum =>     [0x2cfe9 : 184297]
		|- SubSystem =>     [0x2 : IMAGE_SUBSYSTEM_WINDOWS_GUI ]
		|- DLLCharacteristics =>     [0x8000 : 32768]
			|-- [IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE]
		|- SizeOfStackReserve =>     [0x100000 : 1048576]
		|- SizeOfStackCommit =>     [0x0 : 0]
		|- SizeOfHeapReserve =>     [0x1000 : 4096]
		|- SizeOfHeapCommit =>     [0x0 : 0]
		|- LoaderFlags =>     [0x0 : 0]
		|- NumberOfRvaAndSizes =>     [0x10 : 16]

```
