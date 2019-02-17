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
	|- e_lfanew =>[0xd000000000]

	PE header '/home/kh3m/VMSharedFolder/windows_binaries/wmplayer.exe'
	|- Signature =>          [0x4550]
	|- Machine =>             [0x14c]
	|- NumberOfSections =>      [0x6]
	|- TimeDateStamp =>  [0x854a1b2d]
	|- PointerToSymbolTable =>  [0x0]
	|- NumberOfSymbols =>       [0x0]
	|- SizeOfOptionalHeader => [0xe0]
	|- Characteristics =>     [0x102]
	Characteristics:
		|-- [IMAGE_FILE_EXECUTABLE_IMAGE]
		|-- [IMAGE_FILE_32BIT_MACHINE]

		PE Image Optional Header
		|- Magic =>     [0x10b : 32 bit binary]
		|- LinkerVersion =>     [0xc0e : 3086]
		|- SizeOfCode =>     [0x1e00 : 7680]
		|- SizeOfInitalizedData =>     [0x26c00 : 158720]
		|- SizeOfUninitializedData =>     [0x0 : 0]
		|- AddressOfEntryPoint =>     [0x1fb0 : 8112]
		|- BaseOfCode =>     [0x1000 : 4096]
		|- BaseOfData =>     [0x3000 : 12288]
		|- ImageBase =>     [0x400000 : 4194304]
		|- SectionAlignment =>     [0x1000 : 4096]
		|- FileAlignment =>     [0x200 : 512]
		|- MajorOperatingSystemVersion =>     [0xa : 10]
		|- ImageVersion =>     [0xa : 10]
		|- SubSystemVersion =>     [0xa : 10]
		|- Reserved_1 =>     [0x0 : 0]
		|- SizeOfImage =>     [0x2d000 : 184320]
		|- SizeOfHeader =>     [0x400 : 1024]
		|- Checksum =>     [0x3224c : 205388]
		|- SubSystem =>     [0x2 : 2]
		|- DLLCharacteristics =>     [0xc440 : 50240]
			|-- [IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE]
			|-- [IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE]
			|-- [IMAGE_DLLCHARACTERISTICS_NO_SEH]
			|-- [IMAGE_DLLCHARACTERISTICS_GUARD_CF]
		|- SizeOfStackReserve =>     [0x40000 : 262144]
		|- SizeOfStackCommit =>     [0x2000 : 8192]
		|- SizeOfHeapReserve =>     [0x100000 : 1048576]
		|- SizeOfHeapCommit =>     [0x1000 : 4096]

```

