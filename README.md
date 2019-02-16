# PyPE
Yet another Python PE File parsing library

PyPE is essentially just a simple struct abusing library to parse Windows PE files.
It builds a dictionary holding a struct fmt for each field in each header.
Concats them up and then pulls the binary file through a series of unpack calls for each header field.

Example of run:
'''
$test.sh --file /home/kh3m/VMSharedFolder/iverilog-10.0-x86_setup.exe

DOS header '/home/kh3m/VMSharedFolder/iverilog-10.0-x86_setup.exe'
	|- e_magic => [0x5a4d]
	|- e_cblp => [0x50]
	|- e_cp => [0x2]
	|- e_crlc => [0x0]
	|- e_cparhdr => [0x4]
	|- e_minalloc => [0xf]
	|- e_maxalloc => [0xffff]
	|- e_ss => [0x0]
	|- e_sp => [0xb8]
	|- e_csum => [0x0]
	|- e_ip => [0x0]
	|- e_lfarlc => [0x0]
	|- e_ovno => [0x40]
	|- e_res => [0x0]
	|- e_oemid => [0x0]
	|- e_oeminfo => [0x0]
	|- e_res2 => [0x0]
	|- e_lfanew => [0x10000000000]

	PE header '/home/kh3m/VMSharedFolder/iverilog-10.0-x86_setup.exe'
	|- Signature => [0xb8]
	|- Machine => [0x0]
	|- NumberOfSections => [0x0]
	|- TimeDateStamp => [0x1a0040]
	|- PointerToSymbolTable => [0x0]
	|- NumberOfSymbols => [0x0]
	|- SizeOfOptionalHeader => [0x0]
	|- Characteristics => [0x0]

		PE Image Optional Header
 		|- Magic => [0x0 : 0]
 		|- LinkerVersion => [0x0 : 0]
 		|- SizeOfCode => [0x0 : 0]
 		|- SizeOfInitalizedData => [0x0 : 0]
 		|- SizeOfUninitializedData => [0x0 : 0]
 		|- AddressOfEntryPoint => [0x0 : 0]
 		|- BaseOfCode => [0x100 : 256]
 		|- BaseOfData => [0xe0010ba : 234885306]
 		|- ImageBase => [0xcd09b41f : 3439965215]
 		|- SectionAlignment => [0x4c01b821 : 1275181089]
 		|- FileAlignment => [0x909021cd : 2425364941]
 		|- MajorOperatingSystemVersion => [0x73696854 : 1936287828]
 		|- ImageVersion => [0x6f727020 : 1869770784]
 		|- SubSystemVersion => [0x6d617267 : 1835102823]
 		|- Reserved_1 => [0x73756d20 : 1937075488]
 		|- SizeOfImage => [0x65622074 : 1700929652]
 		|- SizeOfHeader => [0x6e757220 : 1853190688]
 		|- Checksum => [0x646e7520 : 1684960544]
 		|- SubSystem => [0x7265 : 29285]
 		|- DLLCharacteristics => [0x0 : 0]
			|-- [IMAGE_DLLCHARACTERISTICS_GUARD_CF]
			|-- [IMAGE_DLLCHARACTERISTICS_APPCONTAINER]
			|-- [IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA]
			|-- [IMAGE_DLLCHARACTERISTICS_NO_SEH]
			|-- [IMAGE_DLLCHARACTERISTICS_NO_ISOLATION]
			|-- [IMAGE_DLLCHARACTERISTICS_NX_COMPAT]
'''

