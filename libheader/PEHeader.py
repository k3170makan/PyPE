#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import DOSHeaderDecoder

class PEHeader:
	__PEHeaderMachineTypes_dict = {"IMAGE_FILE_MACHINE_UNKNOWN ":"0x0",
									 "IMAGE_FILE_MACHINE_AM33 ":"0x1d3",\
									 "IMAGE_FILE_MACHINE_AMD64 ":"0x8664",\
									 "IMAGE_FILE_MACHINE_ARM ":"0x1c0",\
									 "IMAGE_FILE_MACHINE_ARM64 ":"0xaa64",\
									 "IMAGE_FILE_MACHINE_ARMNT ":"0x1c4",\
									 "IMAGE_FILE_MACHINE_EBC ":"0xebc",\
									 "IMAGE_FILE_MACHINE_I386 ":"0x14c",\
									 "IMAGE_FILE_MACHINE_IA64 ":"0x200",\
									 "IMAGE_FILE_MACHINE_M32R ":"0x9041",\
									 "IMAGE_FILE_MACHINE_MIPS16 ":"0x266",\
									 "IMAGE_FILE_MACHINE_MIPSFPU ":"0x366",\
									 "IMAGE_FILE_MACHINE_MIPSFPU16 ":"0x466",\
									 "IMAGE_FILE_MACHINE_POWERPC ":"0x1f0",\
									 "IMAGE_FILE_MACHINE_POWERPCFP":"0x1f1",\
									 "IMAGE_FILE_MACHINE_R4000 ":"0x166 ",\
									 "IMAGE_FILE_MACHINE_RISCV32 ":"0x5032",\
									 "IMAGE_FILE_MACHINE_RISCV64 ":"0x5064",\
									 "IMAGE_FILE_MACHINE_RISCV128 ":"0x5128",\
									 "IMAGE_FILE_MACHINE_SH3 ":"0x1a2",\
									 "IMAGE_FILE_MACHINE_SH3DSP ":"0x1a3",\
									 "IMAGE_FILE_MACHINE_SH4 ":"0x1a6",\
									 "IMAGE_FILE_MACHINE_SH5 ":"0x1a8",\
									 "IMAGE_FILE_MACHINE_THUMB ":"0x1c2",\
									 "IMAGE_FILE_MACHINE_WCEMIPSV2":"0x169"}

	__PEHeaderCharacsTypes_dict = {"IMAGE_FILE_RELOCS_STRIPPED ":"0x0001",\
										"IMAGE_FILE_EXECUTABLE_IMAGE ":"0x0002",\
										"IMAGE_FILE_LINE_NUMS_STRIPPED ":"0x0004",\
										"IMAGE_FILE_LOCAL_SYMS_STRIPPED":"0x0008",\
										"IMAGE_FILE_AGGRESSIVE_WS_TRIM ":"0x0010",\
										"IMAGE_FILE_LARGE_ADDRESS_ AWARE ":"0x0020",\
										"IMAGE_FILE_BYTES_REVERSED_LO ":"0x0040",\
										"IMAGE_FILE_32BIT_MACHINE ":"0x0080",\
										"IMAGE_FILE_DEBUG_STRIPPED ":"0x0100",\
										"IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP ":"0x0200",\
										"IMAGE_FILE_NET_RUN_FROM_SWAP":"0x0400",\
										"IMAGE_FILE_SYSTEM ":"0x0800",\
										"IMAGE_FILE_DLL ":"0x1000",\
										"IMAGE_FILE_UP_SYSTEM_ONLY ":"0x2000",\
										"IMAGE_FILE_BYTES_REVERSED_HI ":"0x4000"}

	__PEHeader_fmt_dict = {\
							"Signature":"I",\
							"Machine":"I",\
							"NumberOfSections":"I",\
							"TimeDateStamp":"2I",\
							"PointerToSymbolTable":"2I",\
							"NumberOfSymbols":"2I",\
							"SizeOfOptionalHeader":"I",\
							"Characteristics":"I"}
	
	__PEHeader_fields = ["Signature",\
							"Machine",\
							"NumberOfSections",\
							"TimeDateStamp",\
							"PointerToSymbolTable",\
							"NumberOfSymbols",\
							"SizeOfOptionalHeader",\
							"Characteristics"]

	"""
	Object for handling PEHeaders files."""
	def __init__(self,DOSHeader):
		self.attribute_list =  [("Signature",0),\
						("Machine",0),\
						("NumberOfSections",0),\
						("TimeDateStamp",0),\
						("PointerToSymbolTable",0),\
						("NumberOfSymbols",0),\
						("SizeOfOptionalHeader",0),\
						("Characteristics",0)]
		self.DOSHeader	 = DOSHeader
		self.header_fields = PEHeader.__PEHeader_fields 
		self.header_fmt_dict = PEHeader.__PEHeader_fmt_dict

	def get_siganture(self):
		index = self.header_fields.index("Signature") 
		return self.attribute_list[index]

	def get_machine(self):
		index = self.header_fields.index("Machine") 
		return self.attribute_list[index]

	def get_timedatestamp(self):
		index = self.header_fields.index("TimeDateStamp") 
		return self.attribute_list[index]

	def get_pointertosymboltable(self):
		index = self.header_fields.index("PointerToSymbolTable") 
		return self.attribute_list[index]

	def get_numberofsymbols(self):
		index = self.header_fields.index("NumberOfSymbols") 
		return self.attribute_list[index]

	def get_sizeofoptionalheader(self):
		index = self.header_fields.index("SizeOfOptionalHeader") 
		return self.attribute_list[index]
	def get_characteristics(self):
		index = self.header_fields.index("Characteristics") 
		return self.attribute_list[index]

	"""
		Parse out a DOSHeader.attribute_list straight from a binary file
		def build_from_binary(
				,_filename 				--- filename to parse DOSHeader from
				,_fileperms="rb"		--- fileperms to access file under

		Returns 
			self.attribute_list a list of tuples [("field name",decimal value),...]

	"""
	def build_from_binary(self,_filename,_fileperms="rb"):
		peheader = PEHeaderDecoder.Decoder(_filename=_filename,\
												_fileperms=_fileperms)

		for index,value in \
				enumerate(peheader.decode()[:len(self.header_fields)]):#might need to undo this hack one day lol
	
			self.attribute_list[index] = \
					(self.attribute_list[index][0],\
					value)

		return self.attribute_list	

