#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
from Utils import spaces
import DOSHeader
import DOSHeaderDecoder
import PEHeaderDecoder

class PEHeader:
	__PEHeaderMachineTypes_dict = {\
		0x0 :["IMAGE_FILE_MACHINE_UNKNOWN ","The contents of this field are assumed to be applicable to any machine type "],\
		0x1d3 :["IMAGE_FILE_MACHINE_AM33 ","Matsushita AM33 "],\
		0x8664:["IMAGE_FILE_MACHINE_AMD64 ","x64 "],\
		0x1c0 :["IMAGE_FILE_MACHINE_ARM ","ARM little endian "],\
		0xaa64:["IMAGE_FILE_MACHINE_ARM64 ","ARM64 little endian "],\
		0x1c4 :["IMAGE_FILE_MACHINE_ARMNT ","ARM Thumb-2 little endian "],\
		0xebc :["IMAGE_FILE_MACHINE_EBC ","EFI byte code "],\
		0x14c :["IMAGE_FILE_MACHINE_I386 ","Intel 386 or later processors and compatible processors "],\
		0x200 :["IMAGE_FILE_MACHINE_IA64 ","Intel Itanium processor family "],\
		0x9041:["IMAGE_FILE_MACHINE_M32R ","Mitsubishi M32R little endian "],\
		0x266 :["IMAGE_FILE_MACHINE_MIPS16 ","MIPS16 "],\
		0x366 :["IMAGE_FILE_MACHINE_MIPSFPU ","MIPS with FPU "],\
		0x466 :["IMAGE_FILE_MACHINE_MIPSFPU16 ","MIPS16 with FPU "],\
		0x1f0 :["IMAGE_FILE_MACHINE_POWERPC ","Power PC little endian "],\
		0x1f1 :["IMAGE_FILE_MACHINE_POWERPCFP","Power PC with floating point support "],\
		0x166 :["IMAGE_FILE_MACHINE_R4000 ","MIPS little endian "],\
		0x5032:["IMAGE_FILE_MACHINE_RISCV32 ","RISC-V 32-bit address space "],\
		0x5064:["IMAGE_FILE_MACHINE_RISCV64 ","RISC-V 64-bit address space "],\
		0x5128:["IMAGE_FILE_MACHINE_RISCV128 ","RISC-V 128-bit address space "],\
		0x1a2 :["IMAGE_FILE_MACHINE_SH3 ","Hitachi SH3 "],\
		0x1a3 :["IMAGE_FILE_MACHINE_SH3DSP ","Hitachi SH3 DSP "],\
		0x1a6 :["IMAGE_FILE_MACHINE_SH4 ","Hitachi SH4 "],\
		0x1a8 :["IMAGE_FILE_MACHINE_SH5 ","Hitachi SH5 "],\
		0x1c2 :["IMAGE_FILE_MACHINE_THUMB ","Thumb "],\
		0x169 :["IMAGE_FILE_MACHINE_WCEMIPSV2","MIPS little-endian WCE v2 "]}
		
	__PEHeaderCharacsTypes_dict = {"IMAGE_FILE_RELOCS_STRIPPED":"0x0001",\
										"IMAGE_FILE_EXECUTABLE_IMAGE":"0x0002",\
										"IMAGE_FILE_LINE_NUMS_STRIPPED":"0x0004",\
										"IMAGE_FILE_LOCAL_SYMS_STRIPPED":"0x0008",\
										"IMAGE_FILE_AGGRESSIVE_WS_TRIM":"0x0010",\
										"IMAGE_FILE_LARGE_ADDRESS_AWARE":"0x0020",\
										"RESERVED":"0x0040",\
										"IMAGE_FILE_BYTES_REVERSED_LO":"0x0080",\
										"IMAGE_FILE_32BIT_MACHINE":"0x0100",\
										"IMAGE_FILE_DEBUG_STRIPPED":"0x0200",\
										"IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP ":"0x0400",\
										"IMAGE_FILE_NET_RUN_FROM_SWAP":"0x0800",\
										"IMAGE_FILE_SYSTEM ":"0x1000",\
										"IMAGE_FILE_DLL ":"0x2000",\
										"IMAGE_FILE_UP_SYSTEM_ONLY ":"0x4000",\
										"IMAGE_FILE_BYTES_REVERSED_HI ":"0x8000"}

	__PEHeader_fmt_dict = {\
							"Signature":"I",\
							"Machine":"H",\
							"NumberOfSections":"H",\
							"TimeDateStamp":"I",\
							"PointerToSymbolTable":"I",\
							"NumberOfSymbols":"I",\
							"SizeOfOptionalHeader":"H",\
							"Characteristics":"H"}
	
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
	def __init__(self,_DOSHeader=None):
		self.attribute_list =  [("Signature",0),\
						("Machine",0),\
						("NumberOfSections",0),\
						("TimeDateStamp",0),\
						("PointerToSymbolTable",0),\
						("NumberOfSymbols",0),\
						("SizeOfOptionalHeader",0),\
						("Characteristics",0,[])] #list at the end is the characs that apply
		self.dos_header	 = _DOSHeader
		if (self.dos_header):
			self.set_offset(int(self.dos_header.get_e_lfanew(),16))
		self.header_fields = PEHeader.__PEHeader_fields 
		self.header_fmt_dict = PEHeader.__PEHeader_fmt_dict
		self.pe_char_fields = PEHeader.__PEHeaderCharacsTypes_dict
		self.pe_machine_types = PEHeader.__PEHeaderMachineTypes_dict
		
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
		self.filename = _filename
		if (self.dos_header):
			return build_from_dosheader(_dosheader=self.dos_header)
	
		peheader,length = PEHeaderDecoder.Decoder(_filename=_filename,\
														_fileperms=_fileperms)

		self.len = length
		for index,value in enumerate(peheader.decode()[:len(self.attribute_list)]):#might need to undo this hack one day lol
			self.attribute_list[index] = (self.attribute_list[index][0],value)

		return self.attribute_list	

	def get_offset(self):
		return self.offset	
	def set_offset(self,_offset):
		self.offset = _offset

	def build_from_dosheader(self):
		if (not(self.dos_header)):
			return None	

		self.filename = self.dos_header.filename
		self.fileperms = self.dos_header.fileperms

		pedecoder = PEHeaderDecoder.Decoder(_filename=self.filename,\
												_fileperms=self.fileperms)
		peheader,length = pedecoder.decode(_start=self.offset)[:len(self.attribute_list)]
		self.len = length

		for index,value in enumerate(peheader):#might need to undo this hack one day lol

			if (self.attribute_list[index][0] == "Characteristics"):
				try:
					for char in self.pe_char_fields:
						char_value = int(self.pe_char_fields[char],16)
						if (value != 0 and (int(char_value) & value != 0)):
							if len(self.attribute_list[index]) == 3:
								self.attribute_list[index][2].append(char)
							else:
								self.attribute_list[index] = (self.attribute_list[index][0],\
																		value,[char])
				except KeyError:
					pass
			else:
				self.attribute_list[index] = (self.attribute_list[index][0],value)	
		return self.attribute_list

	def __repr__(self):
		doc_string = "\tPE header '%s'\n" % (self.filename)
		for index,field in enumerate(self.header_fields):
			pred = "\t|- %s =>%s[%s]\n"
			subj = "".join([field,hex(self.attribute_list[index][1])])
			_spaces = spaces(line_length=50,\
					predicate=len(pred),subject=len(subj))

			subj = (field,_spaces,\
					hex(self.attribute_list[index][1]))

			if (self.attribute_list[index][0] == "Machine"):
				field_name = self.attribute_list[index][0]
				machine_type_value = self.attribute_list[index][1]
				machine_type_desc = self.pe_machine_types[machine_type_value][0]
				pred = "\t|- %s =>%s[ %s:'%s' ]\n"

				_spaces = spaces(line_length=50,\
					predicate=len(pred),subject=len(subj))

				subj = (field_name,_spaces,\
							machine_type_value,machine_type_desc)

				doc_string += pred % (subj[0],subj[1],subj[2],subj[3])

			elif (self.attribute_list[index][0] == "Characteristics"\
				 and len(self.attribute_list[index]) == 3):
				doc_string += "\tCharacteristics:\n"

				for charac in self.attribute_list[index][2]:
					doc_string += "\t\t|-- [%s]\n" % (charac)
			else:
				doc_string += pred % subj
		return doc_string
