#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PEImageOptHeaderDecoder
import PEHeader
from Utils import spaces

class PEImageOptHeader:
	__PEImageOptHeader_magic_versions = {0x10B:"32 bit binary",\
														0x20B:"64 bit binary"}
	__PEImageOptHeader_subsys_types = {\
					0 :"IMAGE_SUBSYSTEM_UNKNOWN",\
					1 :"IMAGE_SUBSYSTEM_NATIVE",\
					2 :"IMAGE_SUBSYSTEM_WINDOWS_GUI",\
					3 :"IMAGE_SUBSYSTEM_WINDOWS_CUI ",\
					5 :"IMAGE_SUBSYSTEM_OS2_CUI ",\
					7 :"IMAGE_SUBSYSTEM_POSIX_CUI ",\
					8 :"IMAGE_SUBSYSTEM_NATIVE_WINDOWS ",\
					9 :"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI ",\
					10 :"IMAGE_SUBSYSTEM_EFI_APPLICATION ",\
					11 :"IMAGE_SUBSYSTEM_EFI_BOOT_ SERVICE_DRIVER ",\
					12 :"IMAGE_SUBSYSTEM_EFI_RUNTIME_ DRIVER ",\
					13 :"IMAGE_SUBSYSTEM_EFI_ROM ",\
					14 :"IMAGE_SUBSYSTEM_XBOX ",\
					16 :"IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"}

	__PEImageOptHeader_dllchar_types = {\
									"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA":0x0020,\
									"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE":0x0040,\
									"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY":0x0080,\
									"IMAGE_DLLCHARACTERISTICS_NX_COMPAT":0x0100,\
									"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION":0x0200,\
									"IMAGE_DLLCHARACTERISTICS_NO_SEH":0x0400,\
									"IMAGE_DLLCHARACTERISTICS_NO_BIND":0x0800,\
									"IMAGE_DLLCHARACTERISTICS_APPCONTAINER":0x1000,\
									"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER":0x2000,\
									"IMAGE_DLLCHARACTERISTICS_GUARD_CF":0x4000,\
									"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE":0x8000}

	__PEImageOptHeader_fmt_dict = {"Magic":"H",\
							"LinkerVersion":"H",\
							"SizeOfCode":"I",
							"SizeOfInitalizedData":"I",\
							"SizeOfUninitializedData":"I",\
							"AddressOfEntryPoint":"I",\
							"BaseOfCode":"I",\
							"BaseOfData":"I",\
							"ImageBase":"I",\
							"SectionAlignment":"I",\
							"FileAlignment":"I",\
							"MajorOperatingSystemVersion":"I",\
							"ImageVersion":"I",\
							"SubSystemVersion":"I",\
							"Reserved_1":"I",\
							"SizeOfImage":"I",\
							"SizeOfHeader":"I",\
							"Checksum":"I",\
							"SubSystem":"H",\
							"DLLCharacteristics":"H",\
							"SizeOfStackReserve":"I",\
							"SizeOfStackCommit":"I",\
							"SizeOfHeapReserve":"I",\
							"SizeOfHeapCommit":"I",\
							"LoaderFlags":"H",\
							"NumberOfRvaAndSizes":"H"}

#TODO : fix last 4 fields of the PE header

	__PEImageOptHeader_fields = ["Magic",\
							"LinkerVersion",\
							"SizeOfCode",
							"SizeOfInitalizedData",\
							"SizeOfUninitializedData",\
							"AddressOfEntryPoint",\
							"BaseOfCode",\
							"BaseOfData",\
							"ImageBase",\
							"SectionAlignment",\
							"FileAlignment",
							"MajorOperatingSystemVersion",\
							"ImageVersion",\
							"SubSystemVersion",\
							"Reserved_1",\
							"SizeOfImage",\
							"SizeOfHeader",\
							"Checksum",\
							"SubSystem",\
							"DLLCharacteristics",\
							"SizeOfStackReserve",\
							"SizeOfStackCommit",\
							"SizeOfHeapReserve",\
							"SizeOfHeapCommit",\
							"LoaderFlags",\
							"NumberOfRvaAndSizes"]





	 
	def __init__(self,_dos_header=None):
		self.attribute_list =  [("Magic",0),\
										("LinkerVersion",0),\
										("SizeofCode",0),\
										("SizeOfInitalizedData",0),\
										("SizeOfUninitializedData",0),\
										("AddressOfEntryPoint",0),\
										("BaseOfCode",0),\
										("BaseOfData",0),\
										("ImageBase",0),\
										("SectionAlignment",0),\
										("FileAlignment",0),\
										("MajorOperatingSystemVersion",0),\
										("ImageVersion",0),\
										("SubSystemVersion",0),\
										("Reserved_1",0),\
										("SizeOfImage",0),\
										("SizeOfHeader",0),\
										("Checksum",0),\
										("SubSystem",0),\
										("DLLCharacteristics",0,[]),\
										("SizeOfStackReserve",0),\
										("SizeOfStackCommit",0),\
										("SizeOfHeapReserve",0),\
										("SizeOfHeapCommit",0),\
										("LoaderFlags",0),\
										("NumberOfRvaAndSizes",0)]


		self.dos_header = _dos_header
		if (self.dos_header):
			self.offset = 16+8 + int(self.dos_header.get_e_lfanew(),16) #I don't know why this works at all
		self.header_fields = \
			PEImageOptHeader.__PEImageOptHeader_fields  
		self.header_fmt_dict = \
			 PEImageOptHeader.__PEImageOptHeader_fmt_dict
		self.header_versions =\
			 PEImageOptHeader.__PEImageOptHeader_magic_versions
		self.header_subsversions =\
			 PEImageOptHeader.__PEImageOptHeader_subsys_types
		self.header_dllchars =\
			 PEImageOptHeader.__PEImageOptHeader_dllchar_types

	def get_magic(self):
		return self.attribute_list[0]

	def set_offset(self,_offset=0):
		self.offset = _offset

	def get_numberofrvaandsizes(self):
		index = self.header_fields.index("NumberOfRvaAndSizes") #Camel script will save us!
		return self.attribute_list[index][1]

	def is32bit(self):
		return self.get_magic() == 0x10b

	def build_from_peheader(self,pe_header=None):
		self.filename = self.pe_header.filename
		self.fileperms = self.pe_header.fileperms
		self.offset = self.pe_header.get_offset() + self.pe_header.fmt_len

		return self.build_from_binary()

	def build_from_dosheader(self,_dos_header=None):
		if (not(self.dos_header)):
			self.dos_header = _dos_header
		self.filename = self.dos_header.filename
		self.fileperms = "rb"

		return self.build_from_binary()	

	def build_from_binary(self,_filename="",_fileperms="rb"):
		if (_filename != ""):
			self.filename = _filename
		if (_fileperms != ""):
			self.fileperms = _fileperms

		optheader_decoder = PEImageOptHeaderDecoder.Decoder(_filename=self.filename,\
                                         _fileperms=self.fileperms)
		optheader,length = optheader_decoder.decode(_start=self.offset)
		self.len = length

		for index,value in enumerate(optheader):

			self.attribute_list[index] = \
				(self.attribute_list[index][0],value)
			if (self.attribute_list[index][0] == "DLLCharacteristics"):

				for char in self.header_dllchars:

					char_value = self.header_dllchars[char]
					and_value = char_value & value

					if (and_value):

						if len(self.attribute_list[index]) == 3:
							self.attribute_list[index][2].append(char)

						else:
							self.attribute_list[index] = \
							(self.attribute_list[index][0],value,[char])
		return self.attribute_list
		
	def __repr__(self):
		doc_string = "\t\tPE Image Optional Header\n"
		for index,field in enumerate(self.header_fields):
			pred = "\t\t|- %s => %s [%s : %s]\n"
			value = self.attribute_list[index][1]
			subj = [field,hex(value),value]
			line_space = 50

			_spaces = spaces(line_length=line_space,\
			predicate=len(pred),subject=len(subj))

			sent = pred % (subj[0],_spaces,subj[1],subj[2])

			if (field == "SubSystem"):
				try:

					subj = [subj[0],subj[1],\
							self.header_subsversions[subj[2]]]

					_spaces = spaces(line_length=line_space,\
							subject=len(subj),predicate=len(pred))

					doc_string  += pred % (subj[0],_spaces\
							,subj[1],subj[2])

				except KeyError: 
					doc_string += sent

			elif (field == "DLLCharacteristics"):
				doc_string  += sent
				if(len(self.attribute_list[index]) == 3):
					for charac in self.attribute_list[index][2]:
						pred = "\t\t\t|-- [%s]\n"
						sent = pred % (charac)
						doc_string += sent

			elif (field == "Magic"):
				try:
					doc_string += pred % (subj[0],_spaces,subj[1],self.header_versions[subj[2]])
				except KeyError:
					doc_string += sent
			else:	
				doc_string += sent
		return doc_string
