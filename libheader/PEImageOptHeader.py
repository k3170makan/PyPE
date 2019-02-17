#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PEImageOptHeaderDecoder
from Utils import spaces

class PEImageOptHeader:
	__PEImageOptHeader_magic_versions = {0x10B:"32 bit binary",\
														0x20B:"64 bit binary"}
	__PEImageOptHeader_subsys_types = {\
					0 :"IMAGE_SUBSYSTEM_UNKNOWN ",\
					1 :"IMAGE_SUBSYSTEM_NATIVE ",\
					2 :"IMAGE_SUBSYSTEM_WINDOWS_GUI ",\
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
							"SizeOfHeapCommit":"I"}

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
							"SizeOfHeapCommit"]





	 
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
										("SizeOfHeapCommit",0)]


		self.dos_header = _dos_header
		self.header_fields = PEImageOptHeader.__PEImageOptHeader_fields  
		self.header_fmt_dict = PEImageOptHeader.__PEImageOptHeader_fmt_dict
		self.header_versions = PEImageOptHeader.__PEImageOptHeader_magic_versions
		self.header_subsversions = PEImageOptHeader.__PEImageOptHeader_subsys_types
		self.header_dllchars = PEImageOptHeader.__PEImageOptHeader_dllchar_types

	def build_from_binary(self,_filename,_fileperms="rb"):
		self.filename = _filename
		self.fileperms = _fileperms
		if (self.dos_header):
			return self.build_from_dosheader()

		optheader = PEImageOptHeaderDecoder.Decoder(_filename=_filename,\
												_fileperms=_fileperms)
		for index,value in \
				enumerate(optheader.decode()[:len(self.header_fields)]):#HACK might need to undo this hack one day lol
			self.attribute_list[index] = \
					(self.attribute_list[index][0],\
					value)

		return self.attribute_list	

	def build_from_dosheader(self):
		if (not(self.dos_header)):
		   return None
		self.filename = self.dos_header.filename
		self.fileperms = "rb"
		self.hack = 16+8 #will explain this later, I know it works not sure why yet lol
		self.e_lfanew = int(self.dos_header.get_e_lfanew(),16)
		optheader = PEImageOptHeaderDecoder.Decoder(_filename=self.filename,\
                                         _fileperms=self.fileperms)
		
		for index,value in enumerate(optheader.decode(_start=(self.e_lfanew+self.hack))):

			self.attribute_list[index] = (self.attribute_list[index][0],value)
			if (self.attribute_list[index][0] == "DLLCharacteristics"):
				for char in self.header_dllchars:
					print(value)
					char_value = self.header_dllchars[char]
					and_value = char_value & value
					if (and_value):
						if len(self.attribute_list[index]) == 3:
							self.attribute_list[index][2].append(char)
						else:
							self.attribute_list[index] = (self.attribute_list[index][0],value,[char])
		return self.attribute_list
	
	def __repr__(self):
		doc_string = "\t\tPE Image Optional Header\n"
		for index,field in enumerate(self.header_fields):
			pred = "\t\t|- %s =>%s[%s : %s]\n"
			value = self.attribute_list[index][1]
			subj = [field,hex(value),value]
			_spaces = spaces(line_length=30,predicate=len(pred),subject=len(subj))
			sent = pred % (subj[0],_spaces,subj[1],subj[2])

			if (field == "SubSystem"):
				try:
					subj = [subj[0],subj[1],self.header_subsversions[subj[2]]]
					_spaces = spaces(line_length=30,subject=len(subj),predicate=len(pred))
					doc_string  += pred % (subj[0],_spaces,subj[1],self.header_subsversions[subj[2]])
				except KeyError: #TODO should add unique handling for funny values late
					doc_string += sent	
			elif (field == "DLLCharacteristics"):
				doc_string  += sent
				#print(self.attribute_list)
				#print(sent)
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
