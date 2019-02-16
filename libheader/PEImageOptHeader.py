#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PEImageOptHeaderDecoder

class PEImageOptHeader:
	__PEImageOptHeader_magic_versions = {0x10B:"32 bit binary",\
														0x20B:"64 bit binary"}
	__PEImageOptHeader_subsys_types = {\
									0 :"IMAGE_SUBSYSTEM_UNKNOWN ",
									1 :"IMAGE_SUBSYSTEM_NATIVE ",
									2 :"IMAGE_SUBSYSTEM_WINDOWS_GUI ",
									3 :"IMAGE_SUBSYSTEM_WINDOWS_CUI ",
									5 :"IMAGE_SUBSYSTEM_OS2_CUI ",
									7 :"IMAGE_SUBSYSTEM_POSIX_CUI ",
									8 :"IMAGE_SUBSYSTEM_NATIVE_WINDOWS ",
									9 :"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI ",
									10 :"IMAGE_SUBSYSTEM_EFI_APPLICATION ",
									11 :"IMAGE_SUBSYSTEM_EFI_BOOT_ SERVICE_DRIVER ",
									12 :"IMAGE_SUBSYSTEM_EFI_RUNTIME_ DRIVER ",
									13 :"IMAGE_SUBSYSTEM_EFI_ROM ",
									14 :"IMAGE_SUBSYSTEM_XBOX ",
									16 :"IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"}
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
							"DLLCharacteristics":"H"}

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
							"DLLCharacteristics"]



	 
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
										("DLLCharacteristics",0,[])]


		self.dos_header = _dos_header
		self.header_fields = PEImageOptHeader.__PEImageOptHeader_fields  
		self.header_fmt_dict = PEImageOptHeader.__PEImageOptHeader_fmt_dict
		self.header_versions = PEImageOptHeader.__PEImageOptHeader_magic_versions
		self.header_subsversions = PEImageOptHeader.__PEImageOptHeader_subsys_types

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
		self.e_lfanew = int(self.dos_header.get_e_lfanew(),16)
		
		optheader = PEImageOptHeaderDecoder.Decoder(_filename=self.filename,\
                                         _fileperms=self.fileperms)
		
		for index,value in enumerate(optheader.decode(_start=(self.e_lfanew+16+8))):
			self.attribute_list[index] = \
					(self.attribute_list[index][0],\
					value)

		return self.attribute_list
	
	def __repr__(self):
		doc_string = "\t\tPE Image Optional Header\n"
		for index,field in enumerate(self.header_fields):
			try:
				if (field == "SubSystem"):
					doc_string += " \t\t|- %s => [%s : %s]\n" % (field,\
							hex(self.attribute_list[index][1]),\
							self.header_subsversions[self.attribute_list[index][1]])
				elif (field == "Magic"):
						doc_string += " \t\t|- %s => [%s : %s]\n" % (field,\
							hex(self.attribute_list[index][1]),\
							self.header_versions[self.attribute_list[index][1]])
				else:	
					doc_string += " \t\t|- %s => [%s : %s]\n" % (field,\
							hex(self.attribute_list[index][1]),\
							self.attribute_list[index][1].__repr__())
			except KeyError:
				doc_string += " \t\t|- %s => [%s : %s]\n" % (field,\
						hex(self.attribute_list[index][1]),\
						self.attribute_list[index][1].__repr__())

		return doc_string
