#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PESectionHeaderDecoder
from Utils import spaces

class PESectionHeader:

	__PESectionHeader_fmt_dict = {"Name":"8B",\
							"VirtualSize":"I",\
							"VirtualAddress":"I",\
							"SizeOfRawData":"I",\
							"PointerToRawData":"I",\
							"PointerToRelocations":"I",\
							"PointerToLineNumbers":"I",\
							"NumberOfRelocations":"H",\
							"NumberOfLineNumbers":"H",\
							"Characteristics":"I"}

	__PESectionHeader_fields = ["Name",\
							"VirtualSize",\
							"VirtualAddress",\
							"SizeOfRawData",\
							"PointerToRawData",\
							"PointerToRelocations",\
							"PointerToLineNumbers",\
							"NumberOfRelocations",\
							"NumberOfLineNumbers",\
							"Characteristics"]




	 
	def __init__(self,_pe_header=None):
		self.attribute_list =  [("Name",""),\
										("VirtualSize",0),\
										("VirtualAddress",0),\
										("SizeOfRawData",0),\
										("PointerToRawData",0),\
										("PointerToRelocations",0),\
										("PointerToLineNumbers",0),\
										("NumberOfRelocations",0),\
										("NumberOfLineNumbers",0),\
										("Characteristics",0,[])]

		self.pe_header = _pe_header
		self.header_fields = PESectionHeader.__PESectionHeader_fields  
		self.header_fmt_dict = PESectionHeader.__PESectionHeader_fmt_dict

	def build_from_binary(self,_filename,_fileperms="rb"):
		self.filename = _filename
		self.fileperms = _fileperms
		if (self.dos_header):
			return self.build_from_dosheader()

		optheader = PESectionHeaderDecoder.Decoder(_filename=_filename,\
												_fileperms=_fileperms)
		for index,value in \
				enumerate(optheader.decode()[:len(self.header_fields)]):#HACK might need to undo this hack one day lol
			self.attribute_list[index] = \
					(self.attribute_list[index][0],\
					value)

		return self.attribute_list	

	def get_offset(self):
		if (not (self.pe_header)):
			return 0
		self.filename = self.dos_header.filename
		self.fileperms = "rb"
		return self.pe_header.size
	def build_from_dosheader(self):
		if (not(self.dos_header)):
		   return None
		self.offset = self.get_offset()
		optheader = PESectionHeaderDecoder.Decoder(_filename=self.filename,\
                                         			 _fileperms=self.fileperms,\
																_offset=self.offset)
		
		for index,value in enumerate(optheader.decode(_start=(self.e_lfanew+self.hack))):
			self.attribute_list[index] = (self.attribute_list[index][0],value)
		return self.attribute_list
	
	def __repr__(self):
		doc_string = "\t\tSection Headers\n"
		for index,field in enumerate(self.header_fields):
			pred = "\t\t|- %s =>%s[%s : %s]\n"
			value = self.attribute_list[index][1]
			subj = [field,hex(value),value]
			_spaces = spaces(line_length=30,predicate=len(pred),subject=len(subj))
			sent = pred % (subj[0],_spaces,subj[1],subj[2])

			doc_string += sent

		return doc_string
