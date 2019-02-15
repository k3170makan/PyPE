#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import DOSHeaderDecoder

class DEHeader:
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

