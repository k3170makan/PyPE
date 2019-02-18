#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import DOSHeaderDecoder
from Utils import spaces

class PEDataDirectory:
	__PEDataDirectory_fmt_dict = {"VirtualAddress":"I",\
							"Size":"I"}
	
	__PEDataDirectory_fields = ["VirtualAddress",\
					"Size"]
	
	def __init__(self):
		self.attribute_list =  [("VirtualAddress",0),\
										("Size",0)]

		self.header_fields = PEDataDirectory.__fields
		self.header_fmt_dict = PEDataDirectory.__PEDataDirectory_fmt_dict

	def get_offset(self):
		if (self.offset):
			return self.offset
		elif (self.PEHeader):	
			return self.PEHeader.get_numberofrvaandsizes()
		
	def get_virtualaddress(self):
		return self.attribute_list[0] 
	def get_size(self):
		return self.attribute_list[1] 

	"""
		Parse out a PEDataDirectoryHeader.attribute_list straight from a binary file
		def build_from_binary(
				,_filename 				--- filename to parse DOSHeader from
				,_fileperms="rb"		--- fileperms to access file under

		Returns 
			self.attribute_list a list of tuples [("field name",decimal value),...]

	"""
	def build_from_binary(self,_filename,_fileperms="rb"):
		self.filename = _filename
		dosheader = DOSHeaderDecoder.Decoder(_filename=_filename,\
											_fileperms=_fileperms)

		for index,value in \
				enumerate(dosheader.decode()[:len(self.header_fields)]):#HACK might need to undo this hack one day lol
	
			self.attribute_list[index] = \
					(self.attribute_list[index][0],\
					value)

		return self.attribute_list	
	def __repr__(self):
		doc_string = "Data Directory header\n"
		for index,field in enumerate(self.header_fields):
			pred = "\t|- %s => [%s]\n"
			subj = "".join([field,hex(self.attribute_list[index][1])])
			_spaces = spaces(predicate=len(pred),subject=len(subj))
			doc_string += pred % (subj[0],subj[1],subj[2])
		return doc_string
