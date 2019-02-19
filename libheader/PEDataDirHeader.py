#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct

from Utils import spaces
import DOSHeader
import DOSHeaderDecoder
import PEHeaderDecoder

class PEDataDirHeader:
	
	__PEHeader_fmt_dict = {\
							"VirtualAddress":"I",\
							"Size":"I"}
	__PEHeader_fields = ["VirtualAddress",\
							"Size"]

	def __init__(self,_pe_header=None):
		self.attribute_list =  [("VirtualAddress",0),\
						("Size",0)] 

		self.pe_header = _pe_header
		if (self.pe_header):
			self.set_offset(pe_header.len + pe_header.offset) 

		self.header_fields = PEDataDirHeader.__PEDataDirHeader_fields 
		self.header_fmt_dict = PEDataDirHeader.__PEDataDirHeader_fmt_dict

	"""
		Parse out a DOSHeader.attribute_list straight from a binary file
		def build_from_binary(
				,_filename 				--- filename to parse DOSHeader from
				,_fileperms="rb"		--- fileperms to access file under

		Returns 
			self.attribute_list a list of tuples [("field name",decimal value),...]

	"""
	def build_from_binary(self,_filename,_fileperms="rb"):
	
		peheader,length = PEHeaderDecoder.Decoder(_filename=_filename,\
														_fileperms=_fileperms)

		pedecoder = PEHeaderDecoder.Decoder(_filename=self.filename,\
												_fileperms=self.fileperms)
		peheader,length = pedecoder.decode(_start=self.offset)[:len(self.attribute_list)]
		self.len = length

		for index,value in enumerate(peheader):#might need to undo this hack one day lol

				self.attribute_list[index] = (self.attribute_list[index][0],value)	
		return self.attribute_list

	def get_offset(self):
		return self.offset	
	def set_offset(self,_offset):
		self.offset = _offset

	def build_from_peheader(self):
		if (not(self.pe_header)):
			return None	

		self.filename = self.pe_header.filename
		self.fileperms = self.pe_header.fileperms
		self.offset = self.pe_header.offset + self.pe_header.len
		return self.build_from_binary()

	def __repr__(self):
		doc_string = "\tData Directory\n"
		for index,field in enumerate(self.header_fields):
			pred = len("\t|- %s => [%s]\n")
			subj = len("".join([field,hex(self.attribute_list[index][1])]))
			_spaces = spaces(line_length=30,predicate=pred,subject=subj)

			doc_string += "\t|- %s =>%s[%s]\n" % (field,_spaces,hex(self.attribute_list[index][1]))
		return doc_string
