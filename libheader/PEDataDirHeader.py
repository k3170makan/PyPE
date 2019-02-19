#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct

from Utils import spaces
import DOSHeader
import DOSHeaderDecoder
import PEHeaderDecoder
import PEDataDirDecoder

class PEDataDirHeader:
	
	__PEDataDirHeader_fmt_dict = {\
							"VirtualAddress":"I",\
							"Size":"I"}
	__PEDataDirHeader_fields = ["VirtualAddress",\
							"Size"]

	def __init__(self,_opt_header=None):
		self.attribute_list =  [  [("VirtualAddress",0),("Size",0)]   ] #array of data dir

		self.opt_header = _opt_header
		if (self.opt_header):
			self.count = self.opt_header.get_numberofrvaandsizes()
			self.set_offset(self.opt_header.len + self.opt_header.offset) 
		self.header_fields = PEDataDirHeader.__PEDataDirHeader_fields 
		self.header_fmt_dict = PEDataDirHeader.__PEDataDirHeader_fmt_dict

	def build_from_binary(self,_filename="",_fileperms="rb"):
		
		if (_filename != ""):
			self.filename = _filename
		opt_decoder = PEDataDirDecoder.Decoder(_filename=self.filename,\
												_fileperms=self.fileperms)
		opt_header,length = opt_decoder.decode(_start=self.offset,_count=self.count)
		self.len = length
		if (opt_header == None or self.count == 0):
			return self.attribute_list

		for index,value in enumerate(opt_header):#might need to undo this hack one day lol
				try:
					for dir_index,datadir in enumerate(value):
						VirtualAddress_name = self.attribute_list[dir_index][0][0] #the data struture choice a messy choice here at best
						VirtualAddress_value = self.attribute_list[dir_index][0][1]
						Size_name = self.attribute_list[dir_index][1][0]
						Size_value = self.attribute_list[dir_index][1][1]
						
						self.attribute_list[dir_index] = [(VirtualAddress_name,VirtualAddress_value),\
																(Size_name,Size_value)]
				except IndexError:
					return self.attribute_list
		return self.attribute_list

	def get_offset(self):
		return self.offset	
	def set_offset(self,_offset):
		self.offset = _offset

	def build_from_optheader(self):
		if (not(self.opt_header)):
			return None	

		self.filename = self.opt_header.filename
		self.fileperms = self.opt_header.fileperms
		self.offset = self.opt_header.offset + self.opt_header.len
		self.count = self.opt_header.get_numberofrvaandsizes()
	
		return self.build_from_binary()

	def __repr__(self):
		doc_string = "\tData Directory\n"
		#for index,field in enumerate(self.header_fields):
		#	pred = len("\t|- %s => [%s]\n")
		#	subj = (field,hex(self.attribute_list[index][1]))
		#	_spaces = spaces(line_length=30,predicate=pred,subject=subj)
		#	doc_string += "\t|- %s =>%s[%s]\n" % (field,_spaces,hex(self.attribute_list[index][1]))
		doc_string += "".join([datadir.__repr__() for datadir in  self.attribute_list])
		return doc_string
