#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import DOSHeaderDecoder
from Utils import spaces

class DOSHeader:
	__DOSHeader_fmt_dict = {"e_magic":"H",\
							"e_cblp":"H",\
							"e_cp":"H",\
							"e_crlc":"H",\
							"e_cparhdr":"H",\
							"e_minalloc":"H",\
							"e_maxalloc":"H",\
							"e_ss":"H",\
							"e_sp":"H",\
							"e_csum":"H",\
							"e_ip":"H",\
							"e_lfarlc":"H",\
							"e_ovno":"H",\
							"e_res":"2Q",\
							"e_oemid":"H",\
							"e_oeminfo":"H",\
							"e_res2":"2Q",\
							"e_lfanew":"H"}
	
	__DOSHeader_fields = ["e_magic",\
					"e_cblp",\
					"e_cp",\
					"e_crlc",\
					"e_cparhdr",\
					"e_minalloc",\
					"e_maxalloc",\
					"e_ss",\
					"e_sp",\
					"e_csum",\
					"e_ip",\
					"e_lfarlc",\
					"e_ovno",\
					"e_res",\
					"e_oemid",\
					"e_oeminfo",\
					"e_res2",\
					"e_lfanew"]


	"""
	Object for handling dos files."""
	def __init__(self):
		self.attribute_list =  [("e_magic",0),\
										("e_cblp",0),\
										("e_cp",0),\
										("e_crlc",0),\
										("e_cparhdr",0),\
										("e_minalloc",0),\
										("e_maxalloc",0),\
										("e_ss",0),\
										("e_sp",0),\
										("e_csum",0),
										("e_ip",0),\
										("e_lfarlc",0),\
										("e_ovno",0),\
										("e_res",0),\
										("e_oemid",0),\
										("e_oeminfo",0),\
										("e_res2",0),\
										("e_lfanew",0)]

		self.header_fields = DOSHeader.__DOSHeader_fields  
		self.header_fmt_dict = DOSHeader.__DOSHeader_fmt_dict
		self.len = 0		

	def get_e_lfanew(self):
		lfanew_index = self.header_fields.index("e_lfanew") #17 should be 17
		return hex(self.attribute_list[lfanew_index][1])[:4]
	def get_e_magic(self):
		e_magic_index = self.header_fields.index("e_magic") #1 duh	

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
		self.fileperms = _fileperms
		dosheader_decoder = DOSHeaderDecoder.Decoder(_filename=_filename,\
											_fileperms=_fileperms)
			
		attributes,length = dosheader_decoder.decode()
		self.len = length
		attributes = attributes[:len(self.attribute_list)]#HACK might need to undo this hack one day lol
		for index,value in enumerate(attributes):
			self.attribute_list[index] = (self.attribute_list[index][0],value)

		return self.attribute_list	
	def __repr__(self):
		doc_string = "DOS header '%s'\n" % (self.filename)
		for index,field in enumerate(self.header_fields):
			pred = len("\t|- %s => [%s]\n")
			subj = len("".join([field,hex(self.attribute_list[index][1])]))
			_spaces = spaces(predicate=pred,subject=subj)
			doc_string += "\t|- %s =>%s[%s]\n" % (field,_spaces,hex(self.attribute_list[index][1]))
		return doc_string


