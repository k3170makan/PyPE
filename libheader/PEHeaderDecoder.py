#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PEHeader

class Decoder:
	def __init__(self,_filename="",_fileperms="rb"):
		self.PEHeader = PEHeader.PEHeader()
		self.fields = self.PEHeader.header_fields
		self.fmt = "".join([self.PEHeader.header_fmt_dict[name] for name in self.fields])
		self.fmt_len = struct.calcsize(self.fmt)
		self.original_file = _filename

		self.decoded_file = ""
		self.fileperms = _fileperms 	

	def decode(self,_start=0):
		self.decoded_file = None
		with open(self.original_file,self.fileperms) as raw_pe:
			raw_pe.read(_start)
			_bytes = raw_pe.read(self.fmt_len)
			self.decoded_file = struct.unpack(self.fmt,_bytes)

		return self.decoded_file
	def decode_field(self,index):
		return self.fields[index]

