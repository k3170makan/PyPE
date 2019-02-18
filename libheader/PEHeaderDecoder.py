#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PEHeader

class Decoder:
	def __init__(self,_filename="",_fileperms="rb"):
		self._header = PEHeader.PEHeader()
		self.fields = self._header.header_fields
		self.fmt_dict = self._header.header_fmt_dict
		self.fmt = "".join([self.fmt_dict[name] for name in self.fields])
		self.fmt_len = struct.calcsize(self.fmt)
		self.len = 0
		self.original_file = _filename

		self.decoded_file = ""
		self.fileperms = _fileperms 	

	def decode(self,_start=0):
		self.decoded_file = None
		with open(self.original_file,self.fileperms) as raw_pe:
			extra = raw_pe.read(_start)
			_bytes = raw_pe.read(self.fmt_len)
			try:
				self.decoded_file = struct.unpack(self.fmt,_bytes)	
			except struct.error:
				self.len = 0
				return None,self.len
		self.len = len(extra)+len(_bytes)
		return self.decoded_file,self.len
	def decode_field(self,index):
		return self.fields[index]

