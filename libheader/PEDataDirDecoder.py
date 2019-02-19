#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PEDataDirHeader

class Decoder:
	def __init__(self,_filename="",_fileperms="rb"):

		self.fileperms = _fileperms 	
		self.filename = _filename
		self.header = PEDataDirHeader.PEDataDirHeader()
		self.fields = self.header.header_fields
		self.fmt_dict = self.header.header_fmt_dict
		self.fmt = "".join([self.fmt_dict[name] for name in self.fields])
		self.fmt_len = struct.calcsize(self.fmt)
		self.len = 0
		self.original_file = _filename

	def decode(self,_start=0,_count=0):
		self.decoded_file = []
		self.len = 0
		self.count = _count

		with open(self.original_file,self.fileperms) as raw_pe:
			extra = raw_pe.read(_start)
			self.len += len(extra)
			#try:
			if (self.count == 0):
				return [],0
			for directory in range(self.count):
				_bytes = raw_pe.read(self.fmt_len)
				self.len += len(_bytes)
				unpack = struct.unpack(self.fmt,_bytes)
				if (unpack != None):
					self.decoded_file.append(unpack)
			#except struct.error:
			#	self.len = 0
			#	return None,self.len
		return self.decoded_file,self.len
	def decode_field(self,index):
		return self.fields[index]

