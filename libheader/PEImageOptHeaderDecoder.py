#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import PEImageOptHeader
"""
Decoders are essentially plugins for how to handle PE files with their inflated,
of course you might want to hex parse it or undo some alphanumeric malwarey nonsense.
Write your own decoder, write your own encoder, same format

"""
class Decoder:
	def __init__(self,_filename="",_fileperms="rb",_start=0):
		self._header = PEImageOptHeader.PEImageOptHeader()
		self.fields = self._header.header_fields
		self.fmt_dict = self._header.header_fmt_dict
		self.fmt = "".join([self.fmt_dict[name] for name in self.fields])
		self.fmt_len = struct.calcsize(self.fmt)
		self.original_file = _filename
		self.decoded_file = ""
		self.fileperms = _fileperms 	
	def decode(self,_start=0):
		self.decoded_file = None
		print(_start)
		with open(self.original_file,self.fileperms) as raw_pe:
			raw_pe.read(_start) #skip to optional header
			_bytes = raw_pe.read(self.fmt_len)
			self.decoded_file = struct.unpack(self.fmt,_bytes)
		return self.decoded_file

	def decode_field(self,index):
		return self.fields[index]

