#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import DOSHeader
"""
Decoders are essentially plugins for how to handle PE files with their inflated,
of course you might want to hex parse it or undo some alphanumeric malwarey nonsense.
Write your own decoder, write your own encoder, same format

"""
class Decoder:
	def __init__(self,_filename="",_fileperms="rb"):
		self._header = DOSHeader.DOSHeader()
		self.fields = self._header.header_fields
		self.fmt_dict = self._header.header_fmt_dict
		self.fmt = "".join([self.fmt_dict[name] for name in self.fields])
		self.fmt_len = struct.calcsize(self.fmt)
		self.original_file = _filename

		self.decoded_file = ""
		self.fileperms = _fileperms 	
	def decode(self):
		self.decoded_file = None
		with open(self.original_file,self.fileperms) as raw_pe:
			_bytes = raw_pe.read(self.fmt_len)
			self.decoded_file = struct.unpack(self.fmt,_bytes)
		return self.decoded_file,len(_bytes)

	def decode_field(self,index):
		return self.fields[index]

