#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse

import struct
class _PEHeaderDecoder:
	def __init__(self,init_filename="",init_fileperms="rb"):
		
		#PE field name's for documentation functions
		__PEHeader_fields = ["e_magic",\
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

		#dictionary to bulid a format string for struct.unpack
		__PEHeader_fmt_dict = {"e_magic":"H",\
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

		#Decoder fields for decoding stuff
		self.fields = __DOS_fields
		self.fmt = "".join([__DOS_fmt_dict[name] for name in self.fields])
		self.fmt_len = struct.calcsize(self.fmt)
		self.original_file = init_filename
		self.decoded_file = ""
		self.fileperms = init_fileperms 	

	def decode(self):
		self.decoded_file = None
		with open(self.original_file,self.fileperms) as raw_pe:
			_bytes = raw_pe.read(self.fmt_len)
			self.decoded_file = struct.unpack(self.fmt,_bytes)
		return self.decoded_file
	def decode_field(self,index):
		return self.fields[index]

class _DOSHeader:
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
	def get_e_lfanew(self):
		lfanew_index = _DOSHeaderDecoder.__DOS_fields.indexof("e_lfanew") #17 should be 17
		return self.attribute_list[lfanew_index]
	def get_e_magic(self):
		e_magic_index = _DOSHeaderDecoder.__DOS_fields.indexof("e_magic") #1 duh	
	def build_from_binary(self,_filename,_fileperms="rb"):
		dosheader = _DOSHeaderDecoder(_filename=_filename,\
												_fileperms=_fileperms)

		for index,value in enumerate(dosheader.decode()[:len(self.attribute_list[index])]):#might need to undo this hack one day lol
			print(index,value)
			self.attribute_list[index] = (self.attribute_list[index][0],value)
		return self.attribute_list	

class _DOSHeaderDecoder:
	def __init__(self,_filename="",_fileperms="rb"):
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

		self.fields = __DOSHeader_fields
		self.fmt = "".join([__DOSHeader_fmt_dict[name] for name in self.fields])
		self.fmt_len = struct.calcsize(self.fmt)
		self.original_file = _filename

		self.decoded_file = ""
		self.fileperms = _fileperms 	
	def decode(self):
		self.decoded_file = None
		with open(self.original_file,self.fileperms) as raw_pe:
			"""
			for index,field in enumerate(self.fields):
				fmt = self.fmt_dict[field]
				print(fmt)
				size = struct.calcsize(fmt)
				_bytes = raw_pe.read(size)
				self.decoded_file.append(struct.unpack(fmt,\
																	_bytes)[0])
			"""
			_bytes = raw_pe.read(self.fmt_len)
			self.decoded_file = struct.unpack(self.fmt,_bytes)

		return self.decoded_file
	def decode_field(self,index):
		return self.fields[index]

class PyPE:
	def __init__(self,_filename,decoder=_DOSHeaderDecoder):
		self.filename = _filename
		self.fileperms = "rb"
		self.decoder = _DOSHeaderDecoder(_filename=self.filename,\
													_fileperms=self.fileperms)

		self.file_handle = None
	def inflate_file(self):
		self.decoded_file = self.decoder.decode()
		return self.decoded_file
	def get_field_name(self,index):
		return self.decoder.decode_field(index)

if __name__ == "__main__":
	
	parser = argparse.ArgumentParser()
	parser.add_argument("--file",\
								"-f",\
								help="PE filename")

	args = parser.parse_args()
	pype = PyPE(_filename=args.file)
	inflate = pype.inflate_file()
	field_count = 0
	print(inflate)
	#for index,field in enumerate(inflate):	
	#	try:
	#		print("[*](%d) %s :=> %s : %s" % (index,pype.get_field_name(field_count),field.__repr__(),hex(field)))
	#	except ValueError:
	#		print("[*](%d) %s :=> [ %s ]" % (index,pype.get_field_name(field_count),field))
	#	except IndexError:
	#		pass
	#	field_count += 1

	dos_header = _DOSHeader()
	dos_header.build_from_binary(args.file)
	print(dos_header)
