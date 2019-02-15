#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct

#old copy of some code that whips up parser and decoder objects
from DOSHeaderDecoder import _DOSHeaderDecoder

class PyPE:
	def __init__(self,_filename,decoder=_DOSHeaderDecoder):
		self.filename = _filename
		self.fileperms = "rb"
		self.decoder = _DOSHeaderDecoder(_filename=self.filename,\
													_fileperms=self.fileperms)

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

	for index,field in enumerate(inflate):	
		try:
			print("[*](%d) %s :=> %s : %s" % (index,pype.get_field_name(field_count),field.__repr__(),hex(field)))
		except ValueError:
			print("[*](%d) %s :=> [ %s ]" % (index,pype.get_field_name(field_count),field))
		except IndexError:
			pass
		field_count += 1
