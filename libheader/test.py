#!/usr/bin/python3
#minimalist python pe library				
import sys
import argparse
import struct
import DOSHeader
import PEHeader
import PEImageOptHeader

if __name__ == "__main__":
	
	parser = argparse.ArgumentParser()
	parser.add_argument("--file",\
								"-f",\
								help="PE filename")

	args = parser.parse_args()
	field_count = 0
	print("[*] parsing '%s'..." % (args.file))
	dos_header = DOSHeader.DOSHeader()
	dos_header.build_from_binary(_filename=args.file)

	pe_header = PEHeader.PEHeader(dos_header) 
	pe_header.build_from_dosheader()

	imgopt_header = PEImageOptHeader.PEImageOptHeader(dos_header)
	imgopt_header.build_from_dosheader()	

	print(dos_header)
	print(pe_header)
	print(imgopt_header)

