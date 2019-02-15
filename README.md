# PyPE
Yet another Python PE File parsing library

PyPE is essentially just a simple struct abusing library to parse Windows PE files.
It builds a dictionary holding a struct fmt for each field in each header.
Concats them up and then pulls the binary file through a series of unpack calls for each header field.
