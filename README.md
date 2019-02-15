# PyPE
Dirty Python code for handling PEFiles
PyPE is essentially just a simple struct abusing library to parse Windows PE files.
It builds a dictionary holding a struct fmt for each field in each header.
Concats them up and then pulls the binary file through a series of unpack calls for each header field.
	
TODO:
	* Add sequencers to the libraries
		- sequencers string up structuers in the files according to scriptable rules
			so for instance if you want to naviage from a DOS to a PE, you do so using the e_flanew field,
			the sequencer will then have a format for saying "please find your child leaf using this rule"
			and that way we can build tree's and graphs and stuff with PE files
	* split up the globbed pype.py file in to folders
