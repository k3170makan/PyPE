#TODO
Some stuff I need to get out of the way for this thing is ready to rock
- [x] split up libraries
- [x] add decoder for PEHeader.Signature, PEHeader.
- [x] add self documenting repr to PEHeader
- [x] add Characteristics parser (in prog)
- [x] add Data Directory Parser - hint: start parsing use PE.offset + PE.len (its a sequential block so no fancy stuff needed)
- [ ] add Machine type parser
- [x] add Optional Header parser
- [ ] start working on struct sequencers to string up different structures in the file
- [ ] add encoder objects that write out files using unpack 
