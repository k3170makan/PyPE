#!/bin/bash
find ~/ -type f -iname *.exe -exec ./libheader/test.py --file {} \;
