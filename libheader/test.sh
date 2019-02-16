#!/bin/bash
find ~/ -type f -iname *.exe -exec ./test.py --file {} \;
