#!usr/bin/python

def spaces(line_length=35,subject=0,predicate=0):
	return " "*(line_length - (predicate+subject))
