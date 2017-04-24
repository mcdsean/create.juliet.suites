# ! /usr/bin/env/python 3.0
#
# Counts the test cases and functional variants
#
# 2013-04-17 smcdonagh@keywcorp.com reviewed and added comments
# 2012-07-26 jspielvogel@keywcorp.com change the py_common.print_with_timestamp() calls back to print() when printing to a file
# 2012-07-25 smcdonagh@keywcorp.com: expanded on the use of py_common.print_with_timestamp()
# 2012-06-22 jspielvogel@keywcorp.com: modified to use more methods from py_common
# 2011-02-22 chuck.willis@mandiant.com: initial version hacked from count_testcase_files.py

import sys,os,re
import py_common 

output=sys.stdout

c_cpp_dir = "testcases"
java_dir = "Java"

def count_files_matching_regex(directory, regex):
	count = 0
	"""
	Counts files that match a regex in a certain directory (recursively, case-insensitive).
	"""
	# py_common.find_files_in_dir() uses the regex case-insensitive
	files = py_common.find_files_in_dir(directory, regex)
	for file in files:
		count += 1

	return count

if __name__ == '__main__':
	"""
	Counts the test cases and functional variants for each language.
	"""
	# count c/c++ test cases
	count = count_files_matching_regex(c_cpp_dir, py_common.get_primary_testcase_filename_regex())
	print("C/C++ testcases    =", count, file=output)

	# count c/c++ functional variants
	count = count_files_matching_regex(c_cpp_dir, py_common.get_baseline_functional_variant_regex())
	print("C/C++ functional variants    =", count, file=output)

	# count java test cases
	count = count_files_matching_regex(java_dir, py_common.get_primary_testcase_filename_regex())
	print("Java testcases    =", count, file=output)

	# count java functional variants
	count = count_files_matching_regex(java_dir, py_common.get_baseline_functional_variant_regex())
	print("Java functional variants    =", count, file=output)
	
	output.close
