import random, shutil, os, argparse, time

import py_common, fileinput 

test_case_list = []
dirsAndFiles = {}  

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
		
		
def disable_cpp_refs_in_main_cpp(main_cpp):	
		# change compiler directive to disable entire CPP sections
		with fileinput.FileInput(main_cpp, inplace=True) as file:
			for line in file:
				print(line.replace("#ifdef __cplusplus", "#if 0"), end='')

def create_bat_file(cwe_bat, t_f):	
	if t_f == "TRUE":
		with fileinput.FileInput(cwe_bat, inplace=True) as file:
			for line in file:					
				print(line.replace("/W3 /MT /GS /RTC1 /bigobj /EHsc /nologo /c", "/DOMITGOOD /W3 /MT /GS /RTC1 /bigobj /EHsc /nologo /c"), end='')
		with fileinput.FileInput(cwe_bat, inplace=True) as file:
			for line in file:					
				print(line.replace(" CWE*.cpp", ""), end='')
	if t_f == "FALSE":
		with fileinput.FileInput(cwe_bat, inplace=True) as file:			
			for line in file:					
				print(line.replace("/DOMITGOOD", "/DOMITBAD"), end='')
			
	
def create_random_juliet_c_true(juliet_suite_path_t):

	for path, dirs, files in os.walk(juliet_suite_path_t):
		
		if "juliet" in path:
			dup_files = []
			test_case_count = 0

			# number of test cases in this path
			count = count_files_matching_regex(path, py_common.get_primary_testcase_filename_regex())
			
			
			if path.count("\\") == 2: # top level directory
				print("************************************************************************")
				print("JULIET C TEST CASES (Protection Profile)")
				print("PATH:", path)
				print("TEST CASE COUNT (GRAND TOTAL) :", count)

				continue
						
			# establish the scaling for this dir or sub-dirs (s01, ...) if applicable
			#if path.count("\\") == 3:
			if path.count("\\") == 4:
				if count in range(0, 600):
					scaling = "1.0" # keep all tesecases
				elif count in range(601, 999):
					scaling = "0.9" # keep 0.9
				elif count in range(1000, 1999):
					scaling = "0.8" # keep 0.8
				elif count in range(2000, 2999):
					scaling = "0.7" # keep 0.7
				elif count in range(3000, 3999):
					scaling = "0.6" # keep 0.6
				else: # >3999
					scaling = "0.5" # keep 0.5

			# for root, dirs, files in os.walk(starting_directory):
			# 	if not dirs:

			#if path.count("\\") >= 3:
			if path.count("\\") >= 4:

				# full path to 'main.cpp' and 'main.cpp.back'
				main_cpp = os.path.join(path, "main.cpp")
				main_cpp_back = os.path.join(path, "main.cpp.back")
				# full path to 'testcases.h' and 'testcases.h.back'
				###testcases_h = os.path.join(path, "testcases.h")
				###testcase_h_back = os.path.join(path, "testcases.h.back")
				
				if os.path.exists(main_cpp):
					
					# create main.cpp.backup (if it does not already exists)
					if not os.path.exists(main_cpp_back):
						shutil.copy(main_cpp, main_cpp_back)				
					# create testcases.h.backup (if it does not already exists)
					###if not os.path.exists(testcase_h_back):
						###shutil.copy(testcases_h, testcase_h_back)
					
					# add '#if 0' to cpp sections of main.cpp (x2)
					disable_cpp_refs_in_main_cpp(main_cpp)
					# todo: add '#if 0' to cpp sections of testcases.h (x2)
				
					for file in files:
						
						if file.endswith(".bat"):
							
							cwe_bat = os.path.join(path, file)
							cwe_bat_back = os.path.join(path, os.path.splitext(file)[0]+'.back')
							
							# make backup of .bat file
							if not os.path.exists(cwe_bat_back):
								shutil.copy(cwe_bat, cwe_bat_back)
								#os.path.splitext(cwe_bat)[0]+'.back'
							create_bat_file(cwe_bat, "TRUE")
															
								
				if "__pycache__" not in path:
					print("------------------------------------------------------------------------")
					print("PATH:", path)
					scale_factor = float(scaling)
					print("SCALE FACTOR              :", scale_factor)
					scaled_count = round(count*scale_factor)
					print("TEST CASE COUNT           :", count)
					print("TEST CASE COUNT (SCALED)  :", scaled_count)
					test_cases_to_delete = count - scaled_count
					print ("TEST CASES TO DELETE      :", test_cases_to_delete)
						
					# delete scaled number of random test cases
					while test_cases_to_delete > 0:
						
						if len(files) != 0:
							# pick a random file in this path
							fe = random.choice(files)
						else:
							break
							
						if fe.endswith(".c"):
						
							# keep track of count
							test_case_count = test_case_count + 1
						
							# break the file name into parts
							random_file_name_parts = py_common.break_up_filename(fe)
											
							# check for multi-file test case
							if str(random_file_name_parts.get('testcase_subfile_id')) != 'None':
								base_file_name = "CWE" + random_file_name_parts.get('testcase_cwe_number') + "_" + random_file_name_parts.get('testcase_cwe_name') + "__" + random_file_name_parts.get('testcase_function_variant') + "_" + random_file_name_parts.get('testcase_flow_variant')
													
								# get a list of all files in this test case						
								dup_files = [x for x in files if base_file_name in x]
								
								for dup in dup_files:
									print("<multi> :", dup)
									files.remove(dup)
									os.remove(os.path.join(path, dup))
								
							else:
								print("<single>:", fe)
								files.remove(fe)
								os.remove(os.path.join(path, fe))
							
							test_cases_to_delete = test_cases_to_delete - 1
							print("TEST CASES DELETED  :", test_case_count)
							print("DELETIONS REMAINING :", test_cases_to_delete)
							
							# ***** selectively disable functions in main.cpp ******
							
							# ditch the file extension and ending letters
							reference_to_look_for_in_main_cpp = os.path.splitext(fe)[0]
							reference_to_look_for_in_main_cpp = reference_to_look_for_in_main_cpp.rstrip('abcdef')
							
							print ("reference_to_look_for_in_main_cpp", reference_to_look_for_in_main_cpp)
							
							# comment out all lines corresponding to the deleted files
							with fileinput.FileInput(main_cpp, inplace=True) as file:
								for line in file:
									curent_line_in_main_cpp = "\t" + reference_to_look_for_in_main_cpp
									new_line_in_main_cpp = "\t//" + reference_to_look_for_in_main_cpp
									print(line.replace(curent_line_in_main_cpp, new_line_in_main_cpp), end='')

							
							# ***** selectively disable functions in testcases.h ******
							'''
							# comment out all lines corresponding to the deleted files
							with fileinput.FileInput(testcases_h, inplace=True) as file:
								for line in file:
									curent_line_in_testcases_h = "\tvoid " + reference_to_look_for_in_main_cpp
									new_line_in_testcases_h = "\t//void " + reference_to_look_for_in_main_cpp
									print(line.replace(curent_line_in_testcases_h, new_line_in_testcases_h), end='')
							'''
		
def create_random_juliet_c_false(suite_path_true, suite_path_false):
	
	# create a full copy of the random /T and put into /F
	shutil.copytree(suite_path_true, suite_path_false)
	
	for path, dirs, files in os.walk(suite_path_false):

		for file in files:
			
			cwe_bat = os.path.join(path, file)

			if file.endswith(".bat"):
				print("FALSE_bat_file:", cwe_bat)
				create_bat_file(cwe_bat, "FALSE")

					
				
if __name__ == '__main__':

	py_common.print_with_timestamp("START: CREATE JULIET SUITE")
	
	current_dir = os.getcwd()
	juliet_test_case_path = current_dir + "\\testcases"
	juliet_suite_path_true = current_dir + "\\juliet\\T"
	juliet_suite_path_false = current_dir + "\\juliet\\F"
	juliet_suite_support_path = current_dir + "\\juliet\\testcasesupport"


	if os.path.exists(juliet_suite_support_path):
		print("Deleting the following directory ... ", juliet_suite_support_path)
		shutil.rmtree(juliet_suite_support_path)
		time.sleep(5)
	if os.path.exists(juliet_suite_path_true):
		print("Deleting the following directory ... ", juliet_suite_path_true)
		shutil.rmtree(juliet_suite_path_true)
		time.sleep(5)
	if os.path.exists(juliet_suite_path_false):
		print("Deleting the following directory ... ", juliet_suite_path_false)		
		shutil.rmtree(juliet_suite_path_false)
		time.sleep(5)
	
	# create a full copy of all c-language test cases
	shutil.copytree(juliet_test_case_path, juliet_suite_path_true)

	# create random true sub-set
	create_random_juliet_c_true(juliet_suite_path_true)			
	# create random false sub-set	
	create_random_juliet_c_false(juliet_suite_path_true, juliet_suite_path_false)			
	# copy juliet support files to suite location 
	#todo: get the following error: Cannot create a file when that file already exists: 'C:\\svn\\create.juliet.suites\\juliet\\testcasesupport'
	shutil.copytree(current_dir + "\\testcasesupport", current_dir + "\\juliet\\testcasesupport")

	py_common.print_with_timestamp("END: CREATE JULIET SUITE")
	
	
	
	
	
	
	
	
	
	