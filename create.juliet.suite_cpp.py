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
			
	
def create_random_juliet_c_true(juliet_suite_path_t, language):

	for path, dirs, files in os.walk(juliet_suite_path_t):
		
		test_case_count = 0

		# number of test cases in this path
		count = count_files_matching_regex(path, py_common.get_primary_testcase_filename_regex())

		if path == juliet_suite_path_t:
			print("************************************************************************")
			print("JULIET C TEST CASES (Protection Profile)")
			print("PATH:", path)
			print("TEST CASE COUNT (GRAND TOTAL) :", count)

			# establish the scaling
			if count in range(0, 600):
				scaling = "1.0" # keep all test cases
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

		# use only the right-most folders
		if not dirs:

			# full path to 'main.cpp' and 'main.cpp.back'
			main_cpp = os.path.join(path, "main.cpp")
			main_cpp_back = os.path.join(path, "main.cpp.back")

			if os.path.exists(main_cpp):

				# create main.cpp.backup (if it does not already exists)
				if not os.path.exists(main_cpp_back):
					shutil.copy(main_cpp, main_cpp_back)

				# add '#if 0' to cpp sections of main.cpp (x2)
				disable_cpp_refs_in_main_cpp(main_cpp)

				for file in files:

					if file.endswith(".bat"):

						cwe_bat = os.path.join(path, file)
						cwe_bat_back = os.path.join(path, os.path.splitext(file)[0]+'.back')

						# make backup of .bat file
						if not os.path.exists(cwe_bat_back):
							shutil.copy(cwe_bat, cwe_bat_back)
							# os.path.splitext(cwe_bat)[0]+'.back'
						create_bat_file(cwe_bat, "TRUE")

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

				if fe.endswith(language):

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
							current_line_in_main_cpp = "\t" + reference_to_look_for_in_main_cpp
							new_line_in_main_cpp = "\t//" + reference_to_look_for_in_main_cpp
							print(line.replace(current_line_in_main_cpp, new_line_in_main_cpp), end='')


def create_random_juliet_c_false(suite_path_true, suite_path_false):
	
	# create a full copy of the random /T and put into /F
	shutil.copytree(suite_path_true, suite_path_false)
	
	for path, dirs, files in os.walk(suite_path_false):

		for file in files:
			
			cwe_bat = os.path.join(path, file)

			if file.endswith(".bat"):
				print("FALSE_bat_file:", cwe_bat)
				create_bat_file(cwe_bat, "FALSE")


def remove_dir(path):
	if os.path.isdir(path):
		time.sleep(1)
		print("Deleting the following directory ... ", path)

		shutil.rmtree(path)


if __name__ == '__main__':

	py_common.print_with_timestamp("START: CREATE JULIET SUITE")

	parser = argparse.ArgumentParser(description='This script creates suites for c, cpp and java.')
	parser.add_argument('language', help='Only one of the following languages must be defined (c, cpp, java)')
	args = parser.parse_args()
	suite_language = args.language.lower()

	# construct the paths for the new suite
	juliet_suite_path = os.path.join(os.getcwd(), 'juliet_' + suite_language + '_suite')
	test_case_complete_path = os.path.join(juliet_suite_path + '_complete')
	juliet_suite_path_true = os.path.join(juliet_suite_path, 'T')
	juliet_suite_path_false = os.path.join(juliet_suite_path, 'F')
	juliet_suite_support_path_source = os.path.join(os.getcwd(), 'testcasesupport')
	juliet_suite_support_path_dest = os.path.join(juliet_suite_path, 'testcasesupport')

	# remove files from previous run
	remove_dir(juliet_suite_path)

	# create a full copy of all c-language test cases
	shutil.copytree(test_case_complete_path, juliet_suite_path_true)

	# create random true suite
	create_random_juliet_c_true(juliet_suite_path_true, suite_language)
	# create matching false suite
	create_random_juliet_c_false(juliet_suite_path_true, juliet_suite_path_false)

	# copy juliet support files to suite location
	if suite_language == 'c' or 'cpp':
		shutil.copytree(juliet_suite_support_path_source, juliet_suite_support_path_dest)

	py_common.print_with_timestamp("END: CREATE JULIET SUITE")
