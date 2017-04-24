Description:

The files in this directory create a  random sub-set of (c-language) Juliet test cases to be used in the Kilo Suites along with the KDM test cases.

The script "create.juliet.suite_c.py" copies all files in the "testcases" directory and puts them into "juliet/T". The "testcases" folder contains all c-language test cases and was derived directly fromt he NIST web site. 

Once a full set of c-language files are contained in "juliet/T", the script then reanomly removes test cases until the pre-determined thresholds are met. Next, the .bat files are modified to add "/DOMITGOOD" to the command line. This completes the TRUE(BAD) set.

Next, all remaining files in the "julite/T" directory are copied to "juliet/F". The .bat files in this new set are modified to change the "/DOMITGOOD" to "/DOMITBAD". THis completes the FALSE(GOOD) set.

Finally, the "testcasesupport" folder is copied to the top-level directory which is needed for building and scanning. 

Sample usage:

create.juliet.suite_c.py > juliet_suite_creation_log_01.txt 2>&1

