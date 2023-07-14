# IPPeCode
This is the first part of my Principles of Programming Languages course work.


<h1>DOCUMENTATION</h1>

parser.py script is written to check the lexical and syntactical accuracy of a given source program written in IPPeCode
(a text-based language similar to assembly language) and converts the IPPe source code into an XML representation.
The script was developed using Python 3.10.

The script uses re, sys and argparse modules during the execution. It doesn’t support any GUI, can be run only by 
using command-line interface. Additionally it’s not an interactive script which means it’ll not ask for any additional 
information. If the script doesn’t encounter any error, it’ll return to 0.

Usage of the code on the command line is given below. More or less than 2 arguments will cause an error.

**<div align="center"> python parser.py source [output] </div>**
<br>
**source**: input of the textual file with an IPPeCode source code. Program will open this text file and check your code 
accordingly. If you want to use a manual input instead of a text file, you are allowed to use ‘-‘. This will open an stdin 
interface on the terminal. When you are done writing your input, you should press CTRL + Z (Windows) or CTRL + D 
(macOS or Linux) to end your process.

**output**: output file of the resulting XML representation in UTF-8 format. By the end of the program, if your output file 
already exists in the path, it’ll be rewritten. Otherwise, a new file will be created. If your output doesn’t have an 
extension by default, .xml extension will be added. If output file wasn’t specified (‘-‘), the resulting XML representation 
will be written into stdout.

<h3> Return Codes and Descriptions: </h3>

(0) Executed successfully

(11) Parsing Error: Unknown operation code of instruction.

(12) Parsing Error: Missing or excessing operand of instruction.

(14) Parsing Error: Bad kind of operand (e.g., label instead of variable).

(17) Other lexical and syntax errors.

(19) Internal errors

<h3> FIX: </h3>

~~The function parse_ippe_code() is not able to catch escape sequences. Therefore, strings variables are not available.~~

Return code 14 (lexical accuracy) wasn’t used because program is not able to check whether the arithmetic instructions and conditional jumps are the same type.

Code structure is not well-designed, not easy to read and difficult to follow the flow.

<h3> BUGS: </h3>

On the command line arguments, if the output file doesn’t have an extension the program will create an xml file along
with another file with the same name but without an extension. (e.g. if the output file is "qwerty" without an extension, 
the program will create "qwerty.xml" and "qwerty")
