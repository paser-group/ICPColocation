'''
Akond Rahman 
Dec 09, 2020
String constants used in parser and orchestrator 
'''

FILE_READ_MODE = 'r'
NEWLINE_CONSTANT = '\n'
COMMENT_SYMBOL = '#'
LPAREN_SYMBOL = '('
RPAREN_SYMBOL = ')'
ATTRIBUTE_SYMBOL = '=>'


CWE_SUSP_COMMENT_LIST      = ['hack', 'fixme', 'later', 'todo', 'to-do', 'bug'  ]
DEBUG_KW = 'debug' 
DEFAULT_RESO_NAME = 'ESLIC_DEFAULT_RESOURCE_NAME'
DEFAULT_CLASS_NAME = 'ESLIC_DEFAULT_CLASS_NAME'
DEFAULT_INHERIT_NAME = 'ESLIC_DEFAULT_INHERITENCE_NAME'
RESOURCE_KEYWORD = 'resource'
CLASS_KEYWORD    = 'class'
INHERITS_KEYWORD = 'inherits'
ARAMETERS_KEYWORD = 'arameters'
PARAMETERS_KEYWORD = 'parameters'
BLOCK_KEYWORD = 'block'


TEMP_LOG_FILE = 'temp.output.from.parser.txt'
BASH_CMD = 'bash'
BASH_FLAG = '-c'
NATIVE_PUPPET_PARSER_CMD = 'puppet parser  dump --render-as console' 
REDIRECT_SYMBOL = '>' 
WHITESPACE_SYMBOL = ' '
ARROWHEAD_SYMBOL = '->'
EQUAL_SYMBOL = '='
NULL_SYMBOL = ''
PP_EXTENSION = '.pp'

ANALYZING_KEYWORD = 'ANALYZING ...'