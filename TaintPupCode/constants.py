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
QUOTE_SYMBOL = "'"
DOLLAR_SYMBOL  = '$'
SLASH_SYMBOL = '/'
COLON_SYMBOL = ':'
AN_S         = 's'


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
CASE_KEYWORD = 'case'
INCLUDE_KEYWORD = 'include' 
WHEN_KEYWORD = 'when'
CASE_DEFAULT_KEYWORD = ':default'
IP_ADDRESS_PATTERN = '0.0.0.0'
HTTP_PATTERN = 'http://'
INVOKE_KEYWORD = 'invoke'
MD5_KEYWORD = 'md5'
SHA1_KEYWORD = 'sha1'
SECRET_PASSWORD_LIST = ['pwd', 'password', 'passwd']
SECRET_USER_LIST = ['user']
SECRET_KEY_LIST = ['key', 'crypt', 'secret']
INVALID_SECRET_CONFIG_VALUES = [DOLLAR_SYMBOL, ':undef', INVOKE_KEYWORD, '[]', '/', 'call', 'hiera', 'unset', 'undefined' ]  
FORBIDDEN_USER_VALUES = ['domain', 'group', 'mode', 'schema', 'email', '_tenant'] 
FORBIDDEN_PASS_VALUES = ['_auth'] 
FORBIDDEN_KEY_VALUES  = ['separator', 'version', 'map', 'backend', '_host', '_tenant', 'set_', '_service_name', 'keytype', '_buffer_size', 'revocation_interval', 'gpg_pub_', 'analytics_keyspace', '_try_keyset', '_path', '_default']  
ADMIN_KEYWORD = 'admin'
CONCAT_KEYWORD = 'cat'
LOCALHOST_KEYWORD  = 'localhost'
LOCAL_IP_KEYWORD   =  '//1'
XTRA_HTTP_PATTERN  = 'http'
XTRA_HTTP_PROTO_KW = '_protocol'
YUM_KW  = 'yum'
INVALID_ATTRIBUTE_KEYWORDS = ['block', 'resource' , '(', ')']  

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

ANALYZING_KW             = 'ANALYZING ...'
OUTPUT_PASS_KW           = 'PASSWORD'
OUTPUT_USER_KW           = 'USERNAME'
OUTPUT_TOKEN_KW          = 'API_KEY'
OUTPUT_EMPTY_KW          = 'EMPTY_PASSWORD'
OUTPUT_DEFAULT_ADMIN_KW  = 'DEFAULT_ADMIN'
OUTPUT_INVALID_IP_KW     = 'INVALID_IP_ADDRESS' 
OUTPUT_HTTP_KW           = 'INSECURE_HTTP' 
OUTPUT_SECRET_KW         = 'HARD_CODED_SECRET' 
MULTI_TAINT_NONSENSE     = 'MUTI_TAINT_GARBAGE' 
VALID_CONFIG_DEFAULT     = 'VALID_CONFIG_SAMPLE_PLACEHOLDER' 

CASE_WHEN_HEURISTIC = 100 ## the heuritic is case and when will appear within the first 100 characters 