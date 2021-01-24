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
COMMA_SYMBOL = ','
REDIRECT_SYMBOL = '>' 
WHITESPACE_SYMBOL = ' '
ARROWHEAD_SYMBOL = '->'
EQUAL_SYMBOL = '='
NULL_SYMBOL = ''
LCURL_SYMBOL = '{'


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
CASE_KEYWORD = 'case '  ## added space to handle invalid keyowrds like 'downcase'
INCLUDE_KEYWORD = 'include' 
WHEN_KEYWORD = 'when'
CASE_DEFAULT_KEYWORD = ':default'
IP_ADDRESS_PATTERN = '0.0.0.0'
HTTP_PATTERN = 'http://'
INVOKE_KEYWORD = 'invoke'
MD5_KEYWORD = 'md5'
SHA1_KEYWORD = 'sha1'
SECRET_PASSWORD_LIST = ['pwd', 'password', 'passwd', 'admin_pass'] #admin_pass is used somewhere , keep an eye for false positives 
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
INVALID_ATTRIBUTE_KEYWORDS   = ['block', 'resource' , '(', ')']  
INVALID_SWITCH_CASE_KEYWORDS = ['downcase' ] 
INVALID_RESO_NAME_KEYWORDS   = ['resource ', 'block', 'else ', ARROWHEAD_SYMBOL, ATTRIBUTE_SYMBOL, 'if ' ] 

TEMP_LOG_FILE = 'temp.output.from.parser.txt'
BASH_CMD = 'bash'
BASH_FLAG = '-c'
NATIVE_PUPPET_PARSER_CMD = 'puppet parser  dump --render-as console' 
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

CASE_WHEN_HEURISTIC      = 100 ## the heuritic is case and when will appear within the first 100 characters 
INVALID_CLASS_KW         = 'block\n'
_DATASET_PATH            = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/' 
PUPPET_KW                = 'puppet-'
MONTH_DATA_KW            = '-2018-06'
MANIFESTS_KW             = 'manifests'
INIT_FILE_KW             = 'init' 
CALL_KW                  = 'call'
DUMMY_FUNC_ASSIGNEE      = 'ESLIC_DUMMY_FUNC_ASSIGNEE'
OUTPUT_WEAK_ENCR_KW      = 'WEAK_ENCRYPTION' 

CSV_HEADER               = ['FILE_NAME', 'SUSPICIOUS_COMMENT', 'MISSING_DEFAULT_SWITCH', 'INVALID_IP', 'INSECURE_HTTP', 'HARD_CODED_SECRET', 'EMPTY_PASSWORD', 'DEFAULT_ADMIN', 'WEAK_ENCRYPT', 'TOTAL' ]
CSV_ENCODING             = 'utf-8'
PKL_WRITE_MODE           = 'wb'
TIME_FORMAT              = '%Y-%m-%d %H:%M:%S'