<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * all functions are called via api_call() from bitfire.php and all authentication 
 * is done there before calling any of these methods.
 */

namespace BitFire;

const STATUS_SERVER_STATE_FAIL = -1;


const RESTRICTED_FILES = ["wp-config", ".."];
const FEATURE_CLASS = array(0 => 'require_full_browser', 10000 => 'xss_block', 11000 => 'web_filter_enabled', 12000 => 'web_filter_enabled', 13000 => 'web_filter_enabled', 14000 => 'sql_block', 15000 => 'web_filter_enabled', 16000 => 'web_filter_enabled', 17000 => 'web_filter_enabled', 18000 => 'spam_filter_enabled', 20000 => 'require_full_browser', 21000 => 'file_block', 22000 => 'check_domain', 23000 => 'check_domain', 24000 => 'whitelist_enable', 25000 => 'blacklist_enable', 26000 => 'rate_limit', 27000 => 'require_full_browser', 29000 => 'rasp_filesystem', 30000 => 'rasp_js', 31000 => 'whitelist_enable', 32000 => 'rasp_db', 33000 => 'rasp_network', 50000 => 'web_filter_enabled');
const FEATURE_NAMES = array(0 => 'IP / Browser', 10000 => 'Cross Site Scripting', 11000 => 'Generic Web Filtering', 12000 => 'Generic Web Filtering', 13000 => 'Generic Web Filtering', 14000 => 'SQL Injection', 15000 => 'Generic Web Filtering', 16000 => 'Generic Web Filtering', 17000 => 'Generic Web Filtering', 18000 => 'Spam Content', 20000 => 'JavaScript Required', 21000 => 'File Upload', 22000 => 'Domain Name Verify Failed', 23000 => 'Domain Verify Failed', 24000 => 'Bot Attempted Restricted Access', 25000 => 'Malicious Robot', 26000 => 'Rate Limit Exceeded', 27000 => 'JavaScript Required', 29000 => 'PHP File Lock', 30000 => 'Strict CMS Requests', 31000 => 'Invalid Robot Network 31', 32000 => 'Unauthorized User Edit', 33000 => 'Network RASP', 50000 => 'Generic Web Filtering');
const MESSAGE_CLASS = array(0 => 'unknown', 10000 => 'Cross Site Scripting', 11000 => 'General Web Blocking', 12000 => 'Remote Code Execution', 13000 => 'Format String Vulnerability', 14000 => 'SQL Injection', 15000 => 'Local File Include', 16000 => 'Web Shell Access', 17000 => 'Dot Dot Attack', 18000 => 'SPAM', 20000 => 'Browser Impersonation', 21000 => 'PHP Script Upload', 22000 => 'General Web Blocking', 23000 => 'Invalid Domain', 24000 => 'Bot Network Auth', 25000 => 'Blacklist Bot', 26000 => 'Rate Limit IP', 27000 => 'Spoofed Browser', 29000 => 'File Write Protection', 30000 => 'XSS account takeover', 31000 => 'Unknown Bot', 32000 => 'Database Spam', 33000 => 'RASP Networking', 50000 => '');
const CODE_CLASS = array(0 => 'robot.svg', 10000 => 'xss.svg', 11000 => 'xxe.svg', 12000 => 'bacteria.svg', 13000 => 'fire.svg', 14000 => 'sql.svg', 15000 => 'file.svg', 16000 => 'php.svg', 17000 => 'fire.svg', 21000 => 'php.svg', 22000 => 'robot.svg', 23000 => 'robot.svg', 24000 => 'robot.svg', 25000 => 'badbot.svg', 26000 => 'speed.svg', 27000 => 'robot.svg', 29000 => 'php.svg', 30000 => 'xss.svg', 31000 => 'badbot.svg', 32000 => 'sql.svg', 33000 => 'xxe.svg', 50000 => 'rule.svg');

const BITFIRE_API_FN = array('\\BitFire\\dump_hashes', '\\BitFire\\review', '\\BitFire\\allow', '\\BitFire\\send_mfa', '\\BitFire\\delete', '\\BitFire\\repair', '\\BitFire\\diff','\\BitFire\\SETTINGS', '\\BitFire\\MALWARESCAN', '\\BitFire\\set_pass', '\\BitFire\\clear_cache', '\\BitFire\\upgrade', '\\BitFire\\hash_diffs', '\\BitFire\\DASHBOARD', '\\BitFire\\download', '\\BitFire\\rem_api_exception', '\\BitFire\\add_api_exception', '\\BitFire\\unlock_site', '\\BitFire\\lock_site', '\\BitFire\\backup_database', '\\BitFire\\add_list_elm','\\BitFire\\clean_post', '\\BitFire\\scan_malware', '\\BitFire\\remove_list_elm', '\\BitFire\\toggle_config_value', '\\BitFire\\get_ip_data', '\\BitFire\\bot_action', '\\BitFire\\get_hr_data', '\\BitFire\\dump_hash_dir','\\BitFire\\install', '\\BitFire\\uninstall', '\\BitFire\\download', '\\BitFire\\malware_files', '\\BitFire\\load_bot_data', '\\BitFire\\replace_array_value', '\\BitFire\\general_scan', '\\BitFire\\sys_info', '\\BitFire\get_ip_info');
const BITFIRE_METRICS_INIT = array('challenge' => 0, 'broken' => 0, 'invalid' => 0, 'valid' => 0, 10000 => 0, 11000 => 0, 12000 => 0, 13000 => 0, 14000 => 0, 15000 => 0, 16000 => 0, 17000 => 0, 18000 => 0, 19000 => 0, 20000 => 0, 21000 => 0, 22000 => 0, 23000 => 0, 24000 => 0, 25000 => 0, 26000 => 0, 29000 => 0, 70000 => 0);
const LOG_SZ = 512;
const BITFIRE_VER = 4415;
const BITFIRE_SYM_VER = "4.4.15";
const APP = "https://app.bitfire.co/";
const INFO = "https://info.bitfire.co/";
const BOTS = "https://bots.bitfire.co/";
const HASH = "https://hash.bitfire.co/";

const COOKIE_VER = 1;

const ACTION_RETURN = -9999999;
const ACTION_CLEAN = -9999998;

const BITFIRE_INTERNAL_PARAM = 'BITFIRE_NONCE';
const BITFIRE_COMMAND = "BITFIRE_API";


// action,ver,_gl,hopid,_ga,el,he,?he,ical,eventdisplay,tribe-bar-date,post_type,cid,feed,gad_source,gc_id,gclid,hop,submissionguid,email,add-to-cart,fbc_id,h_ad_id,interim-login,sfid,sf_action,sf_data,_sf_s,_cache_bust,wpe-login,uniqifyingtoken,_gac,post,_bfa,creative,ad,r,__hs*,__hstc,__hssc,__hsfp,_cache_break,role,known,_hsmi,_hsenc,activate,plugin_status,paged,post_status,tab,plugin,calypso_env

const CONFIG_DASHBOARD_PATH='dashboard_path';
const CONFIG_WHITELIST_ENABLE='whitelist_enable';
const CONFIG_REQUIRE_BROWSER = 'require_full_browser';
const CONFIG_QUICK_BROWSER = 'require_quick_browser';
const CONFIG_ENCRYPT_KEY = 'encryption_key';
const CONFIG_SECRET = 'secret';
const CONFIG_VALID_DOMAIN_LIST = 'valid_domains';
const CONFIG_ENABLED = 'bitfire_enabled';
const CONFIG_WEB_FILTER_ENABLED = 'web_filter_enabled';
const CONFIG_XSS_FILTER="xss_block";
const CONFIG_SQL_FILTER="sql_block";
const CONFIG_FILE_FILTER="file_block";
const CONFIG_SPAM_FILTER="spam_filter_enabled";
const CONFIG_CACHE_TYPE = 'cache_type';
const CONFIG_LOG_FILE = 'log_file';
const CONFIG_CHECK_DOMAIN = 'check_domain';
const ERR_SQL_INJECT = "SQL Injection found";
const CONFIG_RATE_LIMIT_ACTION='rate_limit_action';
const CONFIG_BLACKLIST='blacklist';

const FAIL_NOT = 0;


const FAIL_PARAM_OVERFLOW = 50007;
const FAIL_METHOD         = 50002;
const FAIL_RR_TOO_HIGH    = 26001;


const FAIL_BLOCKED_IP     = 22003;
const FAIL_BLOCKED_AGENT  = 22004;

const FAIL_FAKE_WHITELIST = 24001;
const FAIL_MISS_WHITELIST = 24002;
const FAIL_IS_BLACKLIST   = 25001;
const FAIL_RESTRICTED     = 27001;
const FAIL_CHALLENGE      = 27002;
const FAIL_FILE_BLOCK     = 29001;
const FAIL_HTTP_BLOCK     = 33001;
const FAIL_CMS_REFERER    = 30001;

const FAIL_ENUMERATION    = 41001;
const FAIL_SSL_UPGRADE    = 42001;
const FAIL_ANSWER_VERIFY  = 43001;
const FAIL_ANSWER_MISS    = 44001;


const BLOCK_LONG   = 3;
const BLOCK_MEDIUM = 2;
const BLOCK_SHORT  = 1;
const BLOCK_NONE   = 0;
const BLOCK_WARN   = -1;

const IPDATA_RR_1M='rr_1m';
const IPDATA_RR_5M='rr_5m';



// list of custom flags: host or IP, ssl, http protocol, security headers correct, has referer, supports compression, keep alive
const AGENT_HOST     = 0b00000000001;
const AGENT_SSL      = 0b00000000010;
const AGENT_SEC      = 0b00000000100;
const AGENT_REFER    = 0b00000001000;
const AGENT_COMPRESS = 0b00000010000;
const AGENT_ALIVE    = 0b00000100000;
const AGENT_CLOSE    = 0b00001000000;
const AGENT_BOT      = 0b00010000000;
const AGENT_HTTP10   = 0b00100000000;
const AGENT_HTTP11   = 0b01000000000;
const AGENT_HTTP20   = 0b10000000000;

const METHODS = [
    "GET" => 1,
    "POST" => 2,
    "PUT" => 3,
    "OPTIONS" => 4,
    "HEAD" => 5,
    "DELETE" => 6,
    "CONNECT" => 7,
    "TRACE" => 8,
    "PATCH" => 9,
];


// cache priority
//const CACHE_STALE_OK  = 1;

const CACHE_LOW       = 1;
const CACHE_PACK      = 2;
const CACHE_IGB       = 4;
const CACHE_MSG_PAK   = 8;
const CACHE_SERIAL    = 16;
const CACHE_OVERWRITE = 32;
const CACHE_STALE_OK  = 64;
const CACHE_HIGH      = 128;

// return status
const STATUS_FAIL   = -1;
const STATUS_OK     = 0;
const STATUS_ENOENT = 2;
const STATUS_EACCES = 13;
const STATUS_EEXIST = 17;
const STATUS_ECOM   = 70;

// if we are installed in a web-accessible location, make files un-readable
const FILE_RW = 0664;
const FILE_EX = 0775;

const IP_GOOGLE       = 0b0000000001;
const IP_MICROSOFT    = 0b0000000010;
const IP_CLOUD_FLAIR  = 0b0000000100;
const IP_RESIDENTIAL  = 0b0000001000;
const IP_PROXY        = 0b0000010000;
const IP_INTERNAL     = 0b0000100000;
const IP_REAL_HEADERS = 0b0001000000;
const IP_INSPECTED    = 0b0010000000;
const IP_CLASSIFIED   = 0b0100000000;
const IP_AUTOMATTIC   = 0b1000000000;

const IP_GOOG_MS_AUTO = IP_GOOGLE | IP_MICROSOFT | IP_AUTOMATTIC;


// request classification bit-mask
const REQ_UNUSED     = 0b00000000000000001;
const REQ_VIEW       = 0b00000000000000010;
const REQ_POST       = 0b00000000000000100;
const REQ_XMLRPC     = 0b00000000000001000;
const REQ_WP_JSON    = 0b00000000000010000;
const REQ_AJAX       = 0b00000000000100000;
const REQ_DOT        = 0b00000000001000000;
const REQ_NO_PLUGIN  = 0b00000000010000000;
const REQ_LOGIN      = 0b00000000100000000;
const REQ_DIRECT_PHP = 0b00000001000000000;
const REQ_README     = 0b00000010000000000;
const REQ_UNCOMMON   = 0b00000100000000000;
const REQ_UPLOAD     = 0b00001000000000000;
const REQ_ADMIN      = 0b00010000000000000;
const REQ_RESTRICTED = 0b00100000000000000;
const REQ_USER_LIST  = 0b01000000000000000;
const REQ_UPLOAD_PHP = 0b10000000000000000;

const REQ_BLOCKED    = 0b100000000000000000;

// request classification names
const REQ_NAMES = [
'HIDDEN FILES'  => 0b0000000001000000,
'PLUGIN SCAN'=> 0b0000000010000000,
'LOGIN'      => 0b0000000100000000,
'VERSION SCAN'=> 0b0000010000000000,
'XMLRPC'     => 0b0000000000001000,
'DIRECT PHP' => 0b0000001000000000,
'UPLOAD'     => 0b0001000000000000,
'ADMIN ACCESS'=> 0b0010000000000000,
'VIEW'       => 0b0000000000000010,
'UNCOMMON'   => 0b0000100000000000,
'POST'       => 0b0000000000000100,
'WP-JSON'    => 0b0000000000010000,
'ADMIN-AJAX' => 0b0000000000100000,
'USER LIST'  => 0b1000000000000000,
'UPLOADED PHP' => 0b10000000000000000,
'BLOCKED' => 0b100000000000000000,
];

const REQ_COLOR = [
'HIDDEN FILES'  => 'warning',
'PLUGIN SCAN'   => 'danger',
'LOGIN'         => 'warning',
'VERSION SCAN'  => 'danger',
'XMLRPC'        => 'warning',
'DIRECT PHP'    => 'warning',
'UPLOADED PHP'  => 'danger',
'UPLOAD'        => 'warning',
'ADMIN ACCESS'  => 'warning',
'USER LIST'     => 'danger',
'VIEW'          => 'info',
'UNCOMMON'      => 'info',
'POST'          => 'primary',
'WP-JSON'       => 'primary',
'ADMIN-AJAX'    => 'primary',
'BLOCKED'       => 'danger',
];


const P64 = 'P';
const P32 = 'V';
const P16 = 'v';
const P8 = 'C';
const PS = 'A*';
const PA16 = 'A16';
const PA32 = 'A32';

const REQ_EVIL = REQ_DOT | REQ_NO_PLUGIN | REQ_LOGIN | REQ_README | REQ_USER_LIST;

const COMMON_WILDCARDS = ['https:*', '*javascript', '*data:text', 'hsa_*', 'utm_*', '__hs*', 'itm_*'];

const COMMON_PARAMS = [
 'p' => 1,
 'page' => 1,
 'paged' => 1,
 'q' => 1,
 's' => 1,
 'wpe-login' => 1,
 'search' => 1,
 'lang' => 1,
 'wp_lang' => 1,
 'reauth' => 1,
 'redirect_to' => 1,
 'token' => 1,
 'limit' => 1,
 'loggedout' => 1,
 'ref' => 1,
 'referer' => 1,
 'referrer' => 1,
 'timestamp' => 1,
 'id' => 1,
 'cid' => 1,
 'fbclid' => 1,
 'fbc_id' => 1,
 'lscwp_ctrl' => 1,
 'msclkid' => 1,
 'keyword' => 1,
 'cmpid' => 1,
 'h_ad_id' => 1,
 'gad_source' => 1,
 'gc_id' => 1,
 'gclid' => 1,
 '_ga' => 1,
 '_gac' => 1,
 '_gl' => 1,
 '_fields' => 1,
 'ref_src' => 1,
 'ad_id' => 1,
 'ad' => 1,
 'campaign_id' => 1,
 'nonce' => 1,
 '_wpnonce' => 1,
 'wpnonce' => 1,
 'wp-nonce' => 1,
 'utm_term' => 1,
 'wc_ajax' => 1,
 'filter_brand' => 1,
 'per_page' => 1,
 'per_row' => 1,
 'shop_view' => 1,
 'locale' => 1,
 'offset' => 1,
 'feed' => 1,
 'action' => 1,
 'ver' => 1,
 'add-to-cart' => 1,
 'product' => 1,
 'sku' => 1,
 'quantity' => 1,
 'cart' => 1,
 '_cache_break' => 1,
 'post_type' => 1
];

const COMMON_SCRIPTS = ['wp-cron.php', 'bitfire-beacon.php', 'verify.php', 'admin-ajax.php', 'load-scripts.php', 'load-styles.php', 'index.php', 'wp-login.php', 'authorize-application.php'];
const COMMON_ACTIONS = ['logout', 'heartbeat', 'lostpassword', 'generate-password', 'received', 'send', 'tick', 'as_async_request_queue_runner'];
const COMMON_APIS = ['/wp/v2/posts', '/wp/v2/pages', '/oembed/1.0/embed', '/wp/v2/categories', '/wp/v2/comments'];
const EVIL_PARAMS = ['author', 'rest_route', 'XDEBUG_SESSION_START'];

const COUNTRY = ['-','US','CN','AU','JP','TH','IN','MY','KR','SG','HK','TW','KH','PH','VN','NO','ES','FR','NL','CZ','GB','DE','AT','CH','BR','IT','GR','PL','BE','IE','DK','PT','SE','GH','TR','RU','CM','ZA','FI','AE','JO','RO','LU','AR','UG','AM','TZ','BI','UY','CL','BG','UA','EG','CA','IL','QA','MD','HR','IQ','LT','LV','EE','UZ','SK','KZ','GE','AL','PS','HU','SA','CY','MT','CR','IR','BH','MX','CO','SY','LB','AZ','ZW','ZM','OM','RS','IS','SI','MK','LI','JE','SC','BA','KG','TJ','IM','GG','GI','LY','YE','BY','YT','RE','GP','MQ','KW','LK','SZ','CD','PK','BT','BN','PM','PA','LA','GU','MP','DO','ID','VI','NG','PE','EC','VE','PR','BO','NZ','BD','PG','TL','SB','VU','FJ','CK','TO','NP','KE','MO','TT','LS','VG','KN','AG','JM','VC','KY','LC','GD','CW','BB','BS','PY','GT','UM','DM','TM','TK','MV','AF','NC','MN','WF','DZ','SM','ME','MM','AD','MC','GL','BZ','FO','MF','LR','BW','TN','MG','AO','NA','CI','SD','MU','MW','GA','ML','BJ','TD','CV','RW','CG','MZ','GM','MA','GN','BF','SO','SL','NE','CF','TG','SS','GQ','SN','AS','MR','DJ','KM','IO','NR','WS','FM','PF','HN','SV','NI','GF','NU','TV','PW','MH','KI','KP','AW','CU','HT','SR','GY','VA','ST','ET','ER','GW','FK','BM','BL','AI','TC','SX','AX','NF','BQ','PN','AQ','SH','MS','GS', 'TF', 'BF', 'SJ', 'BV'];

if (!defined('MIN_NUM_CONFIG_OPTIONS')) {
    define('MIN_NUM_CONFIG_OPTIONS', 20);
}


// 100,000 microseconds, seconds . need to know the time the blog was started....
