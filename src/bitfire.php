<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * main firewall.  holds core data references.
 */

namespace BitFire;

use BitFire\Config as CFG;
use ThreadFin\CacheItem;
use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\Maybe;
use ThreadFin\MaybeBlock;

use const BitFire\Data\HEADER_BOOK;
use const BitFire\Data\HEADER_KEYS;
use const ThreadFin\DAY;
use const ThreadFin\HOUR;

use function BitFire\Data\ua_compress;
use function BitFireBot\is_google_or_bing;
use function BitFireBot\send_browser_verification;
use function BitFireChars\rotate_logs;
use function BitFireHeader\block_plugin_enumeration;
use function BitFireSvr\authenticate_tech;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\en_json;
use function ThreadFin\random_str;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\httpp;
use function ThreadFin\ƒ_id;
use function ThreadFin\ƒ_map_inc;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\partial_right as ƒixr;
use function ThreadFin\ƒ_inc;
use function ThreadFin\partial_right;
use function ThreadFin\poly_strlen;
use function ThreadFin\un_json;

require_once \BitFire\WAF_ROOT."src/bitfire_pure.php";
require_once \BitFire\WAF_ROOT."src/const.php";
require_once \BitFire\WAF_ROOT."src/util.php";
require_once \BitFire\WAF_ROOT."src/http.php";
require_once \BitFire\WAF_ROOT."src/storage.php";
require_once \BitFire\WAF_ROOT."src/botfilter.php";
require_once \BitFire\WAF_ROOT."src/data_util.php";
/* Ƒ */


/**
 * http request abstraction
 * @package BitFire
 */
class Request
{
    public $host;
    public $path;
    public $ip;
    public $method;
    public $port;
    public $scheme;
    public $referer;

    public $get = [];
    public $get_freq = [];
    public $post;
    public $post_len;
    public $post_raw;
    public $get_raw;
    public $post_freq = array();
    public $cookies;

    public $agent;
    public $files;

    public $classification;
    public $ip_classification;

    public function __toString() {
        return "{$this->method} {$this->scheme}://{$this->host}{$this->path}";
    }
}




class Block {

    public $code;
    public $parameter;
    public $value;
    public $pattern;
    public $block_time; // set to -1 for warning, 0 = block this request, 1 = short, 2 = medium 3 = long
    public $skip_reporting = false;
    public $uuid;

    public function __construct(int $code, string $parameter, string $value, string $pattern, int $block_time = 0) {
        $this->code = $code;
        $this->parameter = $parameter;
        $this->value = $value;
        $this->pattern = $pattern;
        $this->block_time = $block_time;
        $this->uuid = dechex(mt_rand(1, 16000000));// strtoupper(random_str(8));
    }
    
    public function __toString() : string {
        $class = intval(floor($this->code/1000)*1000);
        return \BitFire\FEATURE_NAMES[$class]??"Unclassified:{$this->code}";
    }
}

class Exception {
    public $code;
    public $parameter;
    public $url;
    public $host;
    public $uuid;
    public $date;

    public function __construct(int $code = 0, string $uuid = 'x', ?string $parameter = NULL, ?string $url = NULL, ?string $host = NULL) {
        $url = (!empty($url)) ? trim($url, '/') : $url;
        $this->code = $code;
        $this->parameter = $parameter;
        $this->url = (empty($url)) ? null : $url;
        $this->host = $host;
        $this->uuid = $uuid;
    }
}


class Config {
    public static $_options = null;
    private static $_nonce = null;

    public static function nonce() : string {
        if (self::$_nonce == null) {
            self::$_nonce = str_replace(array('-','+','/'), "", random_str(10));
        }
        return self::$_nonce;
    }

    // set the full list of configuration options
    public static function set(array $options) : void {
        if (empty($options)) {
            trace("no cfg");
            CacheStorage::get_instance()->save_data("parse_ini", null, -86400); 
        } else {
            trace("cfg");
            Config::$_options = $options;
        }
    }

    // execute $fn if option enabled
    public static function if_en(string $option_name, $fn) {
        if (Config::$_options[$option_name]??false) { $fn(); }
    }

    // set a single value
    public static function set_value(string $option_name, $value) {
        Config::$_options[$option_name] = $value;
    }

    // return true if value is set to true or "block"
    public static function is_block(string $name) : bool {
        $value = self::$_options[$name]??'';
        return ($value === 'block' || $value == true) ? true : false;
    }

    // return true if value is set to "report" or "alert"
    public static function is_report(string $name) : bool {
        $value = self::$_options[$name]??'';
        return ($value === 'report' || $value === 'alert') ? true : false;
    }

    // get a string value with a default
    public static function str(string $name, string $default = '') : string {
        if ($name == "auto_start") { // UGLY HACK for settings.html
            $ini = ini_get("auto_prepend_file");
            $found = false;
            if (!empty($ini)) {
                if ($_SERVER['IS_WPE']??false || CFG::enabled("emulate_wordfence")) {
                    $file = CFG::str("cms_root")."/wordfence-waf.php";
                    if (file_exists($file)) {
                        $s = @stat($file); // cant read this file on WPE, check the size
                        $found = ($s['size']??9999 < 256);
                    }
                }
                else if (contains($ini, "bitfire")) { $found = true; }
            }
            return ($found) ? "on" : "";
        }

        return (string) (isset(Config::$_options[$name])) ? Config::$_options[$name] : $default;
    }

    public static function str_up(string $name, string $default = '') : string {
        return strtoupper(Config::str($name, $default));
    }

    // get an integer value with a default
    public static function int(string $name, int $default = 0) : int {
        $o = Config::$_options[$name]??$default;
        return intval($o);
    }

    public static function arr(string $name, array $default = array()) : array {
        return (isset(Config::$_options[$name]) && is_array(Config::$_options[$name])) ? Config::$_options[$name] : $default;
    }

    public static function enabled(string $name, bool $default = false) : bool {
        if (!isset(self::$_options[$name]) || empty(self::$_options[$name])) {
            return $default;
        }
        $value = self::$_options[$name]??$default;
        if ($value === "block" || $value === "report" || $value == true) { return true; }
        return (bool)$value;
    }

    public static function disabled(string $name, bool $default = false) : bool {
        return !Config::enabled($name, $default);
    }

    public static function file(string $name) : string {
        if (!isset(Config::$_options[$name])) { return ''; }
        if (Config::$_options[$name][0] === '/') { return (string)Config::$_options[$name]; }
        return \BitFire\WAF_ROOT . (string)Config::$_options[$name];
    }

    public static function is_pro(int $level) : bool {
        static $level = -1;
        if ($level < 0) {
            $l = strlen(self::$_options['pro_key']);
            $level = ($l > 48) ? 1 : $level;
            $level = ($l == 32) ? 2 : $level;
        }

        return $level >= $level;
    }
}


/**
 * NOT PURE.  depends on: SERVER['PHP_AUTH_PW'], Config['password']
 */
function verify_admin_password() : Effect {

    // ensure that the server configuration is complete...
    if (! CFG::enabled("configured")) { \BitFireSVR\bf_activation_effect()->run(); }
    $effect = Effect::new();
    // disable caching for auth pages
    // $effect->response_code(CFG::int('verify_http_code'));

    // run the initial password setup if the password is not configured
    // if (CFG::str("password") == "configure") { return $effect; }

    // allow 
    $tech_key = $_COOKIE['_bitfire_tech']??"";
    if (CFG::enabled("bitfire_tech_allow", true) && !empty($tech_key)) {

        if (authenticate_tech($tech_key)->compare("allow")) {
            $GLOBALS['bitfire_tech'] = true;
            return $effect;
        } 
    }

    $raw_pw = $_SERVER["PHP_AUTH_PW"]??'';
    // read any recovery passwords
    $password = CFG::str("password");
    $files = glob(CFG::str("cms_root")."/bitfire.recovery.*");
    foreach ($files as $file) {
        if (filemtime($file) < time() - 3600) {
            unlink($file);
        } else {
            // set the password and unlock the config file
            $password = trim(file_get_contents($file));
            @chmod(WAF_INI, FILE_RW);
        }
    }

    
    // prefer plugin authentication first
    if (is_admin()) {
        return $effect;
    }

    // if we don't have a password, or the password does not match
    // or the password function is disabled
    // create an effect to force authentication and exit
    if (strlen($raw_pw) < 2 ||
        $password == "disabled" ||
        (hash("sha3-256", $raw_pw) !== $password) &&
        (hash("sha3-256", $raw_pw) !== hash("sha3-256", $password))) {

        $effect->header("WWW-Authenticate", 'Basic realm="BitFire", charset="UTF-8"');
        $effect->response_code(401);
        $effect->exit(true);
    }

    return $effect;
}

/** accepts a response code (such as wordpress header_status filter)
 *  returns the passed in user code, or the LAST passed in code if $code == 0 */
function status_code($code = 0) : int {
    static $last_code = 0;

    
    // handle case for wordpress doing weird stuff
    if (function_exists("is_404")) {
        global $wp_query;
        if (isset($wp_query)) {
            if (is_404()) { return 404; }
        }
    }
    if ($code === 0) { 
        if ($last_code === 0) {
            return http_response_code();
        }
    } else {
        $last_code = $code;
    }
    return $last_code;
}




/**
 * make sure the text is ascii for logging 
 * @param string $text 
 * @param int $max_len 
 * @return string 
 */
function fix_text(string $text, int $max_len) : string {

    if (function_exists('mb_convert_encoding')) {
        $x = mb_convert_encoding($text, 'ASCII', 'UTF-8');
    } else {
         // Replace non-ASCII characters with "?"
        $x = preg_replace('/[^\x20-\x7E]/', '?', $text);
    }

    return substr($x, 0, $max_len);
}



/**
 * write report data after script execution 
 */
function log_it($in_block_code = 0, string $in_pattern = '', string $in_value = '') {
    // bail out early if these conditions are not met
    static $block_code = 0;
    static $pattern = '';
    static $value = '';

    if ($in_block_code > 0) {
        $block_code = $in_block_code;
        $pattern = $in_pattern;
        $value = $in_value;
        return;
    }

    static $done = false;
    $ins         = BitFire::get_instance();
    $cache       = CacheStorage::get_instance();
    $agent       = $ins->agent;
    $ip_data     = $ins->ip_data;

    if ($done == true || $block_code == 0 && $ins->inspected == false) {
        return;
    }
    trace("LOG:$block_code:".$ins->_request->classification.":".$ip_data->valid);

    $done        = true;
    $http_code   = status_code();

    // skip noisy agents
    if (in_array($agent, CFG::arr('ignore_agents', []))) {
        debug("IGN:A");
        return;
    }

    // don't log heart beats..
    if (isset($ins->_request->post['action']) && $ins->_request->path === '/wp-admin/admin-ajax.php') {
        $action = $ins->_request->post['action'];
        if ($action === 'heartbeat') {
            trace("HB");
            return;
        }
    }
    // don't log cron
    if (ends_with($ins->_request->path, 'wp-cron.php')) {
        trace("CRON");
        return;
    }


    $update_fn = ƒixr('\BitFire\update_ip_data', $http_code, $agent->crc32, $block_code, $ins->_request->classification);

    // ip_data updated in the last 3 seconds, make sure to lock it...
    $priority = ((count($_COOKIE) > 4) ? CACHE_HIGH : CACHE_LOW) | CACHE_STALE_OK;
    if ($ip_data->update_time >= time() - 3) {
        $cache->update_data("IP_{$ins->_request->ip}", 
            $update_fn, ƒ_id($ip_data),
            HOUR, $priority);
    } else {
        // quick no locking update
        $cache->save_data("IP_{$ins->_request->ip}", $update_fn($ins->ip_data), HOUR, $priority);
    }


    // don't log everything if not configured
    if (!CFG::enabled("log_everything") && $block_code == 0) {
        return;
    }
    // ugly tech mode hack
    if (isset($GLOBALS['bitfire_tech']) && $http_code == 200) {
        return;
    }


    $country_map = array_flip(COUNTRY);
    $country_id = 256 + intval($country_map[$ip_data->iso]??0);
    // weird error on PHP 8.2.23 on this line:  trace("LOC-{$ip_data->iso}");

    // blocking key (function-ize this)
    $key = "";
    if ($block_code > 0) {
        $key = "block";
        $clazz = intval($block_code / 1000);
        if (in_array($clazz, [25, 23, 24])) {
            $key = "bot_rasp";
        }
        if (in_array($clazz, [29, 32, 33, 34])) {
            $key = "rasp";
        }
    }


    $inc = 0;
    if ($block_code == FAIL_RESTRICTED) {
        $inc = 128;
        if (contains($_SERVER['REQUEST_URI'], ["xmlrpc.php", "wp-login.php"])) {
            $inc = 129;
        } else if (contains($_SERVER['REQUEST_URI'], "admin-ajax.php")) {
            $inc = 130;
        } else if (contains($_SERVER['REQUEST_URI'], ["readme.txt", ".css"])) {
            $inc = 131;
        } else {
            $ext = pathinfo($_SERVER['REQUEST_URI'], PATHINFO_EXTENSION);
            if (contains($ext, ['env','txt','old','save','yml','ini','s3cfg','sql','git','json','sh','bak','backup','xml','tmp','inc~','log','key'])) {
                $inc = 132;
            }
        }
    }

    if (!empty($key)) {

        $key_id = $clazz + $inc;
        // update blocking counters
        $cache->update_data("STAT_$key_id", ƒ_inc(1), ƒ_id(0), 86400*14, CACHE_HIGH);
        // update location counters for top 24 countries
        $cache->update_data("STAT_$country_id", ƒ_inc(1), ƒ_id(0), 86400*14, CACHE_HIGH);
    }

    $method = \BitFire\METHODS[$_SERVER['REQUEST_METHOD']??"GET"]??0;
    $time = time();



    $r = fix_text($ins->_request->referer??"", 64);
    $e = fix_text($ins->reason??"" . ",$pattern,$value", 64);
    $url = fix_text($_SERVER['REQUEST_URI'], 192);
    $ua = ua_compress(fix_text($agent->agent_text, 192));

    $used = strlen($r) + strlen($e);
    $ua_len = strlen($ua);
    $url_len = strlen($url);
    $available = LOG_SZ - 91;

    // if we cant fit the UA and URL in available space, get as much url as possible
    // and at least 64 bytes of compressed UA
    if (($used + $ua_len + $url_len) > $available) {
        $ua_len = max(64, $available - $url_len);
        $url_len = $available - $ua_len;
    }

    $str1 = substr($ua, 0, $ua_len) . chr(0) . substr($url, 0, $url_len) . chr(0) . $r . chr(0) . $e . chr(0);
    $flags = 0;
    $flags |= isset($_SERVER['HTTP_HOST']) ? AGENT_HOST : 0;
    $flags |= ($_SERVER['HTTPS']??'' == 'on') ? AGENT_SSL : 0;
    $flags |= (strlen($_SERVER['HTTP_REFERER']??'') > 4) ? AGENT_REFER : 0;
    $flags |= (contains($_SERVER['HTTP_ACCEPT_ENCODING']??'', 'gzip')) ? AGENT_COMPRESS : 0;
    $flags |= (contains($_SERVER['HTTP_CONNECTION']??'', 'alive')) ? AGENT_ALIVE : 0;
    $flags |= (contains($_SERVER['HTTP_CONNECTION']??'', 'close')) ? AGENT_CLOSE : 0;
    $flags |= ($agent->bot) ? AGENT_BOT : 0;
    $flags |= ($_SERVER['SERVER_PROTOCOL']??'' === "HTTP/1.0") ? AGENT_HTTP10 : 0; 
    $flags |= ($_SERVER['SERVER_PROTOCOL']??'' === "HTTP/1.1") ? AGENT_HTTP11 : 0; 
    $flags |= ($_SERVER['SERVER_PROTOCOL']??'' === "HTTP/2.0") ? AGENT_HTTP20 : 0; 

    $str_len = $ua_len + $url_len + $used + 91 + 8;
    // pad to 512 bytes
    $pad_len = 512 - $str_len;
    if ($pad_len > 0) {
        $str1 .= str_repeat(chr(0x41), $pad_len);
    }

    /* DEPRECATED!
    $audit_line = pack('CCPA16SSSSCLLSSA*', $is_bot, $valid, $agent->fingerprint,
        inet_pton($ins->_request->ip), $ins->ip_data->ctr_404??0, $ins->ip_data->rr??0,
        $http_code, $block_code, $method, $post_sz, $time, $ins->_request->classification, $ins->output_len??0, $str1);
    */

    // list of custom flags: host or IP, ssl, http protocol, security headers correct, has referer, supports compression, keep alive
    // custom flags
    // validation
    // fingerprint
    // signature
    // IP
    // ctr_404
    // rr ----

    // resp_code
    // block_code
    // method
    // post_sz
    // resp_sz
    // time
    // classification

    // net_id
    // abuse
    // manual_mode
    // ip classification

    // ----
    // request dict
    // 32 - mime types

    // 2+1+4+24+16+2+2   +2+2+1+4+4+4+4    +2+1+1+2+1+12 + 297

    $pack_format = 
    P16 . P8 . P64 . 'A24' . PA16 . P16 . P16 .
    P16 . P16 . P8 . P32 . P32 . P32 . P32 .
    P16 . P8 . P8 . P16 . P8 . 'A12' . PS;

    $audit_line = pack($pack_format, $flags, $agent->valid, $agent->fingerprint,
        $agent->signature, inet_pton($ins->_request->ip), $ip_data->ctr_404??0,
        $ip_data->rr??1, $http_code, $block_code, $method,
        $ins->_request->post_len, $ins->output_len??0, $time, $ins->_request->classification,
        0, $country_id, 0, 0, 0, '', $str1);


    $weblog_file = get_hidden_file('weblog.bin');
    $wrote = file_put_contents($weblog_file, $audit_line, FILE_APPEND | LOCK_EX);
    // make sure that we always write exactly 512 bytes
    while($wrote < 512) {
        $wrote += file_put_contents($weblog_file, str_repeat(chr(0x41), 512 - $wrote), FILE_APPEND | LOCK_EX);
    }


    /*
    if (mt_rand(1,100) == 50) {
        $sz = filesize($weblog_file);
        if ($sz > LOG_SZ * 16000) {
            require_once WAF_ROOT."src/server.php";
            rotate_logs();
        }
    }
    */

}


/**
 * load the local data for the remote IP
 */
function get_server_ip_data(string $remote_addr, UserAgent $agent): IPData {
    $ip_key = "IP_$remote_addr";
    $x = CacheStorage::get_instance()->load_data($ip_key, null, '\BitFire\IPData');

    if (empty($x)) {
        $x = new_ip_data($remote_addr, $agent);
    }
    return $x;
}




/**
 * 
 */
class BitFire
{
    // passed from blocked.php and botfilter missing js cleanup code
    protected bool $locked = false;

    public $ms_time;
    public $reason = "";
    public $output_len = -1;

    protected static $block_code;

    public ?UserAgent $agent = NULL;
    public ?IPData $ip_data = NULL;


    public $inspected = false;
    public static $_exceptions = NULL;
    /** @var BrowserState $cookie */
    public $cookie = NULL;

    public $_request = null;

    /** @var BitFire $_instance */
    protected static $_instance = null;
    public static $has_instance = false;

    /** @var BotFilter $bot_filter */
    public $bot_filter = null;

    /**
     * WAF is a singleton
     * @return BitFire the bitfire singleton;
     */
    public static function get_instance() {
        if (BitFire::$_instance == null) {

            if (empty(ini_get("date.timezone"))) {
                date_default_timezone_set("UTC");
            }
            BitFire::$_instance = new BitFire();
            self::$has_instance = true;


            // bit of an ugly hack to filter out hacking tools earlier
            if (BitFire::$_instance->agent->inspect) {
                static $blacklist = null;
                if ($blacklist == null) {
                    $blacklist = file(\BitFire\WAF_ROOT . 'data/bad-agent.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                }
                $agent = BitFire::$_instance->agent;


                foreach ($blacklist as $check) {
                    if (strpos($agent->agent_text, $check) !== false) {
                        $agent->browser_name = $check;
                        $code = FAIL_IS_BLACKLIST;
                        BitFire::$_instance->reason = "Hacking tool detected";
                        log_it($code, $check, $agent->agent_text);

                        $browser = $agent->agent_text;
                        $custom_err = $type = "hacking tool";
                        $uuid = dechex(mt_rand(1, 16000000));
                        $block = [];
                        include_once WAF_ROOT . 'views/block.php';
                        die();
                    }
                }
            }

        }
        return BitFire::$_instance;
    }

    /**
     * Create a new instance of the BitFire
     */
    protected function __construct() {

        // filter out all request data for parsed use
        $this->_request = process_request2($_GET, $_POST, $_SERVER, $_COOKIE);
        $this->agent = parse_agent($this->_request->agent, $_SERVER['HTTP_ACCEPT_ENCODING']??'*', true);
        if (function_exists("apache_request_headers")) {
            $server_headers = apache_request_headers();
            $this->agent->fingerprint = parse_header_info(HEADER_KEYS, $server_headers);
            $this->agent->signature = parse_header_values(HEADER_BOOK, $server_headers);
        }

        // Read the current client state
        // $this->cookie = BrowserState::from_cookie($_COOKIE['_bitf']??'', $this->_request->ip, $this->agent);
        $this->cookie = new BrowserState();

        $this->ip_data = get_server_ip_data($this->_request->ip, $this->agent);
        $this->_request->classification = classify_request($this->_request, intval($this->ip_data->valid)); // intval in case ->valid is bool
        $this->agent->valid = $this->ip_data->valid;

        // handle a common case urls we never care about
        if (in_array($this->_request->path, CFG::arr("urls_not_found"))) {
            http_response_code(404);
            die();
        }
    }
    
    public function __wakeup() {
        trigger_error("POP chaining not allowed", E_USER_ERROR);
    }

    public function shutdown() {
        $this->output_len = ob_get_length();
    }

    /**
     * handle API calls.
     */
    
    /**
     * append an exception to the list of exceptions
     */
    public function add_exception(Exception $exception) {
        self::$_exceptions[] = $exception;
    }

    /**
     * create a new block, returns a maybe of a block, empty if there is an exception for it
     */
    public static function new_block(int $code, string $parameter, string $value, string $pattern, int $block_time = 0, ?Request $req = null) : MaybeBlock {
        if ($code === FAIL_NOT) { return Maybe::$FALSE; }
        self::$block_code = $code;
        if ($req == null) {
            trace("DEF_REQ");
            $req = BitFire::get_instance()->_request;
        }
        trace("BL:[$code]");


        $block = new Block($code, $parameter, substr($value, 0, 2048), $pattern, $block_time);
        self::$_exceptions = (self::$_exceptions === NULL) ? load_exceptions() : self::$_exceptions;
        $filtered_block = filter_block_exceptions($block, self::$_exceptions, $req);

        // log to a file of exceptions...
        if ($filtered_block->empty()) {
            // don't let the file grow > 2MB
            $file = get_hidden_file("block.json");
            if (file_exists($file) && filesize($file) > 1024*1024*3) {
                @unlink($file);
            }
            file_put_contents($file, en_json([$block, debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS)]).",\n", LOCK_EX | FILE_APPEND);
        }

        return $filtered_block;
    }
    

    


    /*
     * inspect a request and block failed requests
     * return false if inspection failed...
     */
    public function inspect() : void {

        // don't inspect anything...
        if (! CFG::enabled('bitfire_enabled') && !isset($this->_request->get[BITFIRE_COMMAND])) {
            return;
        }

        // never double inspect
        if ($this->inspected) {
            return;
        }


        // if limited traffic mode is enabled, randomize the ip modulo 100
        // only allow traffic if the modulo is less than the traffic_percent
        $traffic_percent = CFG::int("traffic_percent", 100);
        if ($traffic_percent < 100) {
            $hash = crc32($this->_request->ip);
            if (($hash % 100) >= $traffic_percent) {
                $this->reason = "Traffic Skipped";
                trace("traffic");
                return;
            }
        }

        // install the filesystem rasp...
        if (!$this->locked && cfg::enabled('rasp_filesystem') && function_exists('BitFirePRO\site_lock')) {
            $this->locked = true;
            // we don't want to check the FS for admins, (or authenticated bots?)
            // TODO: add bot config item to allow some bots (mostly backup bots) to
            // access the filesystem
            if (! is_admin() ) {
                if ($this->_request->path != '/wp-cron.php') {
                    \BitFirePRO\site_lock();
                }
            }
        }

        // handle urls that this site does not want to inspect
        if (in_array($this->_request->path, CFG::arr("urls_ignored"))) {
            $this->reason = "URL Ignored";
            return;
        }

        $this->inspected = true;
        trace("ins");

        // make sure that the default empty block is actually empty, hard code here because this data is MUTABLE for performance *sigh*
        // TODO: remove this!
        Maybe::$FALSE = MaybeBlock::of(NULL);

        // don't inspect local commands, this will skip command line access in case we are running via auto_prepend
        if (!isset($_SERVER['REQUEST_URI'])) {
            trace("local");
            $this->reason = "No URL found";
            return;
        }



        //dbg($this->_request, "COMMAND?");
        // if we have an api command and not running in WP, execute it. we are done!
        if ((isset($this->_request->get[BITFIRE_COMMAND]) || isset($this->_request->post[BITFIRE_COMMAND])) && !isset($this->_request->get['plugin'])) {
            require_once WAF_SRC."api.php";
            $this->reason = "BitFire API";
            $e = api_call($this->_request);
            $e->run();
        }


        // QUICK BAIL OUT IF DISABLED
        if (!Config::enabled(CONFIG_ENABLED)) {
            trace("DISABLE");
            $this->reason = "BitFire Disabled";
            return;
        }

 
        $this->bot_filter = new BotFilter();
        // bot filtering
        $this->agent = $this->bot_filter->inspect($this->_request, $this->agent);
         

        // if we are not running inside of Wordpress, then we need to load the page here.
        // if running inside of WordPress, bitfire-admin.php will load the admin pages, so
        // the check for admin.php will fail here in that case
        $no_slash_fn = partial_right('trim', '/');
        $dash_path = contains($no_slash_fn($this->_request->path), ['bitfire/startup.php', $no_slash_fn(CFG::str("dashboard_path"))]);
        if ($dash_path && (
            !isset($this->_request->get['BITFIRE_PAGE']) && 
            !isset($this->_request->get['BITFIRE_API']))) {
                $this->_request->get['BITFIRE_PAGE'] = 'DASHBOARD';
        }

        // serve a dashboard page...
        if (isset($this->_request->get['BITFIRE_PAGE'])) {
            require_once \BitFire\WAF_SRC."dashboard.php";

            $this->reason = "BitFire Dashboard Page";
            $p = strtoupper($this->_request->get['BITFIRE_PAGE']);
            if ($p === "MALWARESCAN") {
                serve_malware();
            }
            else if ($p === "SETTINGS") {
                serve_settings();
            }
            else if ($p === "ADVANCED") {
                serve_advanced();
            }
            else if ($p === "EXCEPTIONS") {
                serve_exceptions();
            }
            else if ($p === "DATABASE") {
                serve_database();
            }
            else if ($p === "BOTLIST") {
                serve_bot_list();
            }
            else {
                serve_dashboard();
            }
            exit;
        }

        // quick approx stats occasionally
        // TODO: simplify this, we can spare some cycles here, less code, more data
        $f = \BitFire\WAF_ROOT."/data/ip.8.txt";
        if (random_int(1, 100) == 81 && file_exists($f)) {
            $n=un_json(file_get_contents($f));
            $t = time();
            if (intval($n['t']??0) < $t) {
                $n['h']=$this->_request->host;
                $cache = CacheStorage::get_instance();

                for ($i=0; $i < 768; $i++) {
                    $stat = intval($cache->load_data("STAT_$i", -1));
                    if ($stat > 0) {
                        $n["stat_$i"]  = $stat;
                        $cache->save_data("STAT_$i", 0, 86400*14);
                    }
                }
                $n['c']=0;
                // set the time for next midnight
                $n['t']=(floor(time() / 86400) * 86400) + 86400;
                unset($n['host']);

                require_once WAF_ROOT."src/server.php";
                rotate_logs();
            }
            $n['c']++;
            file_put_contents($f, en_json($n), LOCK_EX);
        }

        // send headers first
        if (file_exists(WAF_SRC . "headers.php")) {
            require_once \BitFire\WAF_SRC."headers.php";
            \BitFireHeader\send_security_headers($this->_request,  $this->agent)->run();
        }
       
        // always return consistent results for wordpress scanner blocks regardless of bot type
        // we want to fool scanners to think nginx/apache sent this response ...
        if (CFG::enabled("wp_block_scanners") && !is_admin()) {
            require_once \BitFire\WAF_SRC."headers.php";
            $effect = block_plugin_enumeration($this->_request);
            $effect->run();
        }

        // firewall filtering
        if (Config::enabled('xss_block') || Config::enabled('sql_block') || Config::enabled('file_block') || Config::enabled('web_filter_enabled')) {
            require_once \BitFire\WAF_SRC.'webfilter.php';
            $web_filter = new \BitFire\WebFilter();
            $web_filter->inspect($this->_request, $this->cookie);
        }
    }

    public function blocked($ms_time, $code, $reason) {
        $this->ms_time = $ms_time;
        if (empty($this->reason)) {
            $this->reason = $reason;
        }
        status_code($code);
    }
}

/**
 * called to handle some internal setup
 * @return void 
 */
function bitfire_init() {
    if (strlen(CFG::str('pro_key')) > 20) {
        if (file_exists(\BitFire\WAF_SRC . 'pro.php')) {
            @include_once \BitFire\WAF_SRC . 'pro.php';
        }
    }
}

/**
 * create  an effect that will render the block page
 * @param int $code the unique code for this line of code
 * @param string $parameter the parameter name where the issue was detected
 * @param string $value  the value of the detected parameter
 * @param string $pattern  the pattern that was matched
 * @param int $block_time one of BLOCK_SHORT, BLOCK_MEDIUM, BLOCK_LONG
 * @param null|Request $req the offending request
 * @return Effect 
 */
function block_now(int $code, string $parameter, string $value, string $pattern, int $block_time = 0, ?Request $req = null, ?string $custom_err = null) : Effect {

    $block = BitFire::new_block($code, $parameter, $value, $pattern, $block_time, $req);
    if (!$block->empty()) {
        
        // always allow wordpress, google and bing. this call is already cached, so its cheap
        if (!empty($req) && is_google_or_bing($req->ip)) {
            return Effect::$NULL;
        }

        if (php_sapi_name() != "cli") { 
            log_it($code, $pattern, $value);
        }

        $ins = BitFire::get_instance();
        $ins->reason = "Request blocked " . $block();

        // restricted actions get redirected back to the homepage, don't show the block page
        if ($code == FAIL_RESTRICTED) {
            $verification = send_browser_verification($ins->_request, $ins->agent, true, false);
            return (!defined('\BitFire\DOCUMENT_WRAP')) ? Effect::$NULL : $verification;
        }

        // double check the allow list here
        $allow_data = FileData::new(get_hidden_file("browser_allow.json"))->read()->un_json();
        if (empty($req)) { $req = BitFire::get_instance()->_request; }
        $ip_action = $allow_data->lines['ip'][$req->ip??""]??-1;
        $a = $req->agent??"";
        $agent_action = $allow_data->lines['ua'][$a]??-1;
        if ($ip_action > 0 || $agent_action > 0) {
            return Effect::$NULL;
        }
        

        $clazz = code_class($code); 
        if ($clazz == 32000) {
            $clazz = 0;
        }

        $uuid = $block()->uuid;
        $block_type = htmlentities((string)$block());

        if (defined("\BitFire\DOCUMENT_WRAP")) {
            $effect = Effect::new()->out("")->status(99)->exit(true);
            if (empty($custom_err)) { $custom_err = "This site is protected by BitFire RASP. <br> Your action: <strong> $block_type</strong> was blocked."; }  
            require WAF_ROOT."views/block.php";
        } else {
            $effect = Effect::$NULL;
        }
        return $effect;
    }
    return Effect::$NULL;
}

/**
 * @OVERRIDE the default authentication function
 * @since 1.9.0
 */ 
function is_admin() : bool {
    static $is_admin = null;
    if ($is_admin !== null) {
        return $is_admin;
    }
    if (function_exists('wp_get_current_user')) {
        $user = wp_get_current_user();
        if ( in_array( 'administrator', (array) $user->roles ) ) {
            $is_admin = true;
            return $is_admin;
        }
    }
    
    return false;
}

