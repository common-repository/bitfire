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



// Sync with server bot_info
class BotInfo
{
    public $id;
    public $valid;
    public $net;
    public $abuse;
    public $domain;
    public $home_page;
    public $agent;
    public $category;
    public $icon;
    public $favicon;
    public $vendor;
    public $name; 
    public $hit = 0;
    public $miss = 0; 
    public $not_found = 0;
    public $ips;
    public $class;
    public $country;
    public $country_code;
    public $allow;
    public $allowclass;
    public $mtime;
    public $trim;
    public $machine_date;
    public $machine_date2;
    public $crawler_id; // udger code, to remove from old bot data...

    public function __construct($agent)
    {
        $this->agent = $agent;
        $this->ips = [];
    }
}


namespace BitFireSvr;

use BitFire\BitFire;
use BitFire\BotSimpleInfo;
use BitFire\Config;
use BitFire\Config as CFG;
use BitFire\ScanConfig;
use Exception;
use RuntimeException;
use SodiumException;
use ThreadFin\CacheItem;
use ThreadFin\CacheStorage;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFin\Effect;
use ThreadFin\Maybe;
use ThreadFin\MaybeI;
use ThreadFin\MaybeStr;

use const BitFire\BITFIRE_SYM_VER;
use const BitFire\BOT_ALLOW_AUTH;
use const BitFire\BOT_ALLOW_NONE;
use const BitFire\BOT_ALLOW_RESTRICT;
use const BitFire\CACHE_HIGH;
use const BitFire\COMMON_PARAMS;
use const BitFire\FILE_RW;
use const BitFire\FILE_W;
use const BitFire\INFO;
use const BitFire\STATUS_EACCES;
use const BitFire\STATUS_EEXIST;
use const BitFire\STATUS_ENOENT;
use const BitFire\STATUS_OK;
use const BitFire\STATUS_FAIL;
use const BitFire\WAF_INI;
use const BitFire\WAF_ROOT;
use const BitFire\WAF_SRC;
use const ThreadFin\DAY;
use const ThreadFin\DS;



use function BitFire\parse_agent;
use function BitFireChars\save_config2;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\do_for_each;
use function ThreadFin\file_recurse;
use function ThreadFin\file_replace;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\partial_right as ƒixr;
use function ThreadFin\random_str;
use function ThreadFin\debug;
use function ThreadFin\en_json;
use function ThreadFin\ends_with;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\HTTP\httpp;
use function ThreadFin\icontains;
use function ThreadFin\index_yield;
use function ThreadFin\ƒ_id;
use function ThreadFin\make_config_loader;
use function ThreadFin\memoize;
use function ThreadFin\recursive_copy;
use function ThreadFin\trace;
use function ThreadFin\at;
use function ThreadFin\utc_date;
use function ThreadFin\utc_time;

const ACCESS_URL = 5;
const ACCESS_CODE = 6;
const ACCESS_ADDR = 0;
const ACCESS_REFERER = 8;
const ACCESS_AGENT = 9;
const ACCESS_URL_PROTO = 2;
const ACCESS_QUERY = 10;
const ACCESS_HOST = 11;
const ACCESS_URL_METHOD = 12;
const ACCESS_URL_URI = 13;

const CONFIG_KEY_NAMES = [ "bitfire_enabled","allow_ip_block","security_headers_enabled","enforce_ssl_1year","csp_policy_enabled","csp_default","csp_policy","csp_uri","pro_key","rasp_filesystem","max_cache_age","web_filter_enabled","spam_filter_enabled","xss_block","sql_block","file_block","block_profanity","filtered_logging","allowed_methods","whitelist_enable","blacklist_enable","require_full_browser","honeypot_url","check_domain","valid_domains","valid_domains[]","ignore_bot_urls","rate_limit","rr_5m","cache_type","cookies_enabled","wordfence_emulation","report_file","block_file","debug_file","debug_header","send_errors","dashboard_usage","browser_cookie","dashboard_path","encryption_key","secret","password","cms_root","cms_content_url","cms_content_dir","debug","skip_local_bots","response_code","ip_header","dns_service","short_block_time","medium_block_time","long_block_time","cache_ini_files","root_restrict","configured","log_everything","ip_lookups","remote_tech_allow","tech_public_key","nag_ignore","verify_http_code", "block_profanity"];


// helpers
// trim off everything after $trim_char
function trim_off(string $input, string $trim_char) : string { $idx = strpos($input, $trim_char); $x = substr($input, 0, ($idx) ? $idx : strlen($input)); return $x; }

class FileHash {
    public $file_path;
    public $rel_path;
    public $size;
    public $crc_path;
    public $crc_trim;
    public $unique;
    public $crc_expected;
    public $type;
    public $name;
    public $version;
    public $ctime;
    public $skip;
    public $ver;
}



class Whois_Info {
    public string $city = "";
    public int $zip = 0;
    public string $country = "";
    public string $as = "";
    public string $org = "";
    public string $arin = "";
    public string $cidr = "";
    public string $net = "";
    public string $raw = "";
    public array $domains = [];

    public function __toString()
    {
        return (!empty($this->raw)) 
            ? $this->raw
            : "Whois_Info: $this->as $this->org $this->country $this->cidr $this->net"; 
    }
}


/**
 * @param resource $stream - stream to read
 * @param int $size - read block size
 * @return string - the entire stream as a string
 */
function read_stream($stream, $size=8192) {
    $data = "";
    if(!empty($stream)) {
        while (!feof($stream)) {
            $data .= fread($stream , $size);
        }
        fclose ($stream);
    }
    return $data;
}


/**
 * find the AS number of the remote IP
 * TODO: add remote classifier hosted on bitfire.co for difficult to classify IPs
 * @param string $remote_ip 
 * @return Whois_Info the AS number as a string or empty string
 */
function find_ip_as(string $remote_ip, bool $return_raw = false): Whois_Info
{
    static $cache = [];
    static $whois_servers = [
        'whois.ripe.net' => 'RIPE',
        'whois.arin.net' => 'ARIN',
        'whois.apnic.net' => 'APNIC',
        'whois.afrinic.net' => 'AFRINIC',
        'whois.lacnic.net' => 'LACNIC'
    ];

    // this is an expensive call, make sure we don't accidentally do it twice
    if (isset($cache[$remote_ip])) {
        return $cache[$remote_ip];
    }

    $info = new Whois_Info();

    foreach ($whois_servers as $server => $org) {
        $write_ip_fn = ƒixr('fputs', "$remote_ip\r\n");
        $x = MaybeStr::of(fsockopen($server, 43, $no, $str, 1))
            ->effect($write_ip_fn)
            ->then('\BitFireSvr\read_stream');
        $info->raw = ($return_raw) ? "" : $x;

        //  pull the as number from anywhere
        if (preg_match("/AS([0-9]+)/", $x, $matches)) {
            $info->as = $matches[1];
        }
                // city is common
        if (preg_match("/city[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->city = $matches[1];
        }
        // so is country
        if (preg_match("/country[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->country = icontains($matches[1], "world")  ? "global" : $matches[1];
        }
        // postal is sometimes in an address field
        if (preg_match("/postalcode[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->zip = $matches[1];
        }
        if (empty($info->zip) && preg_match("/address:[^:]*:.*?(\d{5})/i", $x, $matches)) {
            $info->zip = $matches[1];
        }
        // pull cidr from anywhere
        if (empty($info->cidr) && preg_match("/([0-9.:]+\/\d+)/i", $x, $matches)) {
            $info->cidr = $matches[1];
        }

        // pull the net range
        if (preg_match("/([\d.:]+\s+-\s+[\d.:]+)/i", $x, $matches)) {
            $info->net = $matches[1];
        }

        // pull the org name from likely places
        if (preg_match("/(org|descr|owner|netname)[^:]*:+\s*(.*)/i", $x, $matches)) {
            $info->org .= $matches[1] . "\n";
        }
        // pull all email addresses
        if (preg_match("/[\w_\.-]+\@(\w+\.\w+)/i", $x, $matches)) {
            $info->domains[] = $matches[1];
        }

        if (!empty($info->as) || !empty($info->org) || !empty($info->country)) {
            $info->arin = $org;
            $info->domains = array_unique($info->domains);
            $info->org = (empty($info->org)) ? join(", ", $info->domains) : $info->org;

            $cache[$remote_ip] = $info;
            return $info;
        }

        $info->org = trim($info->org);
    }

    $cache[$remote_ip] = $info;
    return $info;
}





/**
 * special handling of WordPress DOCUMENT_ROOT - requested by WP team
 */
function doc_root() : string {
    static $root = "/";
    if ($root === "/") { 
        $root = $_SERVER['DOCUMENT_ROOT'] ?: getcwd();
    }
    return $root;
}

/**
 * find the cms root path.  abstracted to cms plugin helper, config file
 * fallback to doc_root()
 * @return string 
 */
function cms_root() : string {
    trace("R1");
    $root = doc_root();
    if (function_exists("\BitFirePlugin\\find_cms_root")) {
        $root = \BitFirePlugin\find_cms_root();
    }
    else if (CFG::enabled("cms_root")) {
        $root = CFG::str("cms_root");
    }
    if (strlen($root) < strlen(doc_root())) { 
        debug("error finding doc_root [%s]", $root);
        $root = doc_root();
    }

    return realpath($root);
}


// helper function.  determines if ini value should be quoted (return false for boolean and numbers)
function need_quote(string $data) : bool {
    return ($data === "true" || $data === "false" || ctype_digit($data)) ? false : true;
}



/**
 * map $filename with $fn, return effect to write updated $filename   
 * NOTE: MAKE SURE TO RELEASE THE FILE LOCK IN $effect->read_api()[0].unlock()
 * @param callable $fn - a function to apply to every line of the ini file. should map a raw key = value line to key = new_value
 * @param string $filename the path to the ini file - can be mocked with FileData::mask_file($file_name, $content)
 * @return Effect  contains a FileMod object with the content value of the new file contents. release the file lock!
 */
function update_ini_fn(callable $fn, string $filename = "", bool $append = false) : Effect {
    if (empty($filename)) {
        $filename = (defined("\BitFire\WAF_INI")) ? \BitFire\WAF_INI : make_config_loader()->run()->read_out();
    }

    $effect = Effect::new();

    // UPDATE THE FILE
    $file = FileData::new($filename, true)->read(true);
    $x1 = count($file->lines);
    if ($append) {
        $last_line = end($file->lines);
        $newline = (empty($last_line) || ends_with($last_line, "\n")) ? "" : "\n";
        $file->append($newline . $fn());
    } else {
        $file->map($fn);
    }

    // join the edited file back up and make sure it is still parsable
    $x2 = count($file->lines);
    $raw = "";
    foreach ($file->lines as $line) {
        $raw .= $line;
        if (!ends_with($line, "\n")) { $raw .= "\n"; }
    }

    $raw = preg_replace("/^\n\n/", "\n", trim($raw));

    // parse the ini file, on error, use the sample config backup file
    $new_config = parse_ini_string($raw, false, INI_SCANNER_TYPED);

    // if the ini file was parsed successfully, write the new data
    // set status to success if the file has a reasonable size still...
    if ($new_config != false && count($new_config) >= MIN_NUM_CONFIG_OPTIONS && $x1 > 1 && $x2 >= $x1) {
        // update the file abstraction with the edit, this will allow us 
        // to update the file multiple times, and not read from the FS multiple times
        FileData::mask_file($filename, $raw);

        $ini_code = "{$filename}.php";
        $effect->status(STATUS_OK)
        ->api(true, "this is a hack to keep the file_lock from being released", [$file])
        // IMPORTANT make sure we don't output the api reference!!
        ->hide_output(true)
        // write the raw ini content
        ->file(new FileMod($filename, $raw, FILE_RW, 0, false, true))
        // write the parsed config php file
        ->file(new FileMod($ini_code, '<?'.'php $config = ' . var_export($new_config, true) . ";\n", FILE_RW, 0, false, true))
        // clear the config cache entry
        ->update(new CacheItem("parse_ini", ƒ_id(), ƒ_id(), -DAY, CACHE_HIGH));
    }

    return $effect;
}



/**
 * if $value === "!" then config line is removed
 * @param string $param ini parameter name to change
 * @param string $value the value to set the parameter to
 */
function update_ini_value(string $param, string $value, ?string $default = NULL) : Effect {
    $param = htmlspecialchars(strtolower($param));
    if (!contains($param, "csp_policy")) {
        $value = htmlspecialchars($value);
    }
    // normalize values
    switch($value) {
        case "off":
            $value = "false";
        case "alert":
            $value = "report";
        case "block":
        case "on":
            $value = "true";
        default:
    }

    $quote_value = (need_quote($value) && !contains($value, '"')) ? "\"$value\"" : "$value";
    $param_esc = str_replace(["[", "]"], ["\[", "\]"], $param);
    $search = (!empty($default)) ? "/\s*[\#\;]*\s*{$param_esc}\s*\=.*[\"']?{$default}[\"']?/" : "/\s*[\#\;]*\s*{$param_esc}\s*\=.*/";
    $replace = "$param = $quote_value";


    debug("update ini value [%s] [%s]", $search, $replace);

    if ($value === "!") { $replace = ""; }
    $fn = (ƒixl("preg_replace", $search, $replace));

    // replace the parameter
    if (icontains(FileData::new(WAF_INI)->read()->raw(), "$param")) {
        $effect = update_ini_fn($fn, WAF_INI);
    }
    // append the parameter
    else {
        $effect = update_ini_fn(ƒ_id($replace), WAF_INI, true);
    }


    // remove any old config files lying around ...
    file_recurse(get_hidden_file(''), function ($x) {
        if (contains($x, "config.ini.")) {
            unlink($x);
        }
    }, "/.*.\d{3,10}$/");


    if ($effect->read_status() == STATUS_OK) {
        debug("updated %s -> %s", $param, $value);
    } else {
        debug("config failed to update %s -> %s", $param, $value);
    }
    return $effect;
}


/**
 * if $value === "!" then config line is removed
 * @param string $param ini parameter name to change
 * @param string $value the value to set the parameter to
 */
function add_ini_value(string $param, string $value, string $comment = "") : Effect {
    #assert(in_array($param, CONFIG_KEY_NAMES), "unknown config key $param");

    $param = htmlspecialchars(strtolower($param));
    $value = htmlspecialchars(strtolower($value));
    // normalize values
    switch($value) {
        case "off":
            $value = "false";
        case "alert":
            $value = "report";
        case "block":
        case "on":
            $value = "true";
        default:
    }

    // if we already have the content, skip
    $content = file_get_contents(WAF_INI);
    if (contains($content, $param)) {
        return Effect::$NULL;
    }

    $line = "\n";
    if (!empty($comment)) {
        $line .= "; $comment\n";
    }
    // don't quote numbers
    if (is_numeric($value)) {
        $line .= "\n$param = $value\n";
    } else {
        $line .= "\n$param = \"$value\"\n";
    }

    $line = preg_replace("/^\n\n/", "\n", trim($line));

    return Effect::new()->file(new FileMod(WAF_INI, $content . $line));
}



/**
 * update all system config values from defaults
 */
function update_config(string $ini_src) : Effect
{
    // ugly af, but it works
    $configured = $GLOBALS["bitfire_update_config"]??false;
    $e = Effect::new();
    if ($configured) { debug("update config 2x skipped"); }
    $GLOBALS["bitfire_update_config"] = true;
    debug("update config");

    $ini_test = FileData::new($ini_src);
    // FILESYSTEM GUARDS
    if (! $ini_test->exists) { return $e->exit(false, STATUS_EEXIST, "$ini_src does not exist!"); }
    if (! $ini_test->readable || ! $ini_test->writeable) { 
        if (!@chmod($ini_src, FILE_RW)) {
            return $e->exit(false, STATUS_EACCES, "$ini_src permissions error!");
        }
    }

    
    $server_id = random_str(8);
    $info = $_SERVER;
    $info["action"] = "update_config";
    $info["assert"] = @ini_get("zend.assertions");
    $info["assert.exception"] = @ini_get("assert.exception");
    $info["writeable"] = true;
    $info["cookie"] = 0;
    $info["HTTP_COOKIE"] = "**redacted**";
    $info["REQUEST_URI"] = preg_replace("/nonce=[0-9a-hA-H]{8,24}/", "nonce=**redacted**", $info["REQUEST_URI"]);
    $info["QUERY_STRING"] = preg_replace("/nonce=[0-9a-hA-H]{8,24}/", "nonce=**redacted**", $info["QUERY_STRING"]);
    $info["robot"] = false;
    $info["ini"] = get_hidden_file("config.ini");
    $info['crypto'] = ['sodium1' => function_exists("sodium_crypto_sign_open"), 'sodium' => extension_loaded('sodium'), 'openssl' => extension_loaded('openssl'), 'mcrypt' => extension_loaded('mcrypt')];
    $info['server_id'] = $server_id;

    $e = update_ini_value("encryption_key", random_str(32), "default");
    $e->chain(update_ini_value("secret", random_str(32), "default"));
    $e->chain(update_ini_value("browser_cookie", "_bitf", "_bitfire"));
    $e->chain(update_ini_value("server_id", "_$server_id", "_bitfire"));
 
    // configure wordpress root path
    // TODO: move all of WordPress settings into the wordpress-plugin/bitfire-admin.php
    $root = cms_root();
    $content_path = "/wp-content"; // default fallback
    $scheme = filter_input(INPUT_SERVER, "REQUEST_SCHEME", FILTER_SANITIZE_SPECIAL_CHARS);
    $host = trim(filter_input(INPUT_SERVER, "HTTP_HOST", FILTER_SANITIZE_URL), "/");

    $content_url = "$scheme://$host/$content_path";
    if (!empty($root)) {
        $info["cms_root_path"] = $root;
        $content_dir = $root . $content_path;
        $wp_version = "";
        if (function_exists('get_bloginfo')) {
            $wp_version = get_bloginfo('version');
        }

        // defaults if loading outside WordPress (example WordPress is corrupted)
        if (function_exists("content_url")) {
            $content_url = \content_url();
        } else if (defined("WP_CONTENT_URL")) { $content_url = \WP_CONTENT_URL; }

        $e->chain(update_ini_value("cms_root", $root, ""));
        $e->chain(update_ini_value("cms_content_dir", $content_dir, ""));
        $e->chain(update_ini_value("cms_content_url", $content_url, ""));
        $e->chain(update_ini_value("wp_version", $wp_version, ""));
        $info['assets'] = $content_url;
        // we won't be using passwords since we will check WordPress admin credentials
        if (defined("WPINC")) {
            $e->chain(update_ini_value("password", "disabled"));
        }
    } else {
        $info["cms_root"] = "WordPress not found.";
    }

    // WPEngine fixes
    if (isset($_SERVER['IS_WPE'])) {
        // can only auto_load wordfence-waf due to hardcoding auto_prepend_file setting
        $e->chain(update_ini_value("wordfence_emulation", "true"));
        // WPEngine does not respect cache headers well, so we must bust with a parameter
        //$info["cache_param"] = random_str(4);
        //$e->chain(update_ini_value("cache_bust_parameter", $info["cache_param"]));
        // WPEngine prevents writing to php files, so we disable ini file cache here
        $e->chain(update_ini_value("cache_ini_files", "false"));
    }


    // configure caching
    if (function_exists('shmop_open')) {
        $e->chain(update_ini_value("cache_type", "shmop", "nop"));
        $e->chain(update_ini_value("cache_token", mt_rand(32768,1300000))); // new cache entry
        $info["cache_type"] = "shmop";
    } else if (function_exists('apcu')) {
        $e->chain(update_ini_value("cache_type", "apcu", "nop"));
        $info["cache_type"] = "apcu";
    } else {
        $e->chain(update_ini_value("cache_type", "opcache", "nop"));
        $info["cache_type"] = "opcache";
    }
    // test semaphore access
    $type = "flock";
    if (function_exists('sem_get')) {
        $sem = sem_get(0x11223344);
        if ($sem) {
            if (sem_acquire($sem, true)) {
                if (sem_release($sem)) {
                    $type = "sem";
                }
            }
            sem_remove($sem);
        }
    }
    $e->chain(update_ini_value("lock_type", $type, "flock"));


    // X forwarded for header, WPE sends the wrong header there...
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_CF_CONNECTING_IP", "REMOTE_ADDR"));
    } else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !isset($_SERVER['IS_WPE'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_X_FORWARDED_FOR", "REMOTE_ADDR"));
    } else if (isset($_SERVER['HTTP_FORWARDED'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_FORWARDED", "REMOTE_ADDR"));
    } else if (isset($_SERVER['HTTP_X_REAL_IP'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_X_REAL_IP", "REMOTE_ADDR"));
    } else {
        $info["forward"] = "no";
    }

    // are any cookies set?
    if (count($_COOKIE) > 1) {
        $info["cookies"] = count($_COOKIE);
        $e->chain(update_ini_value("cookies_enabled", "true", "false"));
    } else {
        $info["cookies"] = "not enabled.  none found. <= 1";
    }

    $host = filter_input(INPUT_SERVER, "HTTP_HOST", FILTER_SANITIZE_URL);
    $domain = at($host, ":", 0);
    $info["domain_value"] = $domain;
    $domain = join(".", array_slice(explode(".", $domain), -2));

    $e->chain(update_ini_value("valid_domains[]", $domain, "default"));

    // configure dynamic exceptions
    if (CFG::int("dynamic_exceptions") == 1) {
        // dynamic exceptions are enabled, but un-configured (true, not time).  Set for 5 days
        $e->chain(update_ini_value("dynamic_exceptions", time() + (DAY * 5), "true"));
    }

    require_once \BitFire\WAF_SRC . "bitfire.php";


    // attempt to set the title tag to the homepage title for browser verification
    $response = http2("GET", "https://" .$_SERVER['HTTP_HOST'] . "/");
    if (preg_match("/<title>([^<]*)/", $response->content, $matches)) {
        $e->chain(update_ini_value("title_tag", $matches[1]));
    }

    // use WordPress or hosted content if not WordPress
    if (function_exists("plugin_dir_url")) {
        $assets = \plugin_dir_url(dirname(__FILE__, 1)) . "public/";
    } else if (!empty($root)) {
        $assets = CFG::str("cms_content_url") . "/plugins/bitfire/public";
    } else {
        $assets = "https://bitfire.co/assets";
    }
    $info['assets'] = $assets;
    $info['version'] = BITFIRE_SYM_VER;

    debug("replacing assets (%s)", $assets);
    $z = file_replace(\BitFire\WAF_ROOT . "public/theme.bundle.css", "/url\(([a-z\.-]+)\)/", "url({$assets}$1)")->run();
    if ($z->num_errors() > 0) { debug("ERROR [%s]", en_json($z->read_errors())); }

    $e->chain(Effect::new()->file(new FileMod(get_hidden_file("install.log"), "\n".json_encode($info, JSON_PRETTY_PRINT), FILE_RW, 0, true)));
    httpp(INFO."zxf.php", base64_encode(json_encode($info)));

    return $e;
}


/**
 * parse an array of scan config strings into a ScanConfig object
 * @param array $config 
 * @return ScanConfig 
 */
function parse_scan_config(array $config) : ScanConfig {
    require_once WAF_SRC . "cms.php";
    $scan_config = new ScanConfig();
     
    foreach ($config as $line) {
        $parts = explode(":", $line);
        $key = $parts[0];
        $val = $parts[1]??0;
        $scan_config->$key = $val;
    }

    return $scan_config;
}

/** 
 * take an array of strings and convert to ini array format
 */
function array_to_ini(string $value_name, array $data) : string {
    $result = "";
    foreach ($data as $item) {
        if (is_numeric($item)) {
            $result .= "{$value_name}[] = {$item}\n";
        } else if (is_bool($item)) {
            $result .= "{$value_name}[] = " . ($item ? "true" : "false") . "\n";
        } else {
            $result .= "{$value_name}[] = \"$item\"\n";
        }
    }
    return "\n$result\n";
}



/**
 * take a config array and create the ini string
 * @param array $a 
 * @return string 
 */
function build_ini_string(array $a) : string {
    $out = '';
    $root_section = '';
    foreach($a as $root_key => $root_value){
        if(is_array($root_value)){
            // find out if the root-level item is an indexed or associative array
            $indexed_root = array_keys($root_value) == range(0, count($root_value) - 1);
            // associative arrays at the root level have a section heading
            if(!$indexed_root) $out .= PHP_EOL."[$root_key]".PHP_EOL;
            // loop through items under a section heading
            foreach($root_value as $key => $value){
                if(is_array($value)){
                    // indexed arrays under a section heading will have their key omitted
                    $indexed_item = array_keys($value) == range(0, count($value) - 1);
                    foreach($value as $sub_key=>$sub_value){
                        // omit sub key for indexed arrays
                        if($indexed_item) $sub_key = "";
                        // add this line under the section heading
                        $out .= "{$key}[$sub_key] = $sub_value" . PHP_EOL;
                    }
                }else{
                    if($indexed_root){
                        // root level indexed array becomes root_section
                        $root_section .= "{$root_key}[] = $value" . PHP_EOL;
                    }else{
                        // plain values within root level sections
                        $out .= "$key = $value" . PHP_EOL;
                    }
                }
            }

        }else{
            // root level root_section values
            $root_section .= "$root_key = $root_value" . PHP_EOL;
        }
    }
    return $root_section.$out;
}




// add firewall startup to .user.ini
// TODO: refactor with effects and FileData
function install_file(string $file, string $format): bool
{
    $d = dirname(__FILE__, 2);
    $self = realpath($d . "/startup.php");
    debug("install file: %s - [%s]", $file, $d);

    if ((file_exists($file) && is_writeable($file)) || is_writable(dirname($file))) {
        $ini_content = (!empty($format)) ? sprintf("\n#BEGIN BitFire\n{$format}\n#END BitFire\n", $self, $self) : "";
        debug("install content: (%s) [%s]", $self, $ini_content);

        // remove any previous content, capture the current content
        $c = "";
        if (file_exists($file)) {
            $c = file_get_contents($file);
            if ($c !== false) {
                if (strstr($c, "BEGIN BitFire") !== false) {
                    $c = preg_replace('/\n?\#BEGIN BitFire.*END BitFire\n?/ism', '', $c);
                }
            }
        }

        // remove old backups
        do_for_each(glob(dirname($file).'/.*.bitfire.*'), 'unlink');
        do_for_each(glob(dirname($file).'/*.bitfire.*'), 'unlink');

        // create new backup with random extension and make unreadable to prevent hackers from accessing
        if (file_exists($file) && is_readable($file)) {
            $backup_filename = "$file.bitfire_bak." . mt_rand(10000, 99999);
            if (copy($file, $backup_filename)) {
                @chmod($backup_filename, FILE_RW);
            }
        }

        $full_content = $c . $ini_content;
        if (file_put_contents($file, $full_content, LOCK_EX) == strlen($full_content)) {
            return true;
        }
    }

    return false;
}

// install always on protection (auto_prepend_file)
// TODO refactor install_file to use effects 
function install() : Effect {
    $effect = Effect::new();
    $software = filter_input(INPUT_SERVER, "SERVER_SOFTWARE", FILTER_SANITIZE_URL);
    $apache = stripos($software, "apache") !== false;

    $root = cms_root(); // prefer CMS root over doc root
    if (empty($root)) {
        $root = doc_root();
    }
    $ini = "$root/".ini_get("user_ini.filename");
    $hta = "$root/.htaccess";
    $extra = "";
    $note = "";
    $status = false;


    // if the system has not been configured, configure it now
    // AND RETURN HERE IMMEDIATELY
    if (CFG::disabled("configured")) {
        debug("install before configured?");
        $ip = filter_input(INPUT_SERVER, CFG::str_up("ip_header", "REMOTE_ADDR"), FILTER_VALIDATE_IP);
        $block_file = \BitFire\BLOCK_DIR . DS . $ip;
        $effect->chain(update_config(\BitFire\WAF_INI));
        $effect->chain(update_ini_value("configured", "true")); // MUST SYNC WITH UPDATE_CONFIG CALLS (WP)
        $effect->chain(Effect::new()->file(new FileMod(\BitFire\WAF_ROOT."install.log", "configured server settings. rare condition.",  FILE_RW, 0, true)));
        // add allow rule for this IP, if it doesn't exist
        if (!file_exists($block_file)) {
            $effect->chain(Effect::new()->file(new FileMod($block_file, "allow", FILE_RW, 0, false)));
        }
        return $effect;
    }


    // ONLY HIT HERE AFTER CONFIGURATION.
    // FOR WORDPRESS THIS IS SECOND ACTIVATION

    // force WordFence compatibility mode if running on WP ENGINE and WordFence is not installed, emulate WordFence
    // don't run this check if we are being run from the activation page (request will be null)
    if (CFG::enabled("wordfence_emulation")) {
        $cms_root = cms_root();
        $waf_load = "$cms_root/wordfence-waf.php";
        $effect->exit(false, STATUS_EEXIST, "WPEngine hosting. UNINSTALL WordFence before enabling always on.");
        // we are on wordpress, found the dir and it exists
        if (!empty($cms_root) && file_exists($cms_root)) {
            // wordfence is not installed, and the autoload file does not exist, lets inject ours
            if (!file_exists(CFG::str("cms_content_dir")."plugins/wordfence") && !file_exists($waf_load)) {
                $self = dirname(__DIR__) . "/startup.php";
                if (file_exists($self)) {
                    $effect->file(new FileMod($waf_load, "<?"."php include_once '$self'; ?>\n"))
                        ->status(STATUS_OK)
                        ->out("WPEngine hosting. WordFence WAF emulation enabled. Always on protected.");
                } else {
                    $effect->exit(false, STATUS_ENOENT, "Critical error, unable to locate BitFire startup script. Please re-install.");
                }
            }
        } else {
            $effect->exit(false, STATUS_ENOENT, "Critical error, unable to locate WordPress root directory.");
        }
    }

    // NOT WPE
    else {
        // handle NGINX and other cases
        $root_path = dirname(__DIR__) . DS;
        $content = "display_errors = \"On\"\nauto_prepend_file = \"{$root_path}startup.php\"";
        $status = (\BitFireSvr\install_file($ini, $content) ? true : false);
        $file = $ini;
        $extra = "This may take up to " . ini_get("user_ini.cache_ttl") . " seconds to take effect (cache clear time)";
        $note = ($status == "success") ?
            "BitFire was added to auto start in [$ini]. $extra" :
            "Unable to add BitFire to auto start.  check permissions on file [$file]";
    }

    $effect->chain(Effect::new()->file(new FileMod(\BitFire\WAF_ROOT."install.log", join(", ", debug(null))."\n$note\n", FILE_RW, 0, true)));
    return $effect->exit(false)->api($status, $note)->status((($status) ? STATUS_OK : STATUS_FAIL));
}


// uninstall always on protection (auto_prepend_file)
// TODO: refactor to api response
function uninstall() : Effect {
    $apache = stripos($_SERVER['SERVER_SOFTWARE'], "apache") !== false;
    $root = doc_root(); // SERVER DOCUMENT ROOT, NOT CMS ROOT!
    $ini = "$root/".ini_get("user_ini.filename");
    $hta = "$root/.htaccess";
    $extra = "";
    $effect = Effect::new();
    $status = "success";

    // remove any dangling semaphores
    if (function_exists('sem_get')) {
        $opt = (PHP_VERSION_ID >= 80000) ? true : 1;
        $sem = sem_get(CFG::int('cache_token'), 1, 0660, $opt);
        if (!empty($sem)) { sem_remove($sem); }
        $sem = sem_get(0x228AAAE7, 1, 0660, $opt);
        if (!empty($sem)) { sem_remove($sem); }
    }

    // attempt to uninstall emulated wordfence if found
    $is_wpe = isset($_SERVER['IS_WPE']);
    if (Config::enabled("wordfence_emulation") || $is_wpe) {
        $cms_root = cms_root();
        $waf_load = "$cms_root/wordfence-waf.php";
        // auto load file exists
        if (file_exists($waf_load)) {
            $c = file_get_contents($waf_load);
            // only remove it if this is a bitfire emulation
            if (stristr($c, "bitfire")) {
                $effect->unlink($waf_load);
                $method = "wordfence";
            }
        }
    }
    else {
        $file = $ini;
        $extra = "This may take up to " . ini_get("user_ini.cache_ttl") . " seconds to take effect (cache clear time)";
        $method = "user.ini";

        $status = ((\BitFireSvr\install_file($file, "")) ? "success" : "error");
        // install a lock file to prevent auto_prepend from being uninstalled for ?5 min
        $effect->file(new FileMod(\BitFire\WAF_ROOT . "uninstall_lock", "locked", 0, time() + intval(ini_get("user_ini.cache_ttl"))));
    }
    $path = realpath(\BitFire\WAF_ROOT."startup.php"); // duplicated from install_file. TODO: make this a function

    // remove all stored cache data
    CacheStorage::get_instance()->delete();

    // remove all backup config files
    do_for_each(glob("$root/.*bitfire_bak*", GLOB_NOSORT), [$effect, 'unlink']);
    do_for_each(glob("$root/*bitfire_bak*", GLOB_NOSORT), [$effect, 'unlink']);
    // remove all configuration...
    do_for_each(glob(get_hidden_file("*"), GLOB_NOSORT), [$effect, 'unlink']);
    $effect->unlink(get_hidden_file(""));

    $note = ($status == "success") ?
        "BitFire was removed from auto start. $extra" :
        "Unable to remove BitFire from auto start.  check permissions on file [$file]";
    $effect->status(($status == "success") ? STATUS_OK : STATUS_FAIL);
    $effect->out(json_encode(array('status' => $status, 'note' => $note, 'method' => $method, 'path' => $path)));


    return $effect;
}




function hash_file3(string $path, callable $type_fn, callable $ver_fn, string $root_dir = ""): ?FileHash {
    $name = "root";

    $reg = "/^.*\\".DS."wp-content\\".DS."(?:plugins|themes)\\".DS."([^\\".DS."]*)/";
    if (preg_match($reg, $path, $matches)) {
        $root_dir = $matches[0];
        $name = $matches[1]; 
    } else if (preg_match("/^.*(\\".DS."wp-(?:includes|admin))\\".DS.".*/", $path, $matches)) {
        if (empty($root_dir)) { $root_dir = cms_root(); }
        $root_dir .= $matches[1];
    }
    $hash = hash_file2($path, $root_dir, $name, $type_fn);
    if (!empty($hash)) {
        $hash->ver = $ver_fn($path);
    }
    return $hash;
}

// run the hash functions on a file
// TODO: move unique to data enrichment, not needed on server call
function hash_file2(string $path, string $root_dir, string $name, callable $type_fn): ?FileHash
{
    $root_dir = rtrim($root_dir, '/');
    // GUARDS
    $realpath = realpath($path);
    $extension = pathinfo($realpath, PATHINFO_EXTENSION);
    if (!$realpath) { return null; }
    if (is_dir($realpath)) { return null; }
    if (!is_readable($realpath)) { return null; }

    $input = join('', FileData::new($realpath)->read()->map('trim')->lines);
    // if the extension is not php, check for php code anyway...
    if ($extension != "php") { 
        if (strpos($input, "<?php") === false) { return null; }
    }

    $hash = new FileHash();
    $hash->file_path = $realpath;
    $hash->rel_path = str_replace("//", "/", str_replace($root_dir, "", $realpath));

    $hash->crc_trim = crc32($input);
    $hash->type = $type_fn($realpath);
    $hash->name = $name;
    $hash->size = filesize($realpath);
    $hash->unique = strtolower(random_str(10));
    $hash->ctime = filectime($realpath);

    // we don't even need to scan it if we are missing important functions
    /*
    $req_fn = '/(?:header|\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*|mail|fwrite|file_put_contents|create_function|call_user_func|call_user_func_array|uudecode|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru%s*)\s*\(?/mi';
    if (!preg_match($req_fn, $input)) {//} && !preg_match("/(include|require)(_once)?[^=]+?;/", $input)) {
        $hash->skip = true;
    }
    */

    // HACKS AND FIXES
    if ($hash->type != "wp_plugin") {
        if (stripos($realpath, "/wp-includes/") !== false) { $hash->rel_path = "/wp-includes".$hash->rel_path; }
        else if (stripos($realpath, "/wp-admin/") !== false) { $hash->rel_path = "/wp-admin".$hash->rel_path; }
    }

    $hash->crc_path = crc32($hash->rel_path);
    return $hash;
}




// run the hash functions on a file
function hash_file(string $filename, string $root_dir, string $plugin_id, string $plugin_name): ?array
{
    if (is_dir($filename)) {
        return null;
    }
    if (!is_readable($filename)) {
        return null;
    }
    $root_dir = rtrim($root_dir, '/');
    $filename = str_replace("//", "/", $filename);
    $i = pathinfo($filename);
    $input = @file($filename);
    if (!isset($i['extension']) || $i['extension'] !== "php" || empty($input)) {
        return null;
    }

    $shortname = str_replace($root_dir, "", $filename);
    $shortname = str_replace("//", "/", $shortname);
    if (strpos($filename, "/plugins/") !== false) {
        $shortname = '/'.str_replace("$root_dir", "", $filename);
    } else if (strpos($filename, "/themes/") !== false) {
        $shortname = '/'.str_replace("$root_dir", "", $filename);
    }


    $result = array();
    $result['crc_trim'] = crc32(join('', array_map('trim', $input)));
    $result['crc_path'] = crc32($shortname);
    $result['path'] = substr($shortname, 0, 255);
    $result['name'] = $plugin_name;
    $result['plugin_id'] = $plugin_id;
    $result['size'] = filesize($filename);

    return $result;
}


/**
 * authenticate a BitFire tech support user
 * @param string $signed_message 
 * @return MaybeStr 
 */
function authenticate_tech(string $signed_message) : MaybeI {
    try {
        $key = CFG::str("tech_public_key", "b39a09eb3095c54fd346a2f3c8a13a8f143a1b3fe26b49c286389c55cec73c3e"); 
        $tech_public_key = hex2bin($key); 
        if (function_exists('sodium_crypto_sign_open')) {
            $open = sodium_crypto_sign_open(hex2bin($signed_message), $tech_public_key);
            return MaybeStr::of($open);
        }
        return MaybeStr::of(false); 
    } catch (Exception $e) {
        return MaybeStr::of(false); 
    } 
}


/**
 * Create an effect to activate the firewall. unit-testable
 * This will set the config file to enable firewall to run
 * install auto_prepend_file into .htaccess or .user.ini (apache/nginx)
 * 
 * This is called on plugin activation AND upgrade...
 * @return Effect the effect to update ini and install auto_prepend
 */
function bf_activation_effect() : Effect {

    // ensure that cache objects directory exists!
    if (file_exists(WAF_ROOT . "data") && !file_exists(WAF_ROOT . "data" . DIRECTORY_SEPARATOR . "objects")) {
        mkdir(WAF_ROOT . "data" . DIRECTORY_SEPARATOR . "objects", 0775, true);
    }

    // if we are already configured, just return
    if (CFG::enabled("configured")) {
        return Effect::new()->status(STATUS_OK);
    }

    $effect = \BitFireSvr\update_ini_value("bitfire_enabled", "true");
    debug("configured: [%d]", CFG::enabled("configured"));

    $effect->chain(update_config(\BitFire\WAF_INI));
    // make sure we run auto configure and install auto start
    // update configured after check for install.  allows install on deactivate - activate
    $effect->chain(update_ini_value("configured", "true")); // MUST SYNC WITH UPDATE_CONFIG CALLS (WP)
    // in case of upgrade, run the config updater to add new config parameters
    //$effect->chain(\BitFireSvr\upgrade_config());


    // read the result of the auto prepend install and update the install.log
    if ($effect->read_status() == STATUS_OK) {
        $content = "\nBitFire " . BITFIRE_SYM_VER . " Activated at: " . 
            date(DATE_RFC2822) . "\n" . $effect->read_out();
    } else {
        $errstr = function_exists("posix_strerror") ? posix_strerror($effect->read_status()) : " (can't convert errno: to string) ";
        $content = "\nBitFire " . BITFIRE_SYM_VER . " Activation FAILED at: " . 
            date(DATE_RFC2822) . "\nError Code: " . $effect->read_status() . " : " .
            "$errstr\n" . $effect->read_out() . "\n";
    }
    $effect->file(new FileMod(\BitFire\WAF_ROOT."install.log", $content, 0, 0, true));

    return $effect;
}

/**
 * Create an effect to deactivate the firewall. unit-testable
 * turn off the global firewall enable flag and uninstall the auto_prepend_file 
 * @return Effect the effect to update ini and un-install auto_prepend
 */
function bf_deactivation_effect() : Effect {
    // turn off the global run flag
    $effect = \BitFireSvr\update_ini_value("bitfire_enabled", "false");
    // uninstall auto_prepend_file from .htaccess and/or user.ini
    $effect->chain(\BitFireSvr\uninstall());

    if ($effect->read_status() == STATUS_OK) {
        $content = "\nWordPress plugin De-activated at: " . 
            date(DATE_RFC2822) . "\n" . $effect->read_out();
    } else {
        $errstr = function_exists("posix_strerror") ? posix_strerror($effect->read_status()) : " (can't convert errno to string) ";
        $content = "\nWordPress plugin deactivation FAILED at: " . 
            date(DATE_RFC2822) . "\nError Code: " . $effect->read_status() . " : " .
            "$errstr\n" . $effect->read_out() . "\n";
    }
    $effect->file(new FileMod(\BitFire\WAF_ROOT."install.log", $content, 0, 0, true));

    return $effect;
}



function core_download() {
    $ip_list = ['ipaa', 'ipab', 'ipac', 'ipad', 'ipae', 'ipaf', 'ipag', 'ipah', 'ipai', 'ipaj', 'ipak', 'ipal'];

    $d = dirname(get_hidden_file(""));
    if (!is_writeable($d)) {
        return;
    }

    echo "<h1>Downloading core IP Database...\nPlease wait 1 minute...\n</h1>";
    flush();
    $wrote = -2;
    array_map(function ($x) use ($wrote) {
        $temp = get_hidden_file($x.".bin");
        $sz = 0;
        if (file_exists($temp)) {
            $sz = filesize($temp);
            // if the file size is correct, or was modified in the last 3 minutes (may be still downloading...)
            if (in_array($sz, [2097152, 2026288]) || filemtime($temp) > (time() - (60*3))) {
                return;
            }
        }
        $result = http2("GET", "https://bitfire.co/{$x}?sz=$sz&wrote=$wrote");
        $wrote = file_put_contents($temp, $result->content, LOCK_EX);
    }, $ip_list);

    $out_file = get_hidden_file("ip.bin");
    if (!file_exists($out_file) || filesize($out_file) !== 25094960) {
        $handle = fopen($out_file, 'w+');
        if ($handle) {
            ftruncate($handle, 0);
            rewind($handle);
            fclose($handle);
        }


        array_map(function ($x) use ($out_file) {
            $f = get_hidden_file($x.".bin");
            file_put_contents($out_file, file_get_contents($f), FILE_APPEND | LOCK_EX);
        }, $ip_list);

        // clean up old temp files
        if (filesize($out_file) > 24000000) {
            $dir = get_hidden_file("");
            $files = glob($dir . "/ipa*.bin");
            array_walk($files, function($x) { unlink($x); });
        }
    }

    if (!file_exists(WAF_ROOT . "data/city.bin")) {
        $result = http2("GET", "https://bitfire.co/city.bin");
        file_put_contents(WAF_ROOT . "data/city.bin", $result->content, LOCK_EX);
    }
}


function convert_bot_file(string $file_base) {
    $old_path = $file_base.'.json';
    $new_path = $file_base.'.js';
    $file = FileData::new($old_path);
    if ($file->exists) {
        $orig_time = $file->mtime();
        /** @var BotSimpleInfo $data */
        $data = unserialize($file->raw());
        if ($data->valid) {
            //don't allow bots that are restricted
            if ($data->manual_mode != BOT_ALLOW_NONE) {
                $data->manual_mode = BOT_ALLOW_AUTH;
            }
        } else if ($data->manual_mode != BOT_ALLOW_NONE) {
            // restrict bots that haven't accessed in 7 days
            if ($orig_time < time() - (DAY * 7)) {
                $data->manual_mode = BOT_ALLOW_RESTRICT;
            }
            // allow bots that are not abusive and have accessed in the last 7 days
            else {
                $score = (is_object($data->abuse)) ? $data->abuse->score : $data->abuse;
                if (is_int($score) && $score < 20) {
                    $data->manual_mode = BOT_ALLOW_AUTH;
                } else {
                    $data->manual_mode = BOT_ALLOW_RESTRICT;
                }
            }
        }
        // configure un-configured bots...
        if ($data->manual_mode == 0) {
            $data->manual_mode = BOT_ALLOW_RESTRICT;
        }
        $output = json_encode($data, JSON_PRETTY_PRINT);
        file_put_contents($new_path, $output, LOCK_EX);
        touch($new_path, $orig_time);
        rename($old_path, "$old_path.bak");
    }
}


function upgrade($upgrade=null, $extra=null) {

    $dir = get_hidden_file("bots");
    $files = glob("$dir/.json");
    foreach ($files as $file) {
        $parts = explode(".", $file);
        array_pop($parts);
        convert_bot_file(join(".", $parts));
    }

    // clear the cache!
    $cache = CacheStorage::get_instance();
    $cache->delete();

    // make sure we have a unique cache token. this will clear the cache if hit
    if (CFG::int("cache_token") == 4455661) {
        update_ini_value("cache_token", mt_rand(32768,1300000))->run();
    }

    // enable auto-learning for 3 days after upgrade to 4.3.3
    // XXX TODO: need to diff the versions and only enable if upgrading from 4.3.2 or earlier
    if (BITFIRE_SYM_VER >= "4.3.3") {
        update_ini_value("dynamic_exceptions", (time() + (DAY*3)))->run();
    }

    if (!isset(CFG::$_options['ok_apis'])) {
        add_ini_value("ok_apis", "", "list of anonymous allowed wp-json endpoints")->run(); 
    }
    if (!isset(CFG::$_options['ok_scripts'])) {
        add_ini_value("ok_scripts", "", "list of anonymous allowed scripts")->run(); 
    }
    if (!isset(CFG::$_options['ok_actions'])) {
        add_ini_value("ok_actions", "", "list of anonymous allowed ajax actions ")->run(); 
    }
    if (!isset(CFG::$_options['ok_params'])) {
        add_ini_value("ok_params", "", "list of anonymous allowed get parameters ")->run(); 
    }
    if (!isset(CFG::$_options['self_ip'])) {
        add_ini_value("self_ip", "", "my own ip address")->run(); 
    }
    if (!isset(CFG::$_options['rest_auth'])) {
        add_ini_value("rest_auth", false, "require user auth for rest api")->run(); 
    }
    if (!isset(CFG::$_options['server_id'])) {
        add_ini_value("server_id", random_str(8), "create a unique server id")->run(); 
    }
    if (!isset(CFG::$_options['rasp_auth'])) {
        add_ini_value("rasp_auth", "false", "rasp user authentication")->run(); 
    }
    if (!isset(CFG::$_options['cor_policy'])) {
        add_ini_value("cor_policy", "same-site", "cross origin resource sharing")->run(); 
    }
    if (!isset(CFG::$_options['csp_enable_time'])) {
        add_ini_value("csp_enable_time", "0", "pro feature to learn the csp policy")->run(); 
    }
    if (!isset(CFG::$_options['permission_policy'])) {
        add_ini_value("permission_policy", "false", "simple permission policy block geo,camera,mic,payment apis")->run(); 
    }
    if (!isset(CFG::$_options['high_sensitivity'])) {
        add_ini_value("high_sensitivity", "false", "default block unknown bots")->run(); 
    }
    if (!isset(CFG::$_options['block_scrapers'])) {
        add_ini_value("block_scrapers", "false", "also block web scrapers")->run();
    }
    if (!isset(CFG::$_options['verify_css'])) {
        add_ini_value("verify_css", "spinner", "verification page type")->run();
    }
    if (!isset(CFG::$_options['verify_http_code'])) {
        add_ini_value("verify_http_code", "428", "http code for verification page")->run();
    }
    if (!isset(CFG::$_options['lock_type'])) {
        add_ini_value("lock_type", "flock", "lock type")->run();
    }
    if (isset(CFG::$_options['log_everything'])) {
        return;
    }


    $d = ["action" => "upgrade", "server" => $_SERVER['SERVER_NAME'], "ip" => $_SERVER['SERVER_ADDR']];
    httpp(INFO."zxf.php", base64_encode(json_encode($d)));

    $bot_dir = get_hidden_file("bots");
    $bot_list = glob($bot_dir . "/*.js*");

    add_ini_value("log_everything", true, "log all requests, not just blocked requests")->run();
    add_ini_value("ip_lookups", 0, "number of IP lookups performed")->run();
    add_ini_value("remote_tech_allow", true, "allow bitfire to fix bitfire configuration remotely")->run();
    add_ini_value("nag_ignore", true, "disable nag notices")->run();
    add_ini_value("verify_http_code", 303, "browser verification code")->run();
    update_ini_value("block_profanity", false, "block profanity in requests")->run();
    update_ini_value("tech_public_key", "b39a09eb3095c54fd346a2f3c8a13a8f143a1b3fe26b49c286389c55cec73c3e")->run();

    file_put_contents(dirname(WAF_INI)."/browser_allow.json", "{\n'ip': {},\n'ua': {}\n }", LOCK_EX);

    // convert old format bots to BotSimpleInfo
    // TODO: after updating, should also convert to new .js format
    foreach ($bot_list as $file) {
        if (ends_with($file, ".json")) {
        }
        $bot_info = unserialize(file_get_contents($file));

        $agent = parse_agent($bot_info->agent);
        if (!$agent->bot) {
            unlink($file);
            continue;
        }


        $last_time = filemtime($file);
        if ($bot_info->valid && !$bot_info instanceof BotSimpleInfo) {

            $simple = new BotSimpleInfo($bot_info->agent);
            $simple->domain = $bot_info->domain??"";
            $simple->net = $bot_info->net??"";
            $simple->vendor = $bot_info->vendor??"";
            $simple->category = $bot_info->category??"";
            $simple->hit = $bot_info->hit??0;
            $simple->miss = $bot_info->miss??0;
            $simple->not_found = $bot_info->not_found??0;
            $simple->valid = $bot_info->valid??0;
            $simple->home_page = $bot_info->home_page??"";
            $simple->class = $bot_info->class??"";
            $simple->class_id = (int)$bot_info->class_id??0;
            $simple->ips = $bot_info->ips??[];
            $simple->category = strip_tags($bot_info->category);
            $simple->name = $bot_info->name??"upgrade error, please remove";
            $simple->mtime = $bot_info->mtime??time();
            $simple->ctime = $simple->mtime;
            $simple->manual_mode = BOT_ALLOW_AUTH;
            $simple->agent = $bot_info->agent??"";
            $simple->agent_trim = $agent->trim??"";
            $simple->icon = $bot_info->icon??"";
            $simple->favicon = $bot_info->favicon??"";
            $simple->crc32 = crc32($agent->trim);


            file_put_contents($file, serialize($simple), LOCK_EX);
            touch($file, $last_time);
        } else {
            unlink($file);
        }
    }

    // restore the old configurations
    // nothing to do on upgrade now...
    /*
    $old_config = CFG::str("cms_content_dir") . "/bitfire/config.ini";
    if (file_exists($old_config)) {
        @chmod(WAF_INI, FILE_RW);
        rename($old_config, WAF_INI);
    }
    $restore_list = glob(CFG::str("cms_content_dir") . "/bitfire/*");
    if (count($restore_list) > 0) {
        array_walk($restore_list, function($x) {
            $n = basename($x);
            chmod(WAF_ROOT."data/$n", FILE_RW);
            rename($x, WAF_ROOT."data/$x");
        });
    }
    $dir_name = CFG::str("cms_content_dir") . "/bitfire";
    if (count($dir_name) > 0) {
        if (file_exists($dir_name)) {
            @chmod($dir_name, FILE_RW);
            @rmdir($dir_name);
        }
    }
    */
}


/**
 * update the common parameters list in the config file.
 * TODO: clean up hidden params directory (older than 7 days)
 * @param array $get - the get parameters
 * @param string $ip - the remote ip
 * @return bool - true if any unknown parameters were found 
 */
function update_common_params(array $get, string $ip, bool $learning_mode = false) : bool {

    // ignore all known parameters...
    //$ok = explode(',', Config::str('ok_params'));
    //$unknown_params = array_diff(array_keys($get), $ok, COMMON_PARAMS, EVIL_PARAMS);
    $params = Config::str('ok_params');
    $user_params = array_fill_keys(explode(',', $params), 1);
    $known_params = array_merge($user_params, COMMON_PARAMS);
    $unknown_params = array_filter($get, ƒixr('\BitFire\remove_junk_parameters', $known_params), ARRAY_FILTER_USE_BOTH);


    // this should be the common case
    if (empty($unknown_params)) {
        return false;
    }

    // learning mode we take everything from verified humans and add it to the ok_params list
    if ($learning_mode) {
        $keys = array_keys($unknown_params);
        $list = join(',', $keys);
        update_ini_value("ok_params", str_replace(',,', ',', "$params,$list"))->run();
        return false;
    }

    // create the  params directory if it does not exist
    $dir = get_hidden_file("params");
    if (!file_exists($dir)) {
        mkdir($dir);
    }

    $unknown = true;
    // inspect unknown parameters
    foreach (array_keys($unknown_params) as $param) {
        // only inspect "clean" parameters (this is the internet)
        $clean = preg_replace("/[^a-z0-9_-]/i", "_", $param);
        if ($clean != $param) { $unknown = true; continue; }

        $file_name = "$dir/$clean";
        $file = FileData::new($file_name);

        // read each file line trimming newlines
        $lines = $file->read(false)->lines;

        // if we last saw this parameter more than 7 days ago, delete it. it is unknown
        $m = $file->mtime();
        $now = time();
        if ($m > 0 && $m < ($now - (DAY * 8))) {
            unlink($file_name);
            continue;
        }

        if (!in_array(trim($ip), $lines)) {
            // add the new ip
            $lines[] = trim($ip);

            // we have seen this parameter at least 5 times before, add it to the ok_params list
            if (count($lines) > 5) {
                update_ini_value("ok_params", $params . ",$param")->run();
                // don't need to keep this file around
                $unknown = false;
                unlink($file_name);
            }
            // save this parameter name if we see it again..
            else {
                file_put_contents($file_name, join("\n", $lines), LOCK_EX);
            }
        }
    }

    return $unknown;
}


namespace BitFireChars;

use BitFire\Config;
use Exception;
use FFI;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;

use function ThreadFin\get_hidden_file;
use function ThreadFin\icontains;

const LOWER = 0.04;
const UPPER = 0.96;
const RISKY_FN = ['base64_decode', 'uudecode', 'hebrev', 'hex2bin', 'str_rot13', 'eval', 'proc_open', 'pcntl_exec', 'exec', 'shell_exec', 'call_user_func', 'call_user_func_array', 'system', 'passthru', 'shell_exec', 'move_uploaded_file', 'stream_wrapper_'];


/**
 * create the initial frequency array
 * @return array 
 */
function init_frequency() : array {
    for ($i = 0; $i < 128; $i++) {
        $freq[$i] = [];
    }
    return $freq;
}

/**
 * take the total frequency counts and turn it into final count
 * @param array $frequency 
 * @return array 
 */
function finalize_frequency(array $frequency) : array {
    $final = [];
    foreach ($frequency as $index => $list) {
        $num = count($list);
        // skip characters that don't appear enough
        if ($num < 10) { continue; }

        // find the lower and upper boundaries
        sort($list);
        $lower = round((LOWER * $num), 0);
        $upper = round((UPPER * $num), 0);
        $l_min = max(0, $lower - 1);
        $l_up = max(0, $upper - 1);
        $l = (floor($lower) == $lower) ? $list[$l_min] : ($list[$l_min] + $list[$lower+1])/2;
        $u = (floor($upper) == $upper) ? $list[$l_up] : ($list[$l_up] + $list[$upper+1])/2;
        $final[$index] = ["lower" => $l, "upper" => $u];
    }
    return $final;
}

/**
 * calculate character frequency for a single file if it is risky
 * @param string $path - assumes $path exists
 * @param bool $final
 * @return null|array 
 */
function update_freq(string $path) : ?array {
    static $file_map = [];
    assert(file_exists($path), "can't update character frequency if the file doesn't exist: $path");

    $content = file_get_contents($path);
    // skip the file if it doesn't contain any of the risky functions, or dynamic functions
    if (! icontains($content, RISKY_FN)) {
        if (!preg_match("/\$[a-zA-Z0-9_]+\s*\(/", $content)) {
            return null;
        }
    }

    // ignore paths we have looked at before
    $file_name = dirname($path) . "/" . basename($path);
    if (isset($file_map[$file_name])) { return null; }

    $file_map[$file_name] = true;

    return find_freq($content, false);
}


/**
 * calculate character frequency on single file
 * @param string $content - the file content to inspect
 * @param bool $final - flag to return the final frequency
 * @return null|array 
 */
function find_freq(string $content, bool $final = false) : ?array {
    static $global_frequency = null;
    if ($global_frequency === null) {
        $global_frequency = init_frequency();
    }
    if ($final) { return $global_frequency; }

    $frequency = count_chars($content, 1);
    $semi = $frequency[59]??0;
    $lines = $frequency[10]??1;
    //$opens = $frequency[40]??0;
    //$concat = $frequency[46]??0;
    // skip short files
    if ($semi < 10) {
        return null;
    }

    foreach ($frequency as $index => $count) {
        // skip bells and other control characters
        if ($index < 5) { continue; }
        // count ascii characters, and their frequency vs lines
        if ($index <= 127) {
            $global_frequency[$index][] = $count;
            $global_frequency[$index+128][] = round(($count/$lines), 4);
        }
    }

    return null;
}


/**
 * fix a broken config file, save as much of the original config as possible
 * @param string $config_file 
 * @return array 
 * @throws Exception 
 */
function save_config2(string $config_file) : array {
    $orig = FileData::new(get_hidden_file("config-sample.ini"))->read();
    $file = FileData::new($config_file)->read();
    $data = [];
    $file->map(function ($line) use (&$data, $orig) {
        $parse = @parse_ini_string($line, false, INI_SCANNER_TYPED);
        if (is_array($parse)) {
            foreach ($parse as $key => $value) {
                if (is_array($value)) {
                    $data[$key] = array_merge($data[$key]??[], $value);
                } else {
                    $data[$key] = $value;
                }
            }
            return $line;
        } else {
            $parts = explode('=', $line);
            $key = trim(current($parts));
            $value = trim(end($parts));
            $check = $key;
            // if we are looking at an array section, use the string value as the "key"
            if (!empty($value) && strstr($key, "[") !== false) {
                $check = $value;
            }
            $lines = array_filter($orig->lines, function ($x) use ($check) {
                $r = icontains($x, $check);
                return $r;
            });


            if (count($lines) == 1) {
                $return = current($lines) . "\n";
                $data[$key] = $return;
            } else {
                $return = "$key = false\n";
                $data[$key] = false;
            }
            return $return;
        }
    });

    Effect::new()->file(new FileMod($config_file, $file->raw() . "\n", 0, 0, false))->run();
    return $data;
}


/** trivial log rotator */
function rotate_logs(string $log_file = 'weblog.bin') {

    $info = pathinfo($log_file);
    $file = $info['filename'];
    $ext = $info['extension'];
    $f = get_hidden_file("$file.32.$ext");
    if (file_exists($f)) {
        unlink($f);
    }
    for ($i = 32; $i > 0; $i--) {
        $file1 = get_hidden_file("$file.$i.$ext");

        if (file_exists($file1)) {
            $b = $i+1;
            $file2 = get_hidden_file("$file.$b.$ext");
            rename($file1, $file2);
        }
    }
    rename(get_hidden_file("$file.$ext"), get_hidden_file("$file.1.$ext"));
}

