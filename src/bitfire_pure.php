<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * helper methods for the BitFire, each method in this file should be pure
 */
namespace BitFire;
use Exception;
use BitFire\Config as CFG;
use ThreadFin\MaybeBlock;
use ThreadFin\Effect as Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;

use const ThreadFin\HOUR;
use const BitFire\Data\HEADER_BOOK;

use function BitFireSvr\update_ini_value;
use function ThreadFin\cidr_match;
use function ThreadFin\contains;
use function ThreadFin\cookie;
use function ThreadFin\dbg;
use function ThreadFin\map_map_value;
use function ThreadFin\partial_right as ƒixr;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\random_str;
use function ThreadFin\set_if_empty;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\get_hidden_file;
use function ThreadFin\icontains;
use function ThreadFin\at;
use function ThreadFin\ends_with_any;
use function ThreadFin\starts_with;
use function ThreadFin\trace;
use function ThreadFin\find;


/**
 * TEST
 * block code to return code class
 * @param int $code 
 * @return int 
 */
function code_class(int $code) : int {
    assert(!empty($code), "empty code in code_class");
    assert($code < 100000, "invalid code class >10000");
    assert($code > 0, "invalid code class <1");
    return intval(floor($code / 1000) * 1000);
}


/**
 * TEST
 * map array exception data to an BitFire\Exception object
 * @param array $raw 
 * @return Exception 
 */
function map_exception(array $raw) : \BitFire\Exception {
    return new \BitFire\Exception($raw['code']??0, $raw['uuid']??'none', $raw['parameter']??null, $raw['url']??null, $raw['host']??null);
}



/**
 * TEST
 * returns $block if it doesn't match the block exception
 */
function match_block_exception(?Block $block, \BitFire\Exception $exception, string $host, string $url) : ?Block {

    if ($block == NULL) { return NULL; }
    if (!empty($exception->parameter) && $block->parameter !== $exception->parameter) { return $block; }
    // make sure that every non default parameter matches
    if (!empty($exception->host) && $host !== $exception->host) { return $block; }
    if (!empty($exception->url) && $url !== $exception->url) { return $block; }
    if (!empty($exception->code)) {
        $ex_class = code_class($exception->code);
        $bl_class = code_class($block->code);
        // handle entire blocking class
        if ($ex_class === $bl_class) { return NULL; } 
        // handle specific code class
        if ($block->code !== $exception->code) { return $block; }
    }
    debug("filtered block exception - code: [%d] param [%s], uuid [%s]", $exception->code, $exception->parameter, $exception->uuid);
    return NULL;
}


/**
 * load exceptions from disk, map to object
 * @return array of \BitFire\Exception
 */
function load_exceptions() : array {

    $file = get_hidden_file("exceptions.json");
    return FileData::new($file)->read()->un_json()->map('\BitFire\map_exception')();
}


/**
 * TEST
 * @param \BitFire\Exception $ex1 
 * @param \Bitfire\Exception $ex2 
 * @return true if both exceptions match 
 */
function match_exception(\BitFire\Exception $ex1, \BitFire\Exception $ex2) : bool {
    if (!empty($ex1->code) && $ex1->code != $ex2->code) { return false; }
    if (!empty($ex1->host) && $ex1->host != $ex2->host) { return false; }
    if (!empty($ex1->parameter) && $ex1->parameter != $ex2->parameter) { return false; }
    if (!empty($ex1->url) && $ex1->url != $ex2->url) { return false; }
    return true;
}

/**
 * remove an exception from the list
 */
function remove_exception(\BitFire\Exception $ex) : Effect {
    $filename = get_hidden_file("exceptions.json");
    $exceptions = array_filter(load_exceptions(), function(\BitFire\Exception $test) use ($ex) { return ($ex->uuid === $test->uuid) ? false : true; }); 
    $effect = Effect::new(new FileMod($filename, json_encode($exceptions, JSON_PRETTY_PRINT), FILE_RW));
    return $effect;
}

/**
 * add exception to list.  returns a list containing not more than one exception matching $ex in the array
 * TEST
 * @param Exception $ex 
 * @param array $exceptions 
 * @return array 
 */
function add_exception_to_list(\BitFire\Exception $ex, array $exceptions = []) : array {
    $ex = set_if_empty($ex, "uuid", random_str(8));
    $match_exception_fn = ƒixr("\BitFire\match_exception", $ex);
    // exception is not in the list
    if (!find($exceptions, $match_exception_fn)) {
        $ex->date_utc = date(DATE_RFC3339);
        $exceptions[] = $ex;
    }
    return $exceptions;
}



/**
 * returns a maybe of the block if no exception exists
 */
function filter_block_exceptions(Block $block, array $exceptions, \BitFire\Request $request) : MaybeBlock {
    $r = (array_reduce($exceptions, ƒixr('\BitFire\match_block_exception', $request->host, $request->path), $block));

    return MaybeBlock::of($r);
}

/**
 * take a $_SERVER array and map it to a Request object
 * TEST
 * @param array $server 
 * @return Request 
 */
function process_server2(array $server) : Request {
    $url = parse_url($server['REQUEST_URI'] ?? '/');
    $request = new Request();
    $request->ip = process_ip($server);
    $request->host = parse_host_header($server['HTTP_HOST'] ?? '');
    $request->agent = strtolower($server['HTTP_USER_AGENT'] ?? '');
    $request->path = ($url['path'] ?? '/');
    $request->method = ($server['REQUEST_METHOD'] ?? 'GET');
    $request->port = intval($server['SERVER_PORT'] ?? 8080);
    $request->scheme = ($server['HTTP_X_FORWARDED_PROTO'] ?? $server['REQUEST_SCHEME'] ?? 'http');
    if (empty($request->scheme)) {
        $request->scheme = 'http';
    }
    $request->referer = $server['HTTP_REFERER'] ?? '';
    return $request;
}


/**
 * PURE TEST
 * only return the cf_connecting ip if the remote_addr is a cloud flair ip
 * TODO: pull this weekly from bitfire.co and replace with cidr check
 * @param array $server - $_SERVER
 * @param string $default - default if CF_CONNECTING_IP is not set 
 * @return bool 
 */
function check_cloud_flair(array $server, string $default = '127.0.0.1') : string {

    $remote_addr = $server['REMOTE_ADDR']??'';
    $cf_origin_list = is_ipv6($remote_addr) ? 
        ['2400:cb00', '2606:4700', '2803:f800', '2405:b500', '2405:8100', '2a06:98c0', '2c0f:f248'] :
        ['173.245.48', '103.21.24', '103.22.20', '103.31.4', '141.101.6', '108.162.19', '190.93.24', '188.114.9', '197.234.24', '198.41.12', '162.15', '104.1', '104.2', '172.6', '131.0.7'];

    // if the origin is a cloud flair ip, then we can trust the header
    foreach ($cf_origin_list as $cf_ip) {
        if (starts_with($remote_addr, $cf_ip)) {
            return $server['HTTP_CF_CONNECTING_IP']??$default;
        }
    }

    return $default;
}

/**
 * search for possible proxy addresses if $default is not valid, 
 * or server addr and $default are the same network
 * @param array $server - $_SERVER
 * @param string $default - ip from selected configuration option
 * @return string - the proxy ip header value, or $default
 */
function check_proxies(array $server, string $default) : string {
    $headers = [
        'HTTP_X_FORWARDED_FOR' => 'BitFire\get_ip',
        'HTTP_FORWARDED' => 'BitFire\get_fwd_for',
        'HTTP_X_REAL_IP' => 'BitFire\get_ip',
        'REMOTE_ADDR' => 'ThreadFin\ƒ_id'];
    foreach ($headers as $header => $fn) {
        if (isset($server[$header])) {
            $check_ip = $fn($server[$header]);
            if (filter_var($check_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                return $check_ip;
            }
        }
    }

    $self_ip = $server['SERVER_ADDR']??'127.0.0.1';
    // bail early if we have a good remote ip!
    if (!cidr_match($default, $self_ip, 24) && 
        filter_var($default, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            return $default;
    }


    return $default;
}


/**
 * TEST
 * find the correct remote ip address from PHP $_SERVER array, auto detect cloud flair IPS and headers
 * will not auto detect cloud flair headers if not from a cloudflare ip v4 or v6 address. if the resolved
 * ip is the local server, or a private ip, then we will look for a better header
 * @param array $server 
 * @return string 
 */
function process_ip(array $server) : string {
    $header_name = Config::str_up('ip_header', 'REMOTE_ADDR');
    if (!isset($server[$header_name])) {
        $header_name = 'REMOTE_ADDR';
    }
    $remote_ip = get_ip($server[$header_name] ?? '::1');

    // pull from proxies if we found one and remote_addr looks fake...
    $remote_ip = check_proxies($server, $remote_ip);

    // pull CF ip if we found one (always use this, since people will switch without updating the config)
    if (isset($server['HTTP_CF_CONNECTING_IP'])) {
        $remote_ip = check_cloud_flair($server, $remote_ip);
    }

    return $remote_ip;
}


/**
 * TEST
 * count character frequency
 * @param array $inputs 
 * @return array 
 */
function freq_map(array $inputs) : array {
    $r = array();
    foreach($inputs as $key => $value) {
        if (is_string($value)) {
            $r[$key] = get_counts($value);
            continue;
        }
        else if (is_array($value)) {
            $r[$key] = array_reduce($value, '\\BitFire\\get_counts_reduce', []);
            continue;
        } 
        // probably an int, so we wont have any counts...
        $r[$key] = [];
    }
    return $r;
}

/**
 * return a bit mask of browser header order
 * @param array $headers - order of headers to check. max 16
 * @param array $server_headers - the $_SERVER headers
 * @return int of mask data, first byte is the HEADER mask, remaining 8 bytes are ordered masks of HEADER_ORDER_KEYS 
 */
function parse_header_info(array $headers, array $server_headers = []) : int {
    $order = $ctr = 0;
    foreach ($headers as $token => $header_num) {
        if (isset( $server_headers[$token] )) {
            $order += $header_num << ($ctr++*4);
        }
    }

    return $order;
}

function parse_header_values(array $book, array $server) : string {

    // count cookies...
    $count = count($_COOKIE??[]);
    if ($count === 0) {
        $count = substr_count($server['Cookie']??'', ';');
    }
    $print = ($count < 10) ? "0$count" : $count;
    
    // only inspect HTTP_ headers, but not custom ones..
    foreach ($server as $key => $header) {
        // skip headers that have no values we check for, don't unset 
        if ($key == 'Cookie' || $key == 'User-Agent' || $key == 'Host') {
            continue;
        }

        $parts = preg_split('/[ ,;]/', $header);
        foreach ($parts as $check) {
            if (isset($book[$check])) {
                $print .= $book[$check];
            }
        }
    }

    return $print;
}



/**
 * convert a GET, POST, SERVER array into a single Request object
 * @param array $get 
 * @param array $post 
 * @param array $server 
 * @param array $cookies 
 * @return Request 
 */
function process_request2(array $get, array $post, array $server, array $cookies = []) : Request {

    $request = process_server2($server);
    $request->get_raw = $server['QUERY_STRING'] ?? '';
    $request->get = map_map_value(array_filter($get, fn($x) => !empty($x) ), '\\BitFire\\each_input_param');
    $request->post = map_map_value($post, '\\BitFire\\each_input_param');
    $request->cookies = map_map_value($cookies, '\\BitFire\\each_input_param');
    $request->get_freq = freq_map($request->get);
    $request->post_len = intval($server['CONTENT_LENGTH'] ?? 0);
    $request->host = $server['HTTP_HOST']??'localhost';
    if ($server['REQUEST_METHOD']??'' === 'POST') {
        $request->post_raw = file_get_contents('php://input');
        // handle json encoded post data
        $t = $server['CONTENT_TYPE']??'';
        if ($t == 'application/json' && !empty($request->post_raw)) {
            $len = strlen($request->post_raw);
            $x = json_decode($request->post_raw, true);
            if (is_array($x)) {
                $request->post = array_merge($request->post, $x);
            }
            else {
                parse_str($request->post_raw, $tmp);
                if (!empty($tmp)) {
                    $request->post = map_map_value($tmp, '\\BitFire\\each_input_param');
                } else {
                    trace('CT:AJER');
                    debug('JSON/PARSE ERR (%d) [%s]', $len, substr($request->post_raw, 0, 2048));
                }
            }
        }
        $request->post_freq = freq_map($request->post);
    } else {
        $request->post_raw = 'N/A';
        $request->post_freq = [];
        $request->post = [];
    }


    return $request;
}

function remove_junk_parameters(string $value, string $parameter_name, array $user_params, array $wild_cards = []) : bool {

    // handle common and empty parameters
    $name_lower = strtolower($parameter_name);
    $known      = isset($user_params[$name_lower]) || empty($value) || isset(COMMON_PARAMS[$name_lower]);
    if ($known) {
        return false;
    }

    // ignore empty parameters and single character parameters
    if (empty($value) || strlen($value) == 1) {
        return false;
    }

    foreach ($wild_cards as $filter) {
        $pos = strpos($filter, '*');
        $check = ($pos === 0) ? substr($filter, $pos+1) : substr($filter, 0, $pos);
        if (strpos($name_lower, $check) !== false) {
            return false;
        }
    }

    return true;
}


function classify_request(Request $request, int $verified) : int {

    $class = 0;
    // file names to check for
    $name_map = [
        'readme.txt'     => REQ_README,
        'settings.py'    => REQ_EVIL | REQ_RESTRICTED,
        'wp-cron.php'    => 0,
        'admin-ajax.php' => REQ_AJAX | REQ_RESTRICTED,
        'xmlrpc.php'     => REQ_XMLRPC | REQ_RESTRICTED,
    ];
    // paths to check for classes
    $path_map = [
        'admin/'    => REQ_ADMIN | REQ_RESTRICTED,
        'login'     => REQ_LOGIN,
        'download'  => REQ_UPLOAD | REQ_RESTRICTED,
        'wp-config' => REQ_UPLOAD | REQ_EVIL | REQ_RESTRICTED,
    ];
    // http methods to check for
    $method_map = [
        'OPTIONS' => REQ_VIEW,
        'HEAD'    => REQ_VIEW,
        'GET'     => REQ_VIEW 
    ];

    $exts = ['.ini', '.key', '.bak', '.backup', '.xml', '.conf', '.old', '.pem', '.env', '.yml'];



    $learning_mode = (CFG::int('dynamic_exceptions') > time() && $verified);
    $file_name  = basename($request->path, '/');
    $pos  = stripos($request->path, '/wp-json/');
    $rest = ($pos !== false) ? substr($request->path, $pos) : $request->get['rest_route']??'';

    $class |= (!empty($FILES) && count($_FILES) > 0) ? REQ_UPLOAD | REQ_RESTRICTED: 0;
    $class |= (strpos($request->path, '/.') !== false && !contains($request->path, '.well-known')) ? REQ_DOT | REQ_RESTRICTED: 0; 
    $class |= ends_with_any($request->path, $exts)   ? REQ_DOT | REQ_EVIL | REQ_RESTRICTED: 0; 
    $class |= (isset($method_map[$request->method])) ? REQ_VIEW : REQ_POST | REQ_RESTRICTED;
    $class |= $name_map[$file_name]??0;
    // user enumeration outside of wp-json
    //$class |= is_integer($request->get['author']??'aa') ? REQ_USER_LIST | REQ_RESTRICTED: 0;
    $a = intval($request->get['author']??'aa');
    $class |= ($a > 0 && $a < 10000) ? REQ_USER_LIST | REQ_RESTRICTED: 0;


    // urls with the upload keyword, and NOT the uploads directory are restricted, this should never
    // really be the case since these files should be served directly by the web server
    if (!contains($request->path, "/wp-content/uploads/") && contains($request->path, "upload")) {
        $class |= REQ_UPLOAD | REQ_RESTRICTED;
    }

    // find and classify the path
    foreach ($path_map as $key => $value) {
        if (strpos($request->path, $key) !== false) {
            $class |= $value;
            break;
        }
    }


    // EARLY BAIL OUT FOR LOGGED IN USERS. ALL SCRIPTS AND PARAMS ARE 'VALID' FOR LOGGED IN USERS
    if ($verified > 0) {
        return $class & ~REQ_RESTRICTED;
    }

    // direct script access
    if (ends_with($file_name, 'php')) {
        $class |= REQ_DIRECT_PHP | check_restricted_item($file_name, 'ok_scripts', 
            REQ_RESTRICTED, $learning_mode, COMMON_SCRIPTS);
    }

    // ajax actions
    if (isset($request->get['action'])) {
        $class |= REQ_AJAX | check_restricted_item($file_name, 'ok_actions', 
            REQ_RESTRICTED, $learning_mode, COMMON_ACTIONS);
    }

    // wp-json access
    if (!empty($rest)) {
        $rest   = strtolower(rtrim($rest, '/'));
        $class |= REQ_WP_JSON;
        // check for restricted api access
        $class |= check_restricted_item($rest, 'ok_apis', 
            REQ_RESTRICTED, ($learning_mode & $value != 'wp'), COMMON_APIS);

        // user enumeration (rest api or author url)
        $class |= icontains($rest, '/wp/v2/users') ? REQ_USER_LIST | REQ_RESTRICTED: 0;
    }

    // not restricted and ajax, direct or rest, then we don't need to check the parameter names
    // this is for cases where allowed methods are being called, skip parameter check
    if (! ($class & REQ_RESTRICTED) && ($class & (REQ_AJAX | REQ_DIRECT_PHP | REQ_WP_JSON))) {
        return $class;
    }
    
    // flag if the request has unknown parameters,
    if (count($request->get) > 0) {

        $user_params = array_fill_keys(explode(',', CFG::str('ok_params')), 1);
        $wild_cards  = array_filter($user_params, fn($x) => strpos($x, '*') !== false, ARRAY_FILTER_USE_KEY);

        $unknown_params = array_filter($request->get, ƒixr('\BitFire\remove_junk_parameters', 
            $user_params, array_merge($wild_cards, COMMON_WILDCARDS)), ARRAY_FILTER_USE_BOTH);

        if (count($unknown_params) > 0) {

            if ($learning_mode) {
                update_ini_list('ok_params', ',' . implode(',', array_keys($unknown_params)));
            } else {
                $class |= REQ_UNCOMMON | REQ_RESTRICTED;
            }
        }
    }

    return $class;
}

function check_restricted_item(string $value, string $setting, int $class, bool $learning_mode = false, array $additional_items = []) {

    // special case, no action necessary
    if (empty($value)) {
        return 0;
    }

    // true if the request is to an allowed script
    $ok_scripts = explode(',', CFG::str($setting));
    $ok_direct  = array_fill_keys(array_merge($ok_scripts, $additional_items), 1);

    if (! isset($ok_direct[$value]) && !contains($value, array_keys($ok_direct))) {
        if ($learning_mode) {
            update_ini_list($setting, $value);
        } else {
            return $class;
        }
    }

    return 0;
}

function update_ini_list(string $setting_name, string $new_value) {
    $setting = CFG::str($setting_name);
    if (!contains($setting, $new_value)) {
        require_once WAF_SRC  . 'server.php';
        $data =  "$setting,$new_value";
        update_ini_value($setting_name, "$setting,$new_value")->run(); 
    }
}


/**
 * flatten an array into a string
 * @param mixed $key 
 * @param string $value 
 * @return string 
 */
function flatten_list($key, $value = "") : string {
    return (is_array($value)) ? flatten($value) : "^$key:$value";
}

/**
 * flatten an array into a string, arrays are marked with ^, and key/value pairs are separated by :
 * @param mixed $data 
 * @return string 
 */
function flatten($data) : string {
    if (is_array($data)) {
        $r = "";
        foreach ($data as $key => $value) {
            $r .= flatten_list($key, $value);
        }
        return $r;
    } else {
        return (string)$data;
    }
}


/**
 * url and entity decode of $in...
 * @param mixed $in 
 * @return null|string 
 */
function each_input_param($in) : ?string {
    // we don't inspect numeric values because they would pass all tests
    if (is_numeric($in)) { return $in; }

    // flatten arrays
    if (is_array($in)) { $in = flatten($in); }

    $value = strtolower(urldecode($in));
    return html_entity_decode($value);
}


// remove port numbers from http host headers, always returns a string of some length
// PURE
function parse_host_header(string $header) : string {
    // strip off everything after the first port
    return \strtolower(\substr($header, 0, \strpos($header . ':', ':')));
}

// count characters, but not latin unicode characters with umlots, etc
// PURE TEST
function get_counts(string $input) : array {
    // match any unicode character in the letter or digit category, 
    // and count the remaining characters 
    if (empty($input)) { return []; }
    $input2 = \preg_replace('/[\p{L}\d]/iu', '', $input);
    if (empty($input2)) { return []; }
    return \count_chars($input2, 1);
}

// $input maybe a string, or an array
function get_counts_reduce(array $carry, $input) : array {
    $flat_input = flatten($input);
    // match any unicode character in the letter or digit category, 
    // and count the remaining characters 
    $counts = get_counts($flat_input);
    foreach (\array_keys($counts) as $key) {
        $carry[$key] = (isset($carry[$key])) ?
            $carry[$key] + ($counts[$key] ?? 0):
            ($counts[$key] ?? 0);
    }
    return $carry;
}

/**
 * parse out the forwarded header (for=....)
 * PURE TEST
 */ 
function get_fwd_for(string $header) : string {
    if (preg_match('/for\s*=\s*[^0-9a-f\.:]*([0-9a-f\.:]+)/i', $header, $matches)) {
        return $matches[1];
    }
    return $header;
}


/**
 * take the left most ip address from a comma separated list
 * @param string $remote_addr 
 * @return string 
 */
function get_ip(string $remote_addr = '127.0.0.2') : string {
    return trim( at($remote_addr, ',', 0) );
}


class BrowserState {
    public bool $is_admin = false;
    public bool $verified = false;
    public bool $logged_in = false;
    public bool $unfiltered_html = false;
    public bool $valid_print = false;
    public bool $bot = false;
    public bool $human = false;

    public int $browser_id = 0;
    public int $answer = 0;
    public $time = 0;
    protected int $_state = 0;
    protected int $_orig_state = 0;
    protected int $_iv = 0;
    protected string $_ip = "";

    const BOT = 1;
    const PRINT = 2;
    const JS = 4;
    const HTML = 8;
    const LOGGED_IN = 16;
    const VERIFIED = 32;
    const ADMIN = 64;
    const HUMAN = 128;


    // set to true to prevent new cookie creation
    public static $do_not_create = false; 

    public static function new(string $ip, int $browser_id = 0, bool $is_bot = false) : BrowserState {
        $state = new BrowserState();
        $state->_iv = random_int(0, 0xFFFFFFFF);
        $state->answer = random_int(0xFFFF, 0xFFFFFFFF);
        $state->time = time();
        $state->_ip = $ip;
        $state->browser_id = $browser_id;
        return $state;
    }

    public function hash() : string {
        $bin_ip = inet_pton($this->_ip);
        $format = P32.P16.P8.P32.P64.'A16';

        // da20 = time:1852  iv 0783, ans 3065
        // ans 0783, 1852, 3065
        // dae0 - 2921, 6970
        // 321ae = 3584, 2136549198, 1699162652, 2049502149, 10.8088.29
        $hash = hash_hmac('sha1', pack($format, intval($this->time), intval($this->browser_id),
            intval($this->_state), intval($this->_iv), intval($this->answer), $bin_ip), CFG::str('secret'));
        return $hash;
    }

    public function validate_hash(string $bin_hash) : bool {
        $my_hash = $this->hash();
        return hash_equals($my_hash, $bin_hash);
    }

    /**
     * return the current state of all the flags
     * @return int 
     */
    public function get_state() : int {
        $state = 0;
        $state |= $this->bot ? self::BOT : 0;
        $state |= $this->is_admin ? self::ADMIN : 0;
        $state |= $this->logged_in ? self::LOGGED_IN : 0;
        $state |= $this->verified ? self::VERIFIED : 0;
        $state |= $this->unfiltered_html ? self::HTML : 0;
        $state |= $this->valid_print ? self::PRINT : 0;
        $state |= $this->human ? self::HUMAN : 0;

        return $state;
    }

    /**
     * return a base64 encoded cookie string
     * TODO: remove a level of packing here ...
     * @return string 
     */
    public function to_cookie() : string {
        $this->_state = $this->get_state();
        $format = P32.P16.P8.P32.P64.'A16A40';
        $hash = $this->hash();
        $state = pack($format, $this->time, $this->browser_id, $this->_state, $this->_iv, $this->answer, inet_pton($this->_ip), $hash);
        $encoded = base64_encode($state);
        return $encoded;
    }

    /**
     * @return bool true if the state is updated from the original cookie OR is older than 1 hour
     */
    public function is_dirty() : bool {
        $cookie_age = time() - $this->time;
        return ($this->_orig_state !== $this->get_state() || $cookie_age > HOUR);
    }

    protected static function set_new_cookie(string $ip, int $browser_id = 0, bool $is_bot = false) : BrowserState {
        if (static::$do_not_create) {
            return new BrowserState();
        }
        $new_cookie = BrowserState::new($ip, $browser_id, $is_bot);
        cookie('_bitf', $new_cookie->to_cookie());
        return $new_cookie;
    }

    /**
     * take a base64 encoded string and return the actual BrowserState, or empty state if invalid
     * @param string $cookie 
     * @param string $ip 
     * @param null|UserAgent $agent 
     * @return BrowserState 
     * @throws Exception 
     */
    public static function from_cookie(string $cookie, string $ip, ?UserAgent $agent = null) : BrowserState {
        if (empty($cookie) || strlen($cookie) < 74){
            return new BrowserState();
        }


        $state = new BrowserState();
        $data = unpack(P32.'time/'.P16.'browser/'.P8.'state/'.P32.'iv/'.P64.'answer/A16ip/A40hash', base64_decode($cookie));
        // handle null conditions
        if (empty($data['iv']) || empty($data['answer']) || empty($data['state']) || empty($data['browser'])) {
            return static::set_new_cookie($ip, $agent->browser_id??0, $agent->bot??true);
        }
        $state->time = $data['time'];
        $state->_iv = $data['iv'];
        $state->answer = $data['answer'];
        $state->_state = $data['state'];
        $state->_ip = inet_ntop($data['ip']);
        $state->browser_id = $data['browser'];
        $state->_orig_state = $state->_state;

        $cookie_age = time() - $state->time;
        // guard, cookie, timestamp (7 days), ip and browser name
        if (
            empty($cookie) ||
            $cookie_age > (HOUR * 168) ||
            $state->_ip !== $ip ||
            !empty($agent) && $agent->browser_id !== $state->browser_id)
        {
            return static::set_new_cookie($ip, $agent->browser_id??0, $agent->bot??true);
        }

        // if hash is invalid, return new state
        if (!$state->validate_hash($data['hash'])) {
            return static::set_new_cookie($ip, $agent->browser_id??0, $agent->bot??true);
        }

        $state->bot = $state->_state & BrowserState::BOT;
        $state->is_admin = $state->_state & BrowserState::ADMIN;
        $state->logged_in = $state->_state & BrowserState::LOGGED_IN;
        $state->verified = $state->_state & BrowserState::VERIFIED;
        $state->unfiltered_html = $state->_state & BrowserState::HTML;
        $state->valid_print = $state->_state & BrowserState::PRINT;

        // STATE IS VALID!
        return $state;
    }
}

/*
$state = $_COOKIE['_bfire'];
unpack(P32.'time/'.P8.'browser/'.P8.'state/'.P64.'iv/A20hash', base64_decode($state));
$parts = explode(":", base64_decode($state));
*/





namespace BitFire\Pure;
use \ThreadFin\Effect as Effect;
use \BitFire\Block as Block;
use \BitFire\Request as Request;
use ThreadFin\FileMod;

use const BitFire\FILE_RW;

use function ThreadFin\cidr_match;
use function \ThreadFin\partial_right as ƒixr;
use function ThreadFin\utc_time;

/**
 * pure implementation of ip file blocking
 * TEST: test_pure.php:test_ip_block
 */
function ip_block(Block $block, Request $request, int $block_time) : Effect {
    $block_file = \BitFire\BLOCK_DIR . '/' . $request->ip;
    $exp = time() + $block_time;
    $block_info = json_encode(array('time' => utc_time(), "block" => $block, "request" => $request));
    return 
        Effect::new()->file(new FileMod($block_file, $block_info, FILE_RW, $exp));
}


/**
 * check if $ip is in array of cidr ranges
 * @param string $ip 
 * @param array $cidr_map 
 * @return bool - true if $ip is contained in $cidr_list
 */
function ip_in_cidr_list(string $ip, array $cidr_map) : bool {
    foreach ($cidr_map as $net => $mask) {
        if (cidr_match($ip, $net, $mask)) {
            return true;
        }
    }
    return false;
}



/**
 * reverse a fingerprint id into an array of original headers and order
 * @param int $order 
 * @param array $headers 
 * @return array 
 */
function reverse_fingerprint(int $order, array $headers) : array {
    assert(count($headers) <= 16, "too many headers");
    assert(count($headers) > 4, "missing some headers");


    $rev = array_flip($headers);
    $original_headers = [];
    $ctr = 0;

    for ($i = 0; $i < 16; $i++) {
        $bit1 = $order & 0xF;
        $order >>= 4;
        if (isset($rev[$bit1])) {
            $header = $rev[$bit1]??'unknown';
            $original_headers[$ctr++] = $header;
        }
    }

    return $original_headers;
}


function cache_a_bit(string $key, callable $fn, int $ttl = 0, string $cache_dir = '/tmp') : string {
    $cache_file = $cache_dir . "/$key";
    $result = "";
    if (file_exists($cache_file) && mt_rand(1, 100) != 50) {
        $result = file_get_contents($cache_file);
    }
    if (empty($result)) {
        $result = $fn();
        file_put_contents($cache_file, $result, LOCK_EX);
    }

    return $result;
}
