<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 */


namespace BitFire;

use ThreadFin\CacheStorage;
use BitFire\Config as CFG;
use BitFire\StringResult as BitFireStringResult;
use RuntimeException;
use ThreadFin\Effect;
use ThreadFin\FileMod;
use ThreadFin\Maybe;
use ThreadFin\MaybeA;
use ThreadFin\MaybeBlock;

use const ThreadFin\DAY;

use function ThreadFin\contains;
use function ThreadFin\ends_with;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\icontains;
use function ThreadFin\map_reduce;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\recache2;
use function ThreadFin\recache2_file;
use function ThreadFin\starts_with;

const MIN_SQL_CHARS=8;

const SQL_WORDS = array('add', 'all', 'alter', 'ascii', 'between', 'benchmark', 'case', 'contains', 'concat',
'distinct', 'drop', 'delay', 'except', 'exists', 'exec', 'from', 'lower', 'upper', 'outer', 'order', 'null', 
'md5', 'hex', 'like', 'true', 'false', 'function', 'or', 'and', 'left', 'join', 'group by', 'group', 'having',
'right', 'substring', 'select', 'pg_sleep', 'sleep',
'update', '(', ')', ',', '=', '!', 'insert', 'union', 'while', 'where', 'waitfor', 'is null');
const SQL_CONTROL_CHARS = array(35 => 1, 39 => 1, 40 => 1, 41 => 1, 44 => 1, 45 => 1, 61 => 1);
const SQL_IMPORTANT_CHARS = array("\n", "\r", "  ", "\t", '(', ')');

const FAIL_SQL_LITE=14000;
const FAIL_SQL_SELECT=14001;
const FAIL_SQL_UNION=14002;
const FAIL_SQL_FOUND=14004;
const FAIL_SQL_OR=14005;
const FAIL_SQL_BENCHMARK=14007;
const FAIL_SQL_ORDER=14006;




const FAIL_FILE_UPLOAD = 21000;
const FAIL_FILE_PHP_EXT = 21001;
const FAIL_FILE_PHP_MIME = 21002;
const FAIL_FILE_PHP_TAG = 21003;
const FAIL_FILE_POLYGLOT = 21004;

class StringResult {
    public $len;
    public $value;
    public function __construct(string $v, int $l) {
        $this->len = $l;
        $this->value = $v;
    }
}

class WebFilter {


    public function __construct() {
    }
    
    
    public function inspect(\BitFire\Request $request, ?BrowserState $cookie) : MaybeBlock {
        $block = MaybeBlock::$FALSE;

        $admin = is_admin();

        if (Config::enabled(CONFIG_FILE_FILTER)) {
            if (!$admin) {
                \BitFire\file_filter($_FILES);
            }
        }

        // nothing to inspect
        if ((count($request->get) + count($request->post)) == 0) {
            return $block;
        } 

        // admins who are on the site, don't need to be checked...
        $where_from = parse_url($_SERVER['HTTP_REFERER']??"", PHP_URL_HOST);
        $self_from = parse_url("https://" . $_SERVER['HTTP_HOST']??"", PHP_URL_HOST);
        if ($admin && !empty($where_from) && !empty($self_from) && strtolower($where_from) === strtolower($self_from)) {
            return $block;
        }

        if (Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            trace("web");

            // update keys and values
            $key_file = \BitFire\WAF_ROOT."data/keys2.raw";
            $value_file = \BitFire\WAF_ROOT."data/values2.raw";
            $f1 = get_hidden_file("keys2.txt");
            $f2 = get_hidden_file("values2.txt");
            $exp_time = time() - DAY;
            if (!file_exists($f1) || filemtime($f1) < $exp_time || !file_exists($f2) || filemtime($f2) < $exp_time) {
                update_raw($key_file, $value_file)->run();
                file_put_contents($f1, json_encode(recache2_file($key_file)), LOCK_EX);
                file_put_contents($f2, json_encode(recache2_file($value_file)), LOCK_EX);
            }

            // the reduction
            $keys = json_decode(file_get_contents($f1), true);
            $values = json_decode(file_get_contents($f2), true);
            $c1 = count($keys); $c2 = count($values);
            trace("KEY.{$c1} VAL.{$c2}");
            if ($c1 <= 1 || $c2 <= 1) {
                update_raw($key_file, $value_file)->run();
            } 
            else {
                $reducer = ƒixl('\\BitFire\\generic_reducer', $keys, $values);
                // always check on get params
                array_map($reducer, array_keys($request->get), array_values($request->get));
                // don't check for post if user is an admin
                if (!is_admin()) {
                    // check the post parameters
                    array_map($reducer, array_keys($request->post), array_values($request->post));

                    // filter out known common cookies
                    $c = array_filter($_COOKIE, function ($cookie_name) {
                        return !icontains($cookie_name, ['_fbp','sess', 'wordpress_','aff','ref','muid','wp-settings','_bitf','_g','_ym','wp_lang','_ut']);
                    }, ARRAY_FILTER_USE_KEY);

                    // check the now reduced set of cookies
                    array_map($reducer, array_keys($c), array_values($c));
                }
            }
        }


        // SQL injection filter
        if (Config::enabled(CONFIG_SQL_FILTER)) {
            $block = sql_filter($request);
        }

        // check for long parameter names
        $keys = array_keys($request->get);
        array_walk($keys, function ($param) {
            if (strlen($param) > 750) {
                block_now(FAIL_PARAM_OVERFLOW, "param name", substr($param, 0, 12). "...", "param overflow", 0)->run();
            }
        });

        return $block;
    }
}

/**
 * filter for SQL injections
 */
function sql_filter(\BitFire\Request $request) : MaybeBlock {
    trace("sql");
    // UGLY hard coded plugin fixes below...
    // don't check contact-form posts
    if (contains($request->path, "contact-form")) { return Maybe::$FALSE; }

    foreach ($request->get as $key => $value) {
        $maybe = search_sql($key, flatten($value), $request->get_freq[$key]??null);
        if (!$maybe->empty()) { return $maybe; }
    }
    // only check sql on post if not an admin, (lots of false positives for backed admin functions)
    if (!is_admin()) {
        foreach ($request->post as $key => $value) {
            $maybe = search_sql($key, flatten($value), $request->post_freq[$key]??null);
            if (!$maybe->empty()) { return $maybe; }
        }
    }
    return Maybe::$FALSE;
}

function check_file(array $file) {
    if (strpos($file["name"]??"", "%00") !== false)  {
        block_now(FAIL_FILE_UPLOAD, "null file upload", $file["name"], "null byte", BLOCK_SHORT)->run();
    }
    check_ext_mime($file);
    check_php_tags($file);
}


/**
 * check file names, extensions and content for php scripts
 */
function file_filter(array $files) : void {
    trace("files:".count($files));


    if (isset($files["tmp_name"])) {
        check_file($files);
    } else {
        foreach ($files as $file) {
            file_filter($file);
        }
    }

}

/**
 * look for php tags in file uploads
 */
function check_php_tags(array $file, string $mime = "text/plain") : MaybeA {
    // check for <?php tags
    if (empty($file['tmp_name'])) { return Maybe::$FALSE; }
    $data = file_get_contents($file["tmp_name"]);
    if (stripos($data, "<?php") !== false) {
        if (preg_match('/<\?php\s/i', $data)) {
            block_now(FAIL_FILE_PHP_TAG, "PHP file upload", $file["name"], "<?php", BLOCK_SHORT)->run();
            //return MaybeBlock::of(BitFire::new_block(FAIL_FILE_PHP_TAG, "file upload", $file["name"], ".php", BLOCK_SHORT));
        }
    }
    // check for phar polyglots (tar)
    if (substr($data, -4) === "GBMB") {
        block_now(FAIL_FILE_POLYGLOT, "PHP Polyglot", $file["name"], "PHP Polyglot", BLOCK_SHORT)->run();
        //return MaybeBlock::of(BitFire::new_block(FAIL_FILE_POLYGLOT, "file upload", $file["name"], "phar polyglot", BLOCK_SHORT));
    }

    return Maybe::$FALSE;
}

// trim the file like WP does
function wp_file_trim(string $in) : string {
    // from WP wp-includes/formatting.php sanitize_file_name
    $special_chars = array('?', '[', ']', '/', '\\', '=', '<', '>', ':', ';', ',', "'", '"', '&', '$', '#', '*', '(', ')', '|', '~', '`', '!', '{', '}', '%', '+', '’', '«', '»', '”', '“', chr( 0 ));
    $no_special = str_replace($special_chars, '', $in);
	$trimmed = trim($no_special, '.-_');
    return $trimmed;
}

// basic file upload checks
function check_ext_mime(array $file) : string {

    // detail to text
    $f_info = "text/plain";
    if (!empty($file["tmp_name"]??"")) {
        // check file extensions...
        if (file_exists($file["tmp_name"])) {
            $p_info = pathinfo($file["name"]);
            $trimmed_name = wp_file_trim($file["name"]);
            // original file ends with php extension, or the trimmed name ends with php, or the pathinfo extension is a php file
            if (ends_with(strtolower(trim($file["name"])), "php") ||
                ends_with(strtolower($trimmed_name), "php") ||
                in_array(strtolower($p_info['extension']??''), array("php", "phtml", "php5", "php4", "php7", "php8", "phar"))) {
                block_now(FAIL_FILE_PHP_EXT, "file upload", $file["name"], ".php", BLOCK_SHORT)->run();
                //return MaybeBlock::of(BitFire::new_block(FAIL_FILE_PHP_EXT, "file upload", $file["name"], ".php", BLOCK_SHORT));
            }
                
            // check mime types
            $ctx = finfo_open(FILEINFO_MIME_TYPE | FILEINFO_CONTINUE | FILEINFO_EXTENSION);
            $f_info = finfo_file($ctx, $file["tmp_name"]);
            if (stripos($f_info, "php") !== false || stripos($file["type"], "php") !== false) {
                block_now(FAIL_FILE_PHP_MIME, "file upload", $file["name"], ".php", BLOCK_SHORT)->run();
                //return MaybeBlock::of(BitFire::new_block(FAIL_FILE_PHP_MIME, "file upload", $file["name"], ".php", BLOCK_SHORT));
            }
        }
    }

    return $f_info;
}


/**
 * find sql injection for short strings
 */
function search_short_sql(string $name, string $value) : MaybeA {

    if (preg_match('/\s*(or|and)\s+(\d+|true|false|\'\w+\'|)\s*!?=(\d+|true|false|\'\w+\'|)/sm', $value, $matches)) {
        block_now(FAIL_SQL_OR, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE)->run();
    }
    if (preg_match('/\s*(or|and)\s+\d+\s+between\s+\d\s+and/sm', $value, $matches)) {
        block_now(FAIL_SQL_OR, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE)->run();
    }
    if (preg_match('/benchmark\s*\([^,]+\,[^\)]+\)/sm', $value, $matches) || preg_match('/waitfor\s+delay\s+[\'"]/sm', $value, $matches) || preg_match('/sleep\s*\(\d+\)/sm', $value, $matches)) {
        block_now(FAIL_SQL_BENCHMARK, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE)->run();
        //return BitFire::get_instance()->new_block(FAIL_SQL_BENCHMARK, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE);
    }
    if (preg_match('/union[\sal]+select\s+([\'\"0-9]|null|user|subs)/sm', $value, $matches)) {
        block_now(FAIL_SQL_UNION, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE)->run();
        //return BitFire::new_block(FAIL_SQL_UNION, $name, $matches[0], 'sql identified', 0);
    }
    if (!is_admin()) {
        if (preg_match('/\s+select\s+substr(ing)?\s+/', $value, $matches)) {
            block_now(FAIL_SQL_ORDER, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE)->run();
            //return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE);
        }

        if (ends_with(BitFire::get_instance()->_request->path, ".jsp")) {
        if (preg_match('/\'?.*?(or|and|where|order\s+by)\s+[^\s]+(;|--|#|\'|\/\*)/sm', $value)) {
            block_now(FAIL_SQL_ORDER, $name, $value, ERR_SQL_INJECT, BLOCK_NONE)->run();
            //return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
        }
        }
        if (preg_match('/select\s+(all|distinct|distinctrow|high_priority|straight_join|sql_small_result|sql_big_result|sql_buffer_result|\@data|sql_no_cache|sql_calc_found_rows)*[\sa-zA-Z\d_,-]+\s*(into|from)/sm', $value, $matches)) {
            block_now(FAIL_SQL_ORDER, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE)->run();
            //return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE);
        }

/*
        $removed1 = str_replace(SQL_WORDS, "", $value);
        $removed2 = preg_replace('/\'[^\'\s]+\'/sm', '', $removed1);
        $removed3 = preg_replace("/[\-']/", '', $removed2);
        

        $l1 = strlen($value);
        $l2 = strlen($removed3);
        $l3 = strlen($value);

        if ($l3 > 32 && $l2 < ($l1 / 2) || $l2 < ($l1 - 20)) {
            block_now(FAIL_SQL_FOUND, $name, $value, 'mostly sql identified', BLOCK_NONE)->run();
        }
        */
    }



    return Maybe::$FALSE;
}


/**
 * find sql looking things...
 * this could be way more functional, but it would be slower, choices...
 */
function search_sql(string $name, string $value, ?array $counts) : MaybeA {
    $p1 = strpos($value, "union");
    if ($p1 !== false) {
        $p2 = strpos($value, "select", $p1);
        if ($p2 > $p1) {
            $p3 = strpos($value, "from", $p2);
            if ($p3 > $p2) {
                block_now(FAIL_SQL_UNION, $name, $value, ERR_SQL_INJECT, BLOCK_NONE)->run();
                //return BitFire::new_block(FAIL_SQL_UNION, $name, $value, 'union SQL injection', 0);
            }
        }
    }


    if (preg_match('/(select\s+[\@\*])/sm', $value, $matches)) {
        block_now(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE)->run();
        //return BitFire::new_block(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }

    // block short sql,
    $total_control = (!empty($counts)) ? sum_sql_control_chars($counts) : 0;

    $stripped_comments = strip_comments($value);

    if (preg_match('/(select\s+[\@\*])/sm', $stripped_comments->value, $matches) || preg_match('/(select[^a-zA-Z0-9]+(from|if))/sm', $stripped_comments->value, $matches)) {
        block_now(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE)->run();
        //return BitFire::new_block(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }
        
    $block = Maybe::$FALSE;

    // look for the short injection types, if not an admin (prevent wp-admin false positives)
    if (!is_admin()) {

        if ($total_control > 0) {
            \BitFire\search_short_sql($name, $value);
            \BitFire\search_short_sql($name, $stripped_comments->value);
        }
        \BitFire\check_removed_sql($stripped_comments, $total_control, $name, $value);
    }

    return $block;
}

/**
 * check if removed sql was found
 */
function check_removed_sql(StringResult $stripped_comments, int $total_control, string $name, string $value) : MaybeA {
 
    $sql_removed = str_replace(SQL_WORDS, "", $stripped_comments->value);
    $sql_removed_len = strlen($sql_removed);

    // if we have enough sql like syntax
    if ($sql_removed_len + MIN_SQL_CHARS <= $stripped_comments->len + $total_control) {
        // ugly but fast, remove temp variables ...
        $result = strip_strings($sql_removed);

        // we removed at least half of the input, look like sql to me..
        if (in_array($name, array_keys(Config::arr("filtered_logging"))) == false) {
            $removed_len = strlen($sql_removed);
            if ($result->len < 15) {
                return search_short_sql($name, $result->value);
            } else if ($result->len < ($removed_len / 2) || $result->len < ($removed_len - 20)) {
                block_now(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE)->run();
                //return BitFire::new_block(FAIL_SQL_FOUND, $name, $value, 'sql identified', 0);
            }
        }
    }
    
    return Maybe::$FALSE;
}

/**
 * remove sql strings 
 */
function strip_strings(string $value) : StringResult {
    $stripped = map_reduce(array("/\s+/sm" => ' ', "/'[^']+$/sm" => '', "/'[^']*'/sm" => '', "/as\s\w+/sm" => ''), function($search, $replace, $carry) {
        return preg_replace($search, $replace, $carry);
    }, $value);
    return new StringResult($stripped, strlen($stripped));
}

/**
 * remove sql comments 
 */
function strip_comments(string $value) : StringResult {
    $s1 = str_replace(SQL_IMPORTANT_CHARS, " ", $value);
    $s2 = preg_replace("/\/\*\!([^*]+)\*\//sm", ' $1 ', $s1);
    $s3 = preg_replace("/\/\*.*?\*\//sm", ' ', $s2);
    $s4 = preg_replace("/(#|--\s)[^\n]+/", ' ', $s3);
    return new StringResult($s4, strlen($s1)); // only return len of s1
}


/**
 * reduce key / value with fn
 */
function trivial_reducer(callable $fn, string $key, string $value, $ignore) : void {
    if (strlen($value) > 0) {
        $fn($key, $value);
    }
    return;
}

/**
 * reduce key / value with fn
 */
function generic_reducer(array $keys, array $values, $name, $value) : void {

    if (is_array($value)) {
        $value = flatten($value);
    }

    // don't reduce these empty values
    if (empty($value) || strlen($value) < 4) {
        return;
    }


    \BitFire\generic((string)$name, $value, $values, $keys);
}

/**
 * generic search function for keys and values
 */
function generic(string $name, string $value, array $values, array $keys) : void {

    if (is_int($value)) { return; }

    foreach ($values as $key => $needle) {
        // if (!is_int($key) || empty($needle)) { debug("key [%s], need [%s]", $key, $needle); continue; }
        if ((strpos($value, $needle) !== false || strpos($name, $needle) !== false)) { 
            block_now($key, $name, $value, "static match: $needle", BLOCK_NONE)->run();
        }
    }

    foreach ($keys as $key => $needle) {
        \BitFire\dynamic_match($key, $needle, $value, $name);
    }


    // we don't want non-admins to post links to other sites
    if (!is_admin()) {
        $m = '/[^a-z](href|src)\s*=\s*[\'"`]?(?!http|\/)[^\'"`]{12,}/sm';
        if (preg_match($m, $value, $matches)) {
            block_now(10105, 'XSS input', $matches[0], 'XSS Filter', BLOCK_NONE)->run();
        }
    }

}

/**
 * dynamic analysis
 */
function dynamic_match($key, string $needle, string $value, string $name) : void {
    assert(! empty($needle), "generic block list error: needle:[$needle] - code[$key]");
    assert(! ctype_digit($needle), "generic block list error: needle code swap");
    assert($needle[0] === "/", "generic block list error: no regex_identifier");
    static $list = null;

    if (empty($needle) == false && preg_match($needle, $value) === 1) {
        // extra special case here to reduce false positives
        if ($key == 10101) {
            if ($list == null) { $list = file(WAF_ROOT . "data/events.txt", FILE_IGNORE_NEW_LINES); debug("load events sz %d", count($list)); }
            if (!\ThreadFin\contains($value, $list)) {
                debug("found non event (%s)", $value);
                return;
            }
        }
        block_now($key, $name, $value, "dynamic match", BLOCK_NONE)->run();
    }
}

/**
 * static analysis
 */
function static_match($key, $needle, string $value, string $name) : void {
    if (empty($needle) == false && (strpos($value, $needle) !== false || strpos($name, $needle) !== false)) { 
        block_now($key, $name, $value, "static match", BLOCK_NONE)->run();
    }
}

/**
 * take character counts and return number which are sql control chars
 */
function sum_sql_control_chars(?array $counts) : int {
    if (empty($counts)) { return 0; }
    return array_sum(array_intersect_key($counts, SQL_CONTROL_CHARS));
}

/**
 * update encoded data files
 * @param string $key_file 
 * @param string $value_file 
 * @return Effect 
 */
function update_raw(string $key_file, string $value_file) : Effect {
    trace("up_raw");
    require_once WAF_SRC . "http.php";
    $key_data = (http2("GET", APP."encode.php", array("v" => 0, "md5"=>sha1(CFG::str("encryption_key")))));
    $value_data = (http2("GET", APP."encode.php", array("v" => 1, "md5"=>sha1(CFG::str("encryption_key")))));
    return Effect::new()
        ->file(new FileMod($key_file, $key_data->content??""))
        ->file(new FileMod($value_file, $value_data->content??""));
}

