<?php
namespace BitFireWP;

use BitFire\Request;
use ThreadFin\MaybeA;
use ThreadFinDB\Credentials;
use ThreadFinDB\DB;

use function ThreadFin\dbg;
use function ThreadFin\debug;
use function ThreadFin\trace;
use BitFire\Config as CFG;

use const BitFire\DS;
use const BitFire\WAF_SRC;

require_once WAF_SRC . "db.php";



class Parts {
    private $_x;
    private $_names = array();
    public static function of(string $separator, string $data) {
        $p = new Parts();
        $p->_x = explode($separator, $data);
        return $p;
    }

    public function name(...$names) : Parts {
        for ($i=0;$i<count($names);$i++) {
            $this->_names[$names[$i]] = $i;
        }
        return $this;
    }

    public function at(string $name) : ?string {
        if (!isset($this->_names[$name])) { return NULL; }
        $idx = $this->_names[$name];
        if ($idx > count($this->_x)) { return NULL; }
        return $this->_x[$idx];
    }
}

// concatenate all data with a concat glue
function concat_fn(string $bind_char) : callable {
    return function(...$concat) use ($bind_char) : string {
        $result = "";
        for ($i=0,$m=count($concat);$i<$m;$i++) {
            $result .= $concat[$i] . $bind_char;
        }
        return trim($result, $bind_char);
    };
}


// take a single line and return the define value, suitable for array_reduce function
function define_to_array(array $input, string $define_line) : array {
    
    if (preg_match("/define\s*\(\s*['\"]([a-zA-Z_]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]/", $define_line, $matches)) {
        $input[$matches[1]] = $matches[2];
    }
    if (preg_match("/\\$([\w_]+)\s*=\s*['\"]?([a-z0-9A-Z_\.-]+)/", $define_line, $matches)) {
        $input[$matches[1]] = $matches[2];
    }

    return $input;
}

// turn define array into credentials
function array_to_credentials(?array $defines) :?Credentials {
    $credentials = NULL;
    if ($defines && count($defines) > 5) {
        $credentials = new Credentials($defines['DB_USER']??'', $defines['DB_PASSWORD']??'', $defines['DB_HOST']??'', $defines['DB_NAME']??'', $defines['table_prefix']??'wp_');
    }
    return $credentials;
}


// parse wp-config into db credentials
function wp_parse_credentials(string $root) : ?Credentials {
    $credentials = NULL;
    $defines = wp_parse_define("$root/wp-config.php");
    if (isset($defines["SECURE_AUTH_KEY"])) {
        $credentials = array_to_credentials($defines);
    }
    return $credentials;
}

// parse out all defines from the wp-config
function wp_parse_define(string $file) : array {
    $defines = [];
    if (file_exists($file)) {
        $data = file($file);
        if (!empty($data)) {
            $defines =  array_reduce($data, '\BitFireWP\define_to_array', []);
        }
    }
	return $defines;
}


// fetch an auth "salt" for a particular "scheme"
function wp_fetch_salt(string $root, string $scheme) : string {
	$scheme = strtoupper($scheme);
	$defines = wp_parse_define("$root/wp-config.php");
	if (!isset($defines["{$scheme}_KEY"])) { debug("auth define [%s] missing", $scheme); return ""; }
	return $defines["{$scheme}_KEY"] . $defines["{$scheme}_SALT"];
}

// validate an auth cookie
function wp_validate_cookie(string $cookie, string $root) : bool {
    $data = Parts::of("|", $cookie)->name("username", "exp", "token", "hmac");
    $credentials = wp_parse_credentials($root);
    $db = DB::cred_connect($credentials);
    $sql = $db->fetch("SELECT SUBSTRING(user_pass, 9, 4) AS pass FROM " . $credentials->prefix . "users WHERE user_login = {login} LIMIT 1", array("login" => $data->at("username")));
    if ($sql->empty()) { debug("wp-auth failed to load db user data"); return false; }
    $key_src = concat_fn("|")($data->at("username"), $sql->col("pass"), $data->at("exp"), $data->at("token"));

    // first try to auth with data from the config file
    $key_list = array("auth", "secure_auth", "logged_in");
    foreach ($key_list as $name) {
        $key = hash_hmac('md5', $key_src, wp_fetch_salt($root, $name));
        $hash = hash_hmac(function_exists('hash')?'sha256':'sha1', concat_fn("|")($data->at("username"), $data->at("exp"), $data->at("token")), $key);
        if (hash_equals($hash, $data->at("hmac"))) { debug("config key wp match [%s]", $name); return true; }
    }

    // that failed, lets try the db salt and key (may need to try logged_in_key/salt also)
    $db_salt = $db->fetch("SELECT option_value FROM " . $credentials->prefix . "options where option_name = 'auth_salt'");
    if (!$db_salt->empty()) {
        $db_key = $db->fetch("SELECT option_value FROM " . $credentials->prefix . "options where option_name = 'auth_key'");
        if (!$db_salt->empty()) {
            $salt = $db_salt->col('option_value')();
            $key = $db_key->col('option_value')();
            $full_key = $key . $salt;
            $key = hash_hmac('md5', $key_src, $full_key);
            $hash = hash_hmac(function_exists('hash')?'sha256':'sha1', concat_fn("|")($data->at("username"), $data->at("exp"), $data->at("token")), $key);
            if (hash_equals($hash, $data->at("hmac"))) { debug("db key wp match [%s]", $name); return true; }
        }
    }

    debug("wp auth failed");
    return false;
}

// return the wp cookie value
function wp_get_login_cookie(array $cookies) : string {
    $wp = array_filter($cookies, function ($x) {
        if (strpos($x, "wordpress_") !== false) {
            if ((strpos($x, "wordpress_logged_in") === false) && (strpos($x, "wordpress_test") === false)) {
                return true;
            }
        }
        return false;
    }, ARRAY_FILTER_USE_KEY);
    if (count($wp) < 1) { return ""; }
    return array_values($wp)[0];
}

function machine_date($time) : string {
    return date("Y-m-d", (int)$time);
}


function bytes_to_kb($bytes) : string {
    return round((int)$bytes / 1024, 1) . "Kb";
}


function wp_enrich_wordpress_hash_diffs(string $ver, string $doc_root, array $hash): array
{
    if (!isset($hash['path'])) { return $hash; }
    // $paths = explode('/', $hash['path']);
    $out = '/' . trim($doc_root, '/') . ($hash['path'][0] != DS) ? DS : '' . $hash['path'];
    $path = "https://core.svn.wordpress.org/tags/{$ver}{$hash['path']}";
    if (strpos($doc_root, '/plugins') !== false) {
        $path = "https://plugins.svn.wordpress.org/{$hash['name']}/tags/{$ver}/{$hash['path']}";
        $hash['out'] = '/wp-content/plugins/' . $hash['name'] . $hash['path'];
    } else if (strpos($doc_root, '/themes') !== false) {
        $path = "https://themes.svn.wordpress.org/{$hash['name']}/{$ver}/{$hash['path']}";
        $hash['out'] = '/wp-content/themes/' . $hash['name'] . $hash['path'];
    } else {
        $hash['out'] = $hash['path'];
    }

    $hash['mtime'] = filemtime($out);
    $hash['url'] = $path;
    $hash['ver'] = $ver;
    $hash['doc_root'] = $doc_root;
    $hash['machine_date'] = machine_date($hash['mtime']);
    $hash['type'] = ($hash['size2']??$hash['size'] > 0) ? "WordPress file" : "Unknown file";
    $hash['kb1'] = bytes_to_kb($hash['size']);
    $hash['kb2'] = bytes_to_kb($hash['size2']??$hash['size']);
    $hash['bgclass'] = ($hash['size2']??$hash['size'] > 0) ? "bg-success-soft" : "bg-danger-soft";
    $hash['icon'] = ($hash['size2']??$hash['size'] > 0) ? "fe-check" : "fe-x";

    return $hash;
}


/**
 * 
 * @param Request $request 
 * @param MaybeA $cookie 
 * @return void 
 */
function wp_handle_admin(\BitFire\Request $request, MaybeA $cookie) {
    debug("wp_handle_admin");
    $root = \BitFire\Config::str("cms_root");
    if (empty($root)) { debug("no cms_root"); return; }
    if (strpos($request->path, "/wp-admin/") === false) { debug("no wp-admin"); return; }
    if ($request->post['action']??'' === "heartbeat") { return; }
    debug("wp admin request %s", $request->path);
}

function get_credentials() : ?Credentials {
    if (defined("WPINC") && defined("DB_USER")) {
        $credentials = new Credentials(DB_USER, DB_PASSWORD, DB_HOST, DB_NAME);
        if (isset($GLOBALS['wpdb'])) {
            trace("WPDB");
            $credentials->prefix = $GLOBALS['wpdb']->prefix;
            return $credentials;
        }
    } else {
        trace("BIT_DB");
        $credentials = wp_parse_credentials(CFG::str("cms_root"));
        $defs = wp_parse_define(CFG::str("cms_root")."/wp-config.php");
        if (!empty($credentials)) {
            $credentials->prefix = $defs["table_prefix"]??"wp_";
        }
        return $credentials;
    }

    return NULL;
}

function get_db_connection() : ?DB {
    $credentials = get_credentials();

    if ($credentials) {
        return DB::cred_connect($credentials);
    }

    return NULL;
}