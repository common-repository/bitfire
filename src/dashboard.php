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

use ArrayIterator;
use BitFire\Config as CFG;
use BitFireBot\Whois_Info;
use RuntimeException;
use Exception;
use SodiumException;
use ThreadFin\FileData;
use ThreadFin\Effect;
use ThreadFin\Hash_Config;
use ThreadFinDB\Credentials;
use ThreadFinDB\DB;

use const BitFire\Data\COMMON_WORDS;
use const ThreadFin\DAY;
use const ThreadFin\ENCODE_RAW;

use function BitFireSvr\convert_bot_file;
use function BitFire\Data\hydrate_log;
use function BitFire\Data\ip4_pos_to_loc;
use function BitFire\Data\ip4_to_uni;
use function BitFire\Data\ip4_uni_to_pos;
use function BitFireBot\find_ip_as;
use function BitFireBot\host_to_domain;
use function BitFireBot\hydrate_any_bot_file;
use function BitFireBot\is_google_or_bing;
use function BitFirePlugin\get_cms_version;
use function BitFirePlugin\malware_scan_dirs;
use function BitFireSvr\doc_root;
use function BitFireSvr\parse_scan_config;
use function BitFireSvr\update_ini_fn;
use function BitFireSvr\update_ini_value;
use function BitFireWP\wp_parse_credentials;
use function BitFireWP\wp_parse_define;
use function ThreadFin\array_add_value;
use function ThreadFin\ip_to_country;
use function ThreadFin\compact_array;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\en_json;
use function ThreadFin\ends_with;
use function ThreadFin\find_fn;
use function ThreadFin\partial_right as ƒixr;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\find_const_arr;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\HTTP\httpp;
use function ThreadFin\icontains;
use function ThreadFin\make_code;
use function ThreadFin\map_to_object;
use function ThreadFin\render_file;
use function ThreadFin\un_json;
use function ThreadFin\at;

require_once \BitFire\WAF_SRC . "api.php";
require_once \BitFire\WAF_SRC . "const.php";
require_once \BitFire\WAF_SRC . "cms.php";
require_once \BitFire\WAF_SRC . "server.php";
require_once \BitFire\WAF_SRC . "botfilter.php";
require_once \BitFire\WAF_SRC . "renderer.php";
require_once \BitFire\WAF_SRC . "data_util.php";

/*
$wp_inc = \BitFire\WAF_ROOT . "wordpress-plugin/includes.php";
$custom_inc = \BitFire\WAF_ROOT . "wordpress-plugin/includes.php";
if (CFG::str("wp_version") && file_exists($wp_inc)) {
    require_once $wp_inc;
} else if (file_exists($custom_inc)) {
    require_once $custom_inc;
}
*/

if (file_exists(WAF_ROOT . "includes.php")) {
    require_once WAF_ROOT . "includes.php";
}

const PAGE_SZ = 30;
const BAD_BOTS = [
    'msie', 'nokia', 'irix','zgrab','winhttprequest', 'perl', 'go-http', 'midp-2', 'lynx', 'docomo', 'python', 'wget', 'embarcadero','win98', 'win95', 'konqueror', 'symbianos', 'sunos', 'netbsd', 'openbsd', 'beos', 'sonyeric', 'curl', 'jndi', 'playstation', 'blackberry'
];

// boolean to string (true|false) 
function b2s(bool $input) :string {
    return ($input) ? "true" : "false";
}


/**
 * truncate the file to max num_lines, returns true if result file is <= $num_lines long
 * SNAP, file_put_contents back
 */
function remove_lines(FileData $file, int $num_lines): FileData
{
    debug("File lines: %d num_lines: %d", $file->num_lines, $num_lines);

    if ($file->num_lines > $num_lines) {
        $file->lines = array_slice($file->lines, -$num_lines);
        $content = join("", $file->lines);

        file_put_contents($file->filename, $content, LOCK_EX);
    }
    return $file;
}

function get_file_count($path): int
{
    $files = scandir($path);
    if (!$files) {
        return 0;
    }

    $size = 0;
    $ignore = array('.', '..');
    foreach ($files as $t) {
        if (in_array($t, $ignore)) continue;
        if (is_dir(rtrim($path, '/') . '/' . $t)) {
            $size += get_file_count(rtrim($path, '/') . '/' . $t);
        } else {
            if (strpos($t, ".php") > 0) {
                $size++;
            }
        }
    }
    return $size;
}


function list_text_inputs(string $config_name): string
{

    $assets = (defined("WPINC")) ? CFG::str("cms_content_url") . "/plugins/bitfire/public/" : "https://bitfire.co/assets/"; // DUP
    $list = CFG::arr($config_name);
    $idx = 0;
    //$result = \BitFirePlugin\add_script_inline("bitfire-list-$config_name", 'window.list_'.$config_name.' = '.json_encode($list).';');
    $result = '<script>window.list_' . $config_name . ' = ' . json_encode($list) . ';</script>';
    foreach ($list as $element) {
        $id = $config_name . '-' . $idx;
        $result .= '
        <div style="margin-bottom:5px;" id="item_' . $id . '">
        <input type="text" autocomplete="off" disabled id="list_' . $id . '" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="' . htmlspecialchars($element) . '">
        <div class="btn btn-danger" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="remove list element" onclick="remove_list(\'' . $config_name . '\', \'' . htmlspecialchars($element) . '\', ' . $idx . ")\"><span class=\"fe fe-trash-2 orange\"></span></div></div>";
        $idx++;
    }
    $result .= '
    <div style="margin-bottom:5px;">
    <input type="text" id="new_' . $config_name . '" autocomplete="off" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="" placeholder="new entry">
    <div class="btn btn-success" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="add new list element" onclick="add_list(\'' . $config_name . '\')"><span class="fe fe-plus"></span></div>';
    return $result;
}



function is_dis()
{
    static $result = NULL;
    if ($result === NULL) {
        $result = is_writeable(\BitFire\WAF_INI) && is_writeable(\BitFire\WAF_ROOT . "config.ini.php");
    }
    return ($result) ? " " : "disabled ";
}


function url_to_path($url)
{
    $idx = strpos($url, "/");
    return substr($url, $idx);
}

function get_asset_dir()
{
    $assets = "https://bitfire.co/assets/";
    if (defined("WPINC") || (contains($_SERVER['REQUEST_URI'], "wp-admin"))) {
        $assets = CFG::str("cms_content_url") . "/plugins/bitfire/public/";
    } 
    else if (contains($_SERVER['REQUEST_URI'], "startup.php")) {
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $assets = dirname($path) . "/public/";
    }
    return $assets;
}

/**
 * render an html template
 * @param string $view_filename full path to the html file
 * @param string $page_name menu name entry
 * @param array $variables variables to pass to template
 * @return Effect an effect that can render the view
 */
function render_view(string $view_filename, string $page_name, array $variables = []): Effect
{
    $custom_css_file = WAF_ROOT . "/views/custom.css";
    assert(file_exists($custom_css_file), "missing core file $custom_css_file");
    assert(is_readable($custom_css_file), "core file $custom_css_file is not readable");

    $page = (defined("WPINC")) ? "BITFIRE_WP_PAGE" : "BITFIRE_PAGE";
    $url_fn = find_fn("dashboard_url");

    $is_free = false;//(strlen(Config::str('pro_key')) < 20);


    $assets = "https://bitfire.co/assets/";
    if (defined("WPINC")) {
        if (empty(CFG::str("cms_content_url"))) {
            if (function_exists("content_url")) {
                $content_url = \content_url();
            } else if (defined("WP_CONTENT_URL")) { $content_url = \WP_CONTENT_URL; }
            update_ini_value("cms_content_url", $content_url)->run();
        } else { $content_url = CFG::str("cms_content_url"); }
        $assets =  "{$content_url}/plugins/bitfire/public/";
    }
    if (isset($variables['assets'])) {
        $assets = $variables['assets'];;
    }




    $content = CFG::str("cms_content_url");
    $variables['license'] = CFG::str('pro_key', "unlicensed");
    $variables['font_path'] = (defined("WPINC") && !empty($content)) ? "$content/plugins/bitfire/public" : "https://bitfire.co/dash/fonts/cerebrisans";
    $variables['is_wordpress'] = (!empty(\BitFireSvr\cms_root())) ? "true" : "false";
    $variables['api_code'] = \ThreadFin\make_code(CFG::str("secret"), new Hash_Config(), time());
    $variables['api'] = BITFIRE_COMMAND;
    $variables['self'] = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);
    $variables['page_tz'] = date('Z');

    $variables['password_reset'] = (CFG::str('password') === 'default') || (CFG::str('password') === 'bitfire!');
    $variables['is_free'] = b2s($is_free);
    $variables['llang'] = "en-US";
    $variables['public'] = \ThreadFin\get_public();
    $variables['flag_type'] = defined("\BitFire\DOCUMENT_WRAP") ? "Blocked" : "Flagged";
    $variables['assets'] = $assets;
    $variables['version'] = BITFIRE_VER;
    $variables['sym_version'] = BITFIRE_SYM_VER;
    $variables['showfree_class'] = $is_free ? "" : "hidden";
    $variables['hidefree_class'] = $is_free ? "hidden" : "";
    $variables['release'] = (($is_free)  ? "FREE" : "PRO") . " Release " . BITFIRE_SYM_VER;
    $variables['underscore_path'] = (defined("WPINC")) ? "/wp-includes/js/underscore.min.js" : "https://bitfire.co/assets/js/unders" . "core.min.js";
    $variables['show_wp_class'] = (defined("WPINC")) ? "" : "hidden";
    //$variables['jquery'] = (defined("WPINC")) ? "" : "https://bitfire.co/assets/js/jqu"."ery/jqu"."ery.js";
    $variables['need_reset'] = b2s((CFG::str('password') === 'bitfire!'));
    $variables['gtag'] = '';
    $header_variables = array_merge($variables, [
        "dashboard_url" => $url_fn("bitfire", "DASHBOARD"),
        "malware_url" => $url_fn("bitfire_malware", "MALWARE"),
        "settings_url" => $url_fn("bitfire_settings", "SETTINGS"),
        "exceptions_url" => $url_fn("bitfire_exceptions", "EXCEPTIONS"),
        "database_url" => $url_fn("bitfire_database", "DATABASE"),
        "advanced_url" => $url_fn("bitfire_advanced", "ADVANCED"),
        "botlist_url" => $url_fn("bitfire_botlist", "BOTLIST"),
    ], $variables);
    // inject header and style
    if (!isset($header_variables["plugin_alerts"])) {
        $header_variables["plugin_alerts"] = "";
    }
    $variables['header'] = \ThreadFin\render_file(WAF_ROOT . "views/header.html", $header_variables);
    $variables['custom_css'] = str_replace("{{public}}", $variables["public"], file_get_contents($custom_css_file));

    // handle old "include" style views and new templates
    $effect = Effect::new();



    if (ends_with($view_filename, "html")) {
        if (CFG::enabled("dashboard-usage")) {
            $variables['gtag']  = file_get_contents(\BitFire\WAF_ROOT . "views/gtag.html");
        }
        $effect->out(\ThreadFin\render_file($view_filename, $variables));
    }

    // if we don't have wordpress, then wrap the content in our skin
    if (!defined("WPINC")||isset($_COOKIE['_bitfire_tech'])) {
        // save current content
        $out = $effect->read_out();
        $variables["maincontent"] = $out;
        $variables["has_scanner"] = (empty(CFG::str("CMS_ROOT"))) ? "hidden2" : "";
        // render the skin with old content
        $effect->out(render_file(\BitFire\WAF_ROOT . "views/skin.html", $variables), ENCODE_RAW, true);
    }

    return $effect;
}







function serve_malware() {
    require_once WAF_SRC . "cms.php";
    // start the profiler if we have one

    // authentication guard
    $auth = validate_auth();
    $auth->run();
    if ($auth->read_status() == 302) { return; }

    // load the scanner config
    $raw_scan_config = CFG::arr("malware_config");
    if (empty($raw_scan_config)) {
        $raw_scan_config = ["unknown_core:1", "standard_scan:false", "access_time:1", "random_name_per:50", "line_limit:12000", "freq_limit:768", "random_name_per:75", "fn_freq_limit:512", "fn_line_limit:2048", "fn_random_name_per:60",  "includes:0", "var_fn:1", "call_func:1", "wp_func:0", "extra_regex:"];
        $eff = update_ini_fn(ƒixl('\BitFireSvr\array_to_ini', 'malware_config', $raw_scan_config), WAF_INI, true);
        $eff->run();
    }
    $scanConfig = parse_scan_config($raw_scan_config);

    // for reading php files
    if (CFG::enabled("FPL") && function_exists("\BitFirePRO\site_unlock")) { 
        \BitFirePro\site_unlock();
    }
    //$config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";

    //$odd = odd_access_times("/var/www/wordpress/wp-admin");
    //dbg($odd, "odd");

    // $scanConfig->

    //$file_list = dump_hashes();
    //$file_list = array("count" => 0, "root" => cms_root(), "files" => []);
    //$dir_list = dump_dirs();


    $is_free = false;//(strlen(CFG::str("pro_key")) < 20);
    $root = \BitFireSvr\cms_root();
    $data = array();

    //$assets = (defined("WPINC")) ? CFG::str("cms_content_url")."/plugins/bitfire/public/" : "https://bitfire.co/assets/";
    //$f2 = "{$assets}vs2015.css";
    //$f3 = "{$assets}prism2.css";
    //debug("F2 [$f3]");
    //$f4 = \BitFire\WAF_ROOT . "public/theme.min.css";
    //$f5 = \BitFire\WAF_ROOT . "public/theme.bundle.css";
    //$data['theme_css'] = file_get_contents($f3) . file_get_contents($f4) . file_get_contents($f5);
    $data['date_z'] = date('Z');
    $data['version'] = BITFIRE_VER;
    $data['version_str'] = BITFIRE_SYM_VER;
    $data['llang'] = "en-US";
    $data['wp_ver'] = get_cms_version($root);
    //$data['file_count'] = count($file_list['files']);
    //$data['file_list_json'] = en_json(compact_array($file_list['files']));
    //$data['dir_ver_json'] = en_json($dir_list);
    $data['is_free'] = $is_free;
    //$data['dir_list_json'] = en_json(array_keys($dir_list));
    $data['show_diff1'] = ($is_free) ? "\nalert('d1 Upgrade to PRO to access over 10,000,000 WordPress file datapoints and view and repair these file changes');\n" : "\nout.classList.toggle('collapse');\n";
    $data['show_diff2'] = (!$is_free) ? "\ne.innerHTML = html;\ne2.innerText = line_nums.trim();\n" : "";
    $root = \BitFireSvr\cms_root();
    $data["total_files"] = get_file_count($root);
    $data["scan_config"] = $scanConfig;
    $data["server"] = urlencode($_SERVER['HTTP_HOST']);
    $data["email"] = CFG::str("notification_email");
    $data["free_disable"] = ($is_free) ? "disabled" : "";
    //$data["free_disable"] = "";

    // make sure the wordpress version is up to date!
    update_ini_value("wp_version", $data['wp_ver'], "")->run();

    $view = ($root == "") ? "nohashes.html" : "hashes.html";

    render_view(\BitFire\WAF_ROOT."views/$view", "bitfire_malware", $data)->run();
}





function human_date($time): string
{
    return date("D M j Y, h:i:s A P", (int)$time);
}
function human_date2($time): string
{
    return
        "<span class='text-primary'>" . date("D M j", (int)$time) . ", </span>" .
        "<span class='text-muted'>" . date("Y", (int)$time) . "</span> " .
        "<span class='text-info'>" . date("h:i:s A", (int)$time) . "</span> " .
        "<span class='text-muted'>" . date("P", (int)$time) . "</span> ";
}

// return a url to this page stripped of BITFIRE parameters.
function dashboard_url(string $token, string $internal_name): string
{
    trace("self_url");
    // handle all other cases.  we want to recreate our exact url 
    // to handle all cases WITHOUT bitfire parameters...
    $url = parse_url(filter_input(INPUT_SERVER, 'REQUEST_URI', FILTER_SANITIZE_URL));
    $get = ['1' => '0'];
    foreach ($_GET as $k => $v) {
        $get[urldecode($k)] = urldecode($v);
    }
    unset($get['BITFIRE_WP_PAGE']);
    unset($get['BITFIRE_PAGE']);
    unset($get['tooltip']);
    unset($get['page']);
    unset($get['block_page_num']);
    unset($get['alert_page_num']);
    unset($get['block_filter']);
    return $url['path'] . '?' . http_build_query($get) . "&BITFIRE_PAGE=$internal_name";
}



function serve_settings()
{
    // authentication guard
    $auth = validate_auth();
    $auth->run();
    if ($auth->read_status() == 302) {
        return;
    }


    $view = (CFG::disabled("wizard")) ? "wizard.html" : "settings.html";
    if (CFG::str("password") == "configure") {
        $view = "setup.html";
    }

    $email = "you@yourmail.com";
    if (function_exists("wp_get_current_user")) {
        $user = wp_get_current_user();
        $email = $user->user_email;
        $name = $user->first_name . ":" . $user->last_name . ":" . $user->display_name;
    }

    $free = false;//(strlen(CFG::str("pro_key")) < 20);
    $disabled = ($free) ? "disabled='disabled'" : "";
    $info = ($free) ? "<h4 class='text-info'> * Runtime Application Self Protection must first be installed with BitFire PRO. See link in header for details.</h4>" : "";

    if (empty(CFG::$_options['whitelist_enabled'])) { 
        CFG::$_options['whitelist_enabled'] = false;
    }

    $policy = CFG::arr("csp_policy");

    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/$view", "bitfire_settings", array_merge(CFG::$_options, array(
        "display_errors" => "unused-feature",
        "auto_start" => CFG::str("auto_start"),
        "free_tog" => ($free) ? "free_tog" : "tog",
        "csp_policy" => $policy["default-src"]??"X",
        "learning" => (CFG::int('dynamic_exceptions') > time()) ? "Currently Learning" : "Learning Complete",
        "free_mute" => ($free) ? "text-muted" : "",
        "your_email" => $email,
        "name" => $name,
        "free_disable" => ($free) ? "disabled='disabled'" : "",
        "hide_wordpress" => defined("WPINC") ? "hidden" : "",
        "cor_policy" => (CFG::str("cor_policy") == "same-site") ? true : false, 
        //"theme_css" => file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css"),
        "valid_domains_html" => list_text_inputs("valid_domains"),
        "hide_shmop" => (function_exists("shmop_open")) ? "" : "hidden",
        "hide_apcu" => (function_exists("apcu_store")) ? "" : "hidden",
        "hide_shm" => (function_exists("shm_put_var")) ? "" : "hidden",
        "mfa" => defined("WPINC") ? "Enable multi factor authentication. Add MFA phone numbers in user editor." :
            "Multi Factor Authentication is only available in the WordPress plugin. Please install from the WordPress plugin directory.",
        "show_mfa" => (defined("WPINC")) ? "" : "hidden",
        "disabled" => $disabled,
        "info" => $info,
        "waf_ini" => WAF_INI,
        "mfa_class" => (defined("WPINC")) ? "text-muted" : "text-danger"
    )))->run();
}

function serve_advanced()
{
    // authentication guard
    validate_auth()->run();
    $is_free = false;//(strlen(Config::str('pro_key')) < 20);
    $disabled = ($is_free) ? "disabled='disabled'" : "";
    $info = ($is_free) ? "<h4 class='text-info'> * Runtime Application Self Protection must first be installed with BitFire PRO. See link in header for details.</h4>" : "";
    $data = [
        "mfa" => defined("WPINC") ? "Enable multi factor authentication. Add MFA phone numbers in user editor." :
            "Multi Factor Authentication is only available in the WordPress plugin. Please install from the WordPress plugin directory.",
        "show_mfa" => (defined("WPINC")) ? "" : "hidden",
        "disabled" => $disabled,
        "info" => $info,
        "mfa_class" => (defined("WPINC")) ? "text-muted" : "text-danger"
    ];
    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/advanced.html", "bitfire_advanced", array_merge(CFG::$_options, $data))->run();
}

/**
 * 
 * @param string $ip 
 * @return string 
 */
function country_mapper(string $ip): string
{
    static $short_names = null;
    static $long_names = null;

    if ($short_names == null || $long_names == null) {
        $long_names = json_decode(file_get_contents(WAF_ROOT . "data/country_name.json"), true);
    }
    $loc = ip4_pos_to_loc(ip4_uni_to_pos(\BitFire\Data\ip4_to_uni($ip)), $long_names);
    return $loc->country;
}

/*
$db = DB::connect("", "", "", "");
$sql = $db->fetch("SELECT * FROM ip4", []);
$db->insert()
*/

function get_abuse(array $ips): Abuse
{
    $keys = array_keys($ips);
    if (isset($keys[0])) {
        $ip = at($keys[0], '/', 0);
    } else {
        return new Abuse();
    }
    //"{"data":{"ipAddress":"5.8.10.202","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"RU","usageType":"Data Center\/Web Hosting\/Transit","isp":"Petersburg Internet Network Ltd.","domain":"pinspb.ru","hostnames":[],"isTor":false,"totalReports":540,"numDistinctUsers":160,"lastReportedAt":"2023-06-01T14:14:07+00:00"}}abuse [100] domain []"

    $response = http2("GET", "https://app.bitfire.co/ip_check.php", ["ip" => $ip, "maxAgeInDays" => 30]);
    $data = json_decode($response->content, true);
    $abuse = new Abuse();

    if (!empty($data['data'])) { $data = $data['data']; }

    if (!empty($data)) {
        if (isset($data['abuseConfidenceScore'])) {
            $abuse->score = $data['abuseConfidenceScore'] ?? 0;
        } else if (isset($data['score'])) {
            $abuse->score = $data['score'] ?? 0;
        }
        if (isset($data['isp'])) {
            $abuse->isp = $data['isp'] ?? 0;
        }
        if (isset($data['totalReports'])) {
            $abuse->number = $data['totalReports'] ?? 0;
        }
        else if (isset($data['reporters'])) {
            $abuse->number = $data['reporters'] ?? 0;
        }
        if (isset($data['isTor'])) {
            $abuse->tor = $data['isTor'] ?? 0;
        } else if (isset($data['proxy_type'])) {
            $abuse->tor = $data['proxy_type'] ?? 0;
        }
    }

    return $abuse;
}

function crap_bot($bot) : bool {
    $lower = strtolower($bot->name);
    $length = strspn($lower, 'abcdefghijklmnopqrstuvwxyz');
    $simple = substr($lower, 0, $length);
    $crap = in_array($simple, ["censysinspect", "rogerbot", "internetmeasurement", "curl"]);
    $crap |= contains($bot->agent_trim, BAD_BOTS);

    return $crap;
}


/**
 * UGLY AF, clean this up...
 * @return void 
 */
function serve_bot_list()
{
    // authentication guard
    validate_auth()->run();
    $url_fn = find_fn("dashboard_url");
    $request = BitFire::get_instance()->_request;


    if (!isset($request->get['known'])) {
        $request->get['known'] = "to_review";
    }
    $bot_dir = get_hidden_file("bots");
    $old_files = glob("{$bot_dir}/*.json");

    // remove old bots from pre 4.0 version
    array_walk($old_files, function ($file) {
        $parts = explode(".", $file);
        array_pop($parts);
        convert_bot_file(join(".", $parts));
    });


    $bot_files = glob("{$bot_dir}/*.js");
    $ip_counter = [];
    // echo "<pre>\n";

    $all_bots = array_map(function ($file) use (&$ip_counter) {
        $id = pathinfo($file, PATHINFO_FILENAME);
        /*
        if (!file_exists($file)) {
            return false;
        }
        //$bot = unserialize(file_get_contents($file));
        $content = file_get_contents($file);
        if (ends_with($file, ".json")) {
            $bot = unserialize($content);
        } else {
            // map the json data to a real object
            $raw_data = json_decode($content, true);
            if (!empty($content) && is_array($raw_data)) {
                $bot = new BotSimpleInfo($raw_data['agent']);
                $abuse = new Abuse();
                $bot = map_to_object($raw_data, $bot);
                $bot->abuse = map_to_object($raw_data['abuse']??[], $abuse);
            }
        }
        */
        $bot = hydrate_any_bot_file($file);

        if (is_array($bot->ips)) {
            foreach ($bot->ips as $ip => $unused_class) {
                $ip_counter[$ip] = ($ip_counter[$ip] ?? 0) + 1;
            }
        }



        if (!$bot) {
            unlink($file);
            return false;
        }
        $fm_time = filemtime($file);
        if ($bot->mtime < $fm_time) {
            $bot->mtime = $fm_time;
        }
        // ID must always be the filename...
        $bot->id = $id;

        // TODO, cron up removal of old bots...
        if (!$bot->valid && $fm_time < (time() - (86400 * 30))) {
            // unlink($file);
            return false;
        }

        return $bot;
    }, $bot_files);

    // remove empty botsBAD_BOTS 
    $all_bots = array_filter($all_bots);


    // filter out bots that used more than 2 user agents
    $all_bots = array_filter ($all_bots, function ($bot) use ($ip_counter) {
        /** @var BotSimpleInfo $bot */
        foreach ($bot->ips as $ip => $unused_class) {
            if (is_google_or_bing($ip, false)) {
                return true;
            }

            // IP used more than 2 UAs
            $value = $ip_counter[$ip] ?? 0;
            if ($value > 4) {
                // this bot only has this one IP that created it, just delete it
                if (count($bot->ips) == 1) {
                    if (file_exists($bot->path())) {
                        unlink($bot->path());
                    }
                    // echo "delete: " . $bot->path() . "\n";
                    return false;
                }
                // block the IP for 30 days if it has created more than 6 UAs
                if ($value > 6) {
                    touch(WAF_ROOT . "blocks/$ip", time() + (86400 * 30));
                }

                return false;
            }
        }
        return true;
    });

    // remove empty bots 
    $all_bots = array_filter($all_bots);



    $known = $request->get["known"] ?? "known";
    $filter_bots = array_filter($all_bots, function ($bot) use ($known) {
        /** @var BotSimpleInfo $bot */
        $d = explode(",", $bot->domain);
        if (in_array("google.com", $d)) { return $known == "known"; }

        $r = $bot->valid || !empty($bot->home_page) || ($bot->manual_mode == BOT_ALLOW_NET || $bot->manual_mode == BOT_ALLOW_AUTH);
        // return known bots
        if ($known == "known") {
            return $r;
        }
        // ugly af, THIS SHOULD ONLY PULL IN BOTS THAT ARE TRYING TO ACCESS API CALLS
        else if ($known == "to_review") {
            if (!$r && isset($bot->abuse->score)) {
                if ($bot->abuse->score <= 30 && $bot->miss > 0) {
                    if (! ($bot->classification & REQ_EVIL)) {
                        if ($bot->mtime > time() - 86400 * 7) {
                            return !crap_bot($bot) && $bot->manual_mode != BOT_ALLOW_NET && $bot->manual_mode != BOT_ALLOW_AUTH && $bot->vendor != "junk";
                        }
                    }
                }
            }
            return false;  
        }
        // unknown bots
        else if (!$r) {
            // trash bots are small agents, or msie agents
            $score = $bot->abuse->score ?? 0;
            $trash = (contains($bot->agent_trim, BAD_BOTS)) || $score > 50 || $bot->vendor == "junk";
            if ($known == "trash") {
                return $trash;
            }
            return !$trash;
        }

        return false;
    });

    // order by last time seen, newest first
    usort($filter_bots, function ($a, $b) {
        return $b->mtime - $a->mtime;
    });


    $checks = CFG::int("ip_lookups", 0);
    $pro = true;//strlen(CFG::str("pro_key")) > 20;
    $bot_list = array_map(function ($bot) use ($checks, $pro) {
        if (empty($bot->agent)) {
            return null;
        }

        

        // update abuse info if we don't have it
        $id = (!empty($bot->id)) ? $bot->id : crc32($bot->agent_trim);
        if (empty($bot->abuse) || is_int($bot->abuse) || (is_object($bot->abuse) && $bot->abuse->score < 0)) {
            $bot->abuse = get_abuse($bot->ips);
            $bot_file = get_hidden_file("bots") . "/$id.js";
            if (file_exists($bot_file)) {
                file_put_contents($bot_file, json_encode($bot, JSON_PRETTY_PRINT), LOCK_EX);
            }
        }



        $d = explode(",", $bot->domain);
        if (in_array("google.com", $d)) { 
            $bot->vendor = "Google";
            $bot->favicon = "google.webp";
            $bot->favicon = get_asset_dir() . "browsers/google.webp";
        }

        if (empty($bot->country) && !empty($bot->ips)) {
            $ips = array_keys($bot->ips);
            $country_counts = [];
            foreach ($ips as $ip) {
                $country = country_mapper($ip);
                $country_counts[$country] = ($country_counts[$country] ?? 0) + 1;
            }
            arsort($country_counts);
            $bot->country = join(", ", array_slice(array_keys($country_counts), 0, 3));
            if (empty($bot->name)) {
                $bot->name = "Unknown Bot";
            }
        } else if (empty($bot->country)) {
            $bot->country = "-";
        }
        // XXX function-ize this
        // trim down to the minimum user agent, this need to be a function. keep in sync with botfilter.php
        $agent_min1 = preg_replace("/[^a-z\s]/", " ", strtolower(trim($bot->agent ?? "")));
        $agent_min2 = preg_replace("/\s+/", " ", preg_replace("/\s[a-z]{1,3}\s([a-z]{1-3}\s)?/", " ", $agent_min1));
        // remove common words
        $rem_fn = function ($carry, $item) {
            return str_replace($item, "", $carry);
        };
        $agent_min_words = array_filter(explode(" ", array_reduce(COMMON_WORDS, $rem_fn, $agent_min2)));

        $bot->agent_trim = substr(trim(join(" ", $agent_min_words)), 0, 250);


        /*
        if (strlen(CFG::str("pro_key")) < 20) {
            $bot->allow = "<a target='_blank' class='text-white' href='https://bitfire.co/pricing'> Open </a> <i type='button' class='fe fe-external-link'></i>";
            $bot->auth_title = "Upgrade to PRO to enable bot authentication";
            $bot->allowclass = "info pointer text-white";
        } else {
            $bot->allow = "Authenticated <i class='fe fe-award'></i>";
            //$bot->allow = "Authenticated";
            $bot->auth_title = "Bots are network authenticated";
            $bot->allowclass = "success pointer text-dark";
        }
        */


        if ($bot->manual_mode == BOT_ALLOW_ANY || $bot->manual_mode == BOT_ALLOW_OPEN) {
            $bot->allow = "Open <i class='fe fe-shield-off'></i>";
            $bot->domain = "Any";
            $bot->allowclass = "danger text-dark";
            $bot->auth_title = "Bot is allowed full access";
        } else if ($bot->manual_mode == 64 || $bot->manual_mode == BOT_ALLOW_NONE) { // XXX remove 64 on next release
            $bot->allow = "Blocked <i class='fe fe-slash'></i>";
            $bot->allowclass = "dark text-white";
            $bot->auth_title = "Bot is blocked";
        } else if ($bot->manual_mode == BOT_ALLOW_AUTH || $bot->manual_mode == BOT_ALLOW_NET) {
            $bot->allow = "Authenticated <i class='pl1 fe fe-lock bold'></i>";
            $bot->auth_title = "Bot is network authenticated";
            //$bot->allowclass = "primary-bold ";
            $bot->allowclass = "success text-dark ";
        } else if ($bot->manual_mode == BOT_ALLOW_RESTRICT) {
            // CONTINUE IMPLEMENTING RESTRICTION HERE ...
            $bot->allow = "Restricted <i class='pl1 fe fe-lock bold'></i>";
            $bot->auth_title = "Bot has limited access";
            //$bot->allowclass = "primary-bold ";
            $bot->allowclass = "warning text-dark ";
        }
        else {
            $bot->allow = "Blocked <i class='fe fe-shield-off'></i> ";
            $bot->allowclass = "dark text-white";
            $bot->auth_title = "Bot is blocked";
            //$bot->allow = "Default ".$bot->manual_mode." <i class='fe fe-award'></i>";
            //$bot->allowclass = "info";
        }

        $bot->agent = substr($bot->agent, 0, 160);
        if (!empty($bot->home_page) && !contains($bot->home_page, "/search?q")) {
            $info = parse_url($bot->home_page);
            if (isset($info["scheme"]) && isset($info["host"])) {
                $bot->favicon = $info["scheme"] . "://" . $info["host"] . "/favicon.ico";
            } else {
                $bot->favicon = get_asset_dir() . "robot_nice.svg";
            }
        } else if (empty($bot->favicon)) {
            $bot->favicon = get_asset_dir() . "robot_nice.svg";
        }
        $bot->classclass = "danger";
        if ($bot->valid == 0) {
            $bot->classclass = "warning text-dark";
        } else if ($bot->valid > 0) {
            $bot->classclass = "secondary text-dark";
        }
        if (empty($bot->hit)) {
            $bot->hit = 0;
        }
        if (empty($bot->miss)) {
            $bot->miss = 0;
        }
        if (empty($bot->not_found)) {
            $bot->not_found = 0;
        }
        if (empty($bot->domain)) {
            $bot->domain = "-";
        }
        if (empty($bot->icon)) {
            $bot->icon = "robot_nice.svg";
        }
        $bot->machine_date = date("Y-m-d", $bot->ctime);
        $bot->machine_date2 = date("Y-m-d", $bot->mtime);
        $bot->checked = ($bot->valid > 0) ? "checked" : "";
        $bot->domain = trim($bot->domain, ", ");
        $bot->ip_str = join(", ", array_keys($bot->ips));
        if (empty($bot->home_page)) {
            $bot->home_page = "https://www.google.com/search?q=user-agent+" . urlencode($bot->agent);
            $bot->icon = "unknown_bot.webp";
        }
        $bot->category = ($bot->category == "Unknown") ? "" : "<span class='bg-info badge text-white pdl3'>{$bot->category}</span>";

        if ($bot->abuse instanceof Abuse) {
            //$bot->category = "No Information";
            //$bot->classclass = "info";

            if ($bot->abuse->score == -1 && count($bot->ips) > 0) {
                $bot->abuse = get_abuse($bot->ips);
            }

            // replace pictures with robot icons ONLY on unknown and trash bots
            if (!isset($_GET['known']) || $_GET['known'] != "known") {
                if ($bot->abuse->score > 50) {
                    //$bot->category = "Abusive IP";
                    $bot->category .= " <span class='bg-danger badge text-dark'>Abuse: {$bot->abuse->score}</span>";
                    //$bot->classclass = "danger";
                    $bot->favicon = get_asset_dir() . "robot_angry.png";
                } else if ($bot->abuse->score > 30) {
                    //$bot->category = "Some IP Abuse";
                    $bot->classclass = "warning";
                    $bot->category .= " <span class='bg-warning badge text-dark'>Abuse: {$bot->abuse->score}</span>";
                    $bot->favicon = get_asset_dir() . "robot_unknown.png";
                }
                else {
                    //$bot->category .= " <span class='bg-success badge text-dark'>Abuse: {$bot->abuse->score}</span>";
                    if (empty($bot->favicon)) {
                        $bot->favicon = get_asset_dir() . "robot_nice.svg";
                    }
                }
            }

            /*
            if ($bot->abuse->score < 0) {
                if (!$pro && $checks >= 128) {
                    $bot->category .= " <span class='bg-info badge text-dark'>Free Abuse Checks Expired</span>";
                } else if ($pro) {
                    $bot->abuse = get_abuse($bot->ips);
                }
            }
            */
        }


        if (empty($bot->vendor) || contains($bot->vendor, "Unknown Bot")) {
            $a = parse_agent($bot->agent);
            $name = empty($a->browser_name) ? "Unknown Bot" : $a->browser_name;
            $bot->vendor = "";
            $bot->name = $name;
            $bot->log_class = ($bot->name == "Unknown Bot") ? "hidden" : "text-muted";

            if (isset($bot->reason)) {
            if (!icontains($bot->category, "fake")) {
                if (stristr($bot->agent, "chrome") !== false && ! contains($bot->domain, ["google.com", "googlebot.com"])) {
                    $bot->reason .= "Fake Chrome";
                    $bot->category .= " <span class='bg-warning badge text-dark'>Fake Chrome 2</span>";
                } else if (stristr($bot->agent, "firefox") !== false) {
                    $bot->reason .= "Fake FireFox";
                    $bot->category .= " <span class='bg-warning badge text-dark'>Fake Firefox</span>";
                } /*else if (stristr($bot->agent, "google") !== false) {
                    $bot->reason .= "Fake Google";
                    $bot->category .= " <span class='bg-warning badge'>Fake Google</span>";
            } */ else if (stristr($bot->agent, "msie") !== false && stristr($bot->agent, "net clr") == false) {
                    $bot->reason .= "Fake Explorer";
                    $bot->category .= " <span class='bg-warning badge text-dark'>Fake Explorer</span>";
                } else if (stristr($bot->agent, "opera") !== false) {
                    $bot->reason .= "Fake Opera";
                    $bot->category .= " <span class='bg-warning badge text-dark'>Fake Opera</span>";
                } else if (stristr($bot->agent, "edg") !== false) {
                    $bot->reason .= "Fake Edge";
                    $bot->category .= " <span class='bg-warning badge text-dark'>Fake Edge</span>";
                }
            }
            }
        }
 

        /*
        $nnn = random_int(0, 4);
        for ($i = 0; $i<$nnn; $i++) {
            $bot->classification |= 1 << random_int(2, 12);
        }
        */


        foreach (REQ_NAMES as $key => $mask) {
            if ($bot->classification & ($mask)) {
                $color = REQ_COLOR[$key]??'info';
                $bot->category .= " <span class='bg-$color badge'>".$key."</span>";
                continue;
            } else {
                foreach ($bot->ips as $ip => $classification) {
                    if ($classification & ($mask)) {
                        $color = REQ_COLOR[$key]??'info';
                        $bot->category .= " <span class='bg-$color badge'>".$key."</span>";
                        break;
                    }
                }
            }
        }

        $bot->ip = array_keys($bot->ips)[0]??"";
        return $bot;
    }, $filter_bots);

    // remove any empty bots
    $bot_list = array_filter($bot_list);

    // purge these bots...
    if ($request->get['purge']??'' == 'true') {
        $bot_list = array_filter($bot_list, function (BotSimpleInfo $bot) {

            $path = get_hidden_file("bots/{$bot->id}.js");

            // skip bots that are allowed
            if ($bot->manual_mode != BOT_ALLOW_RESTRICT && $bot->manual_mode > BOT_ALLOW_NONE) {
                return true; 
            }
            // if the path exists purge it
            if (file_exists($path)) {
                // unlink($path);
                return false;
            }
            // unreachable case???
            return true;
        });
    }

    $x = $request->get["known"] ?? "unknown";
    $check = ($x === "known") ? "checked" : "";

    if (empty($bot_list)) {
        $bot = new BotSimpleInfo("This is a place-holder bot for display only. Bots will appear here when they are detected. Control access with the triple dot icon on the right.");
        $bot->abuse = new Abuse();
        //$bot->allow = "no authentication";
        //$bot->allowclass = "dark";
        $bot->category = "<span class='bg-dark badge'>Test Sample</span>";
        //$bot->country = "Local Host";
        //$bot->country_code = "-";
        $bot->domain = "BitFire.co";
        $bot->favicon = "https://bitfire.co/favicon.ico";
        $bot->hit = 0;
        $bot->miss = 0;
        $bot->not_found = 0;
        $bot->ips = ['127.0.0.1' => 1];
        $bot->home_page = "https://bitfire.co/sample_bot";
        $bot->favicon = "https://bitfire.co/assets/img/shield128.png";
        $bot->name = "BitFire Example Bot";
        if ($_GET['known']??"x" == "to_review") {
            $bot->name = "No Bots To Review";
            $bot->agent = "Select one of the other categories above 'known', 'unknown' or 'junk' to see bot activity";
        }
        // $bot->net = "-";
        $bot->agent_trim = "BitFire";
        $bot->domain = "bitfire.co";
        $bot->vendor = "BitFire, llc";
        //$bot->machine_date = date("Y-m-d");
        //$bot->machine_date2 = date("Y-m-d");
        $bot->ip = $bot->ips[0]??"";


        $bot_list = [$bot];
    }

    if (isset($bot) && (is_int($bot->abuse) || $bot->abuse->score < 0)) {
        $crc = crc32($bot->agent_trim);
        $bot->abuse = get_abuse($bot->ips);
        $bot_file = get_hidden_file("bots") . "/$crc.js";
        if ($crc != 3036273246 && file_exists($bot_file)) {
            file_put_contents($bot_file, json_encode($bot, JSON_PRETTY_PRINT), LOCK_EX);
        }
    }

    /*
    $long_names = json_decode(file_get_contents(WAF_ROOT . "data/country_name.json"), true);
    $bot_list2 = array_map(function(BotSimpleInfo $info) use ($short_names, $long_names) {

        foreach ($info->ips as $ip => $classification) {
            $h = gethostbyaddr($ip);
            $loc = ip4_pos_to_loc(ip4_uni_to_pos(\BitFire\Data\ip4_to_uni($ip)), $long_names);
            $list = ['city' => $loc->city, 'country' => $loc->country, 'ip' => $ip, 'domain' => $h, 'category' => ''];
            foreach (REQ_NAMES as $name => $mask) {
                if ($classification & $mask) {
                    $list['category'] .= "<span class='badge bg-".REQ_COLOR[$name]."'>$name</span> ";
                }
            }

            $info->ips[$ip] = $list;
        }
        return $info;
    }, $bot_list);
    */


    if (!isset($request->get['known'])) { $request->get['known'] = 'known'; }
    $x = ($request->get["known"]??"known" == "known") ? "unknown" : "known";
    $data = ["bot_list" => $bot_list, "known_check" => $check, "known" => $request->get["known"]];
    $data['unknown'] = ($request->get["known"] == "known") ? "unknown" : "known";

    $data['js_encoded_data'] = json_encode(array_column($bot_list, null, 'id'));

    $data['free_checks'] = (128 - CFG::int("ip_lookups", 0));
    if (true) { //strlen(CFG::str("pro_key")) > 20) {
        $data['free_checks'] = "unlimited";
    }

    if ($request->get['known'] == "to_review") {
        $data['type_info'] = "These are unknown bots that might be useful to your website. Look for any plugins or services that you use and set those bots to &quot;Authenticated&quot;, move to &quot;unknown&quot; or &quot;junk&quot; to restrict or block access.";
    }
    if ($request->get['known'] == "known") {
        $data['type_info'] = "Known bots that are likely to be useful to your website. If unsure, the recommend setting is &quot;Restricted&quot; to grant limited view-only access, or &quot;Authenticated&quot; for full access.";
    }
    if ($request->get['known'] == "unknown") {
        $data['type_info'] = "These bots are unknown. If unsure, the recommend setting is &quot;Restricted&quot; to grant limited view-only access, be careful granting &quot;Authenticated&quot; or &quot;Open&quot; access to unknown bots.";
    }
    if ($request->get['known'] == "trash") {
        $data['type_info'] = "Here you will find abusive IPS, fake bots, and other bots that are not likely to be useful to your website. You may rarely find useful web site integrations where, The recommend setting is &quot;Blocked&quot;";
    }


    render_view(\BitFire\WAF_ROOT . "views/bot_list.html", "bitfire_bot_list", array_merge(CFG::$_options, $data))->run();
}



/**
 * auth on basic auth string or wordpress is admin
 * @param string $raw_pw the password to validate against Config::password
 * @return Effect validation effect. after run, ensured to be authenticated
 */
function validate_auth(): Effect
{

    // issue a notice if the web path is not writeable
    /*
    if (!is_writable(WAF_INI)) {
        return render_view(\BitFire\WAF_ROOT."views/permissions.html", "content", ["title" => "bitfire must be web-writeable", "body" => "please make sure bitfire is owned by the web user and web writeable"])->exit(true);
    }
    */

    //\BitFireSvr\upgrade();

    return \BitFire\verify_admin_password();
}




function serve_exceptions(): void
{
    $file_name = get_hidden_file("exceptions.json");
    $exceptions = FileData::new($file_name)->read()->un_json()->map(function ($x) {
        $class = (floor($x["code"] / 1000) * 1000);
        $x["message"] = MESSAGE_CLASS[$class];
        if (!$x["parameter"]) {
            $x["parameter"] = "All Parameters";
        }
        if (!$x["host"]) {
            $x["host"] = "All Hosts";
        }
        if (!$x["url"]) {
            $x["url"] = "Any URL";
        }
        return $x;
    });

    // ugly...
    $complete = CFG::int("dynamic_exceptions");
    $enabled = false;
    if ($complete < 10) {
        $when = "Learning complete";
    } else {
        if ($complete > time()) {
            $enabled = true;
            $num = ceil(($complete - time()) / DAY);
            $day = ($num > 1) ? "days" : "day";
            $when = "Learning complete in $num $day";
        } else {
            $when = "Learning completed on " . date("M j, Y", $complete);
        }
    }


    $allowed = FileData::new(get_hidden_file("browser_allow.json"))->read()->un_json();

    $data = [
        "exceptions" => $exceptions(),
        "exception_json" => json_encode($exceptions()),
        "learn_complete" => $when,
        "enabled" => $enabled,
        "checked" => ($enabled) ? "checked" : "",
        "ip_json" => json_encode($allowed->lines['ip'] ?? []),
        "agent_json" => json_encode($allowed->lines['ua'] ?? [])
    ];

    render_view(\BitFire\WAF_ROOT . "views/exceptions.html", "bitfire_exceptions", $data)->run();
}

function binary_search(array $malware, int $needle, int $offset, int $malware_size)
{
    if ($offset === 0) {
        $offset = $malware_size / 2;
    }
}


function serve_database(): void
{
    // pull in some wordpress functions in case wordpress is down
    require_once WAF_SRC . "wordpress.php";

    $resp = http2("GET", "https://bitfire.co/backup.php?get_info=1", [
        "secret" => sha1(CFG::str("secret")),
        "domain" => $_SERVER['HTTP_HOST']
    ]);
    $backup_status = json_decode($resp->content, true);
    $backup_status["online"] = ($backup_status["capacity"] ?? 0 > 0);
    $backup_status["online_text"] = ($backup_status["capacity"] ?? 0 > 0) ? _("Online") : _("Offline");

    $backup_status["online_class"] = ($backup_status["online"] == true) ? "success" : "warning";

    //$database_file = ;
    //$database_file = FileData::new(WAF_ROOT . "data/database.json");//->read()->un_json()->lines;

    $info = [];
    $href_list = [];
    $script_list = [];

    $info["backup_status"] = $backup_status;
    $info["backup-age-days"] = -1;
    $info["backup-age-badge"] = "bg-danger-soft";
    $info["backup-storage-badge"] = "bg-success-soft";
    $info["backup-storage"] = "?" . _(" MB");
    $info["backup-posts"] = $backup_status["posts"] ?? '?';
    $info["backup-comments"] = $backup_status["comments"] ?? '?';
    $info["restore_disabled"] = "disabled";
    $info["restore-available"] = "N/A";
    $info["points"] = $backup_status["archives"] ?? ['?'];

    if ($backup_status["online"]) {
        //$info["restore_disabled"] = "";
        $info["restore-available"] = ($backup_status["storage"] ?? 0 > 64000) ? _("Online") : _("N/A");
        $info["restore-class"] = ($backup_status["storage"] ?? 0 > 64000) ? "success" : "danger";

        // database backup info
        $info["backup-storage"] = round(($backup_status["capacity"] - $backup_status["storage"]) / 1024 / 1024, 2) . _(" MB");
        $info["backup-age-sec"] = intval($backup_status["backup_epoch"] ?? 0);
        $info["backup-posts"] = $backup_status["posts"] ?? 0;
        $info["backup-comments"] = $backup_status["comments"] ?? 0;

        if ($info["backup-age-sec"] < time() - (30 * DAY)) {
            $info["backup-age-badge"] = "bg-success-soft";
        }
        $info["backup-size"] = intval($backup_status["storage"] ?? 0);
        if ($info["backup-size"] > 1024 * 1024 * 40) {
            $info["backup-storage-badge"] = "bg-danger-soft";
        }
    }

    $credentials = null;
    if (defined("WPINC") && defined("DB_USER")) {
        $prefix  = "wp_";
        if (isset($GLOBALS['wpdb'])) {
            trace("WP_DB");
            $prefix = $GLOBALS['wpdb']->prefix;
        }
        $credentials = new Credentials(DB_USER, DB_PASSWORD, DB_HOST, DB_NAME);
    } else {
        trace("BIT_DB");
        $credentials = wp_parse_credentials(CFG::str("cms_root"));
        if ($credentials) {
            $prefix = $credentials->prefix;
        }
    }
    if ($credentials) {
        $db = DB::cred_connect($credentials)->enable_log(true);
        $info['site_url'] = $db->fetch(
            "select option_value from `{$prefix}options` WHERE option_name = {option_name}",
            ["option_name" => "siteurl"]
        )
            ->col("option_value")();
        $info[''] = $db->fetch(
            "select option_value from `{$prefix}options` WHERE option_name = {option_name}",
            ["option_name" => "active_plugins"]
        )
            ->col("option_value")();
        $info['active'] = $db->fetch(
            "select option_name from `{$prefix}options` WHERE option_name = {option_name}",
            ["option_name" => "active_plugins"]
        )
            ->col("option_value")();
        $info['auto_load_sz_kb'] = $db->fetch(
            "SELECT ROUND(SUM(LENGTH(option_value))/1024) as size_kb FROM `{$prefix}options` WHERE autoload='yes'",
            null
        )
            ->col("size_kb")();
        $info['auto_load_top10'] = $db->fetch(
            "(SELECT option_name, length(option_value) as size FROM `{$prefix}options` WHERE autoload='yes' ORDER BY length(option_value) DESC LIMIT 10)",
            null
        )
            ->data();

        $info['num-posts'] = $db->fetch("SELECT count(*) as num FROM `{$prefix}posts` p")->col("num")();
        $info['num-comments'] = $db->fetch("SELECT count(*) as num FROM `{$prefix}comments` p")->col("num")();

        /*
        $posts = $db->fetch("SELECT p.id, post_content, post_title, u.display_name, post_date FROM `{$prefix}posts` p LEFT JOIN `{$prefix}users` u ON p.post_author = u.id ORDER BY post_date DESC LIMIT 1000 OFFSET 0",
            null);

        if (!$posts->empty()) {
            // remap malware list to hashmap
            $malware_file = WAF_ROOT . "/data/malware.bin";
            $malware_raw = file_get_contents($malware_file);
            $malware = unpack("N*", $malware_raw);
            $malware_total = count($malware);
        }
        */

        $good_domains = [];
        $bad_domains = [];

        $my_url_len = strlen($info["site_url"]);
        /*
        $info["backup-posts"] = $posts->count() - intval($info["backup-posts"]);
        foreach ($posts->data() as $post) {
            if (preg_match_all("/<script([^>]*)>([^<]*)/is", $post["post_content"], $matches)) {
                $seconds = time();
                $script_list[] = [
                    "id" => $post["id"],
                    "title" => $post["post_title"],
                    "author" => $post["display_name"],
                    "date" => $post["post_date"],
                    "days" => ceil($seconds/DAY),
                    "markup" => $matches[1],
                    "domain" => "script content",
                    "content" => $matches[2]
                ];
            }
            if (preg_match_all("/<a[^>]+>/i", $post['post_content'], $links)) {
                foreach ($links as $link) {
                    // skip link if it is marked nofollow, or user content
                    if (icontains($link[0], ["nofollow", "ugc"])) {
                        continue;
                    }
                    // skip the link if it's not a full path...
                    if (!icontains($link[0], "http")) {
                        continue;
                    }
                    // it's a real link
                    if (preg_match("/href\s*=\s*[\"\']?\s*([^\s\"\']+)/i", $link[0], $href)) {
                        // exclude links to ourself...
                        $source = substr($href[1], 0, strlen($my_url_len) + 16);
                        if (icontains($source, $info["site_url"])) { continue; }

                        $check_domain = preg_replace("#https?:\/\/([^\/]+).*#", "$1", $href[1]);

                        // don't search 2x!
                        if (isset($good_domains[$check_domain])) { continue; }

                        // TODO: add list of Top 1000 domains and check those first to exclude the link here
                        $hash = crc32($check_domain );

                        if (in_list($malware, $hash, $malware_total)) {
                            $bad_domains[$check_domain] = true;
                        } else {
                            $good_domains[$check_domain] = true;
                        }


                        if (isset($bad_domains[$check_domain])) {
                            $parsed = date_parse($post["post_date"]);
                            $new_epoch = mktime(
                                $parsed['hour'], 
                                $parsed['minute'], 
                                $parsed['second'], 
                                $parsed['month'], 
                                $parsed['day'], 
                                $parsed['year']
                            );
                            $seconds = time() - $new_epoch;

                            $href_list[$href[1]] = [
                                "id" => $post["id"],
                                "name" => $post["display_name"],
                                "title" => $post["post_title"],
                                "date" => $post["post_date"],
                                "days" => ceil($seconds/DAY),
                                "markup" => $link[0],
                                "domain" => $check_domain,
                                "md5" => md5($check_domain),
                                "hash" => $hash
                            ];
                        }
                    }
                }
            }
        }
        */
    }


    $info["malware"] = $href_list;

    $defines = wp_parse_define(CFG::str("cms_root") . "/wp-includes/version.php");
    $info['wp_version'] = $defines['wp_version'] ?? "unknown";
    $info['db_version'] = $defines['wp_db_version'] ?? "unknown";
    $info['num_malware'] = count($href_list);

    // http2("POST", APP."domain_check.php", en_json($href_list));

    render_view(\BitFire\WAF_ROOT . "views/database.html", "bitfire_database", $info)->run();
}


/**
 * TODO: split this up into multiple functions
 */
function serve_dashboard(): void
{
    // handle dashboard wizard
    if (CFG::disabled("wizard") && !isset($_GET['tooltip'])) {
        serve_settings();
        return;
    }

    // authentication guard
    $auth = validate_auth();
    $auth->run();
    if ($auth->read_status() == 302) {
        return;
    }

    $f = get_hidden_file("ip.bin");
    $f2 = WAF_ROOT . "data/ipaa.bin";
    if (!file_exists($f) || (file_exists($f2) && filemtime($f2) < (time() - (60 * 3))) || filesize($f)+1024 < 25094900) {
        require_once WAF_SRC . "server.php";
        \BitFireSvr\core_download();
    }


    $vars = ['reqs' => [], 'error' => '/'];
    $weblog_file = get_hidden_file("weblog.bin");
    $vars['error-class'] = "primary";
    if (!file_exists($weblog_file) || !is_writable($weblog_file)) {
        $file = str_replace(doc_root(), "", $weblog_file);
        $vars['error'] = "$file is not writable. no data to show.";
        $vars['error-class'] = "danger bold";
    }

    /*
    $fh = fopen($weblog_file, "rb");

    fseek($fh, 0);
    $raw_pos = fread($fh, 2);
    $tmp = unpack('Spos', $raw_pos);
    $pos = $tmp['pos']??1;

    $start = max($pos - 10, 0);

    //echo "<pre> ($start, $pos)\n";
    for ($i = $start; $i < $pos; $i++) {

        $off = ($i * 296)+2;
        if (fseek($fh, $off) < 0) {
            die("unable to seed to [$off]\n");
        }
        $raw = fread($fh, 296);
        if (strlen($raw) >= 263) {
            $hex = bin2hex($raw);

            //$data = unpack('Cbot/Cvalid/Lip/Qver/S404/S500/Sbr_id/Sos/Scode/Sblock_code/Smethod/Lpost_sz/Lbrowser/Ltime/Lms_time/A64url/A32ref/A64ua/A64reason', $raw);
            //$data = unpack('Cbot/Cvalid/Lip/Lver/S404/S500/Sbr_id/Sos/Scode/Sblock_code', $raw);
            $data = unpack('Cbot/Cvalid/A16/Lver/Sctr404/Srr/Sbr_id/Sos/Scode/Sblock_code/Smethod/Lpost_sz/Lbrowser/Ltime/Lms_time/A64url/A32ref/A96ua/A64reason', $raw);
            //printf("raw size [%d]\n", strlen($raw));
            //echo "[$hex]\n";
            //print_r($data);
            $vars['req'][] = hydrate_log($data);
        }
    }

    */

    $ip = BitFire::get_instance()->_request->ip ?? "127.0.0.1";
    $vars['timezone'] = date_default_timezone_get();
    $vars['verify_http_code'] = CFG::int("verify_http_code", 303);
    $vars['exclude_ip'] = $ip;
    if (isset($_GET['start_time'])) {
        $vars['start_time'] = preg_replace('/[^\dT:\.-]/', '', $_GET['start_time']);
    } else {
        $vars['start_time'] = date('Y-m-d\TH:i', time() - (DAY * 7));
    }
    if (isset($_GET['end_time'])) {
        $vars['end_time'] = preg_replace('/[^\dT:\.-]/', '', $_GET['end_time']);
    } else {
        $vars['end_time'] = 'now';
    }
    $vars['include_filter'] = '';
    if (isset($_GET['include_filter'])) {
        $filter = substr(strtolower($_GET['include_filter']), 0, strspn($_GET['include_filter'], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV0123456789'));
        $vars['include_filter'] = preg_replace('/[\'\"\n\r\&]/', '', $filter);
    }


    render_view(\BitFire\WAF_ROOT . "views/traffic.html", "bitfire", $vars)->run();
    return;
}
