<?php
/**
 * The BitFire Wordpress bootstrap file
 *
 * 
 * 
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin if it has not started via auto_prepend_file.
 * 
 * This WordPress plugin uses the BitFire firewall library to perform all
 * security functions.  This plugin integrates the WordPress admin and plugin
 * pages with the library API.  Source available at github, see link below
 *
 * @link              http://bitfire.co
 * @source            https://github.com/bitslip6/bitfire
 * @since             1.8.0
 * @package           BitFire

 *
 * @wordpress-plugin
 * Plugin Name:       BitFire
 * Plugin URI:        https://bitfire.co/
 * Author URI:        https://bitfire.co/
 * Description:       Only RASP firewall for WordPress. Stop malware, redirects, back-doors and account takeover. 100% bot blocking, backups, malware cleaner.
 * Description:       Only RASP firewall for WordPress. Stop malware, redirects, back-doors and account takeover. 100% bot blocking, backups, malware cleaner.
 * Version:           4.4.14
 * Author:            BitFire.co
 * License:           AGPL-3.0+
 * License URI:       https://www.gnu.org/licenses/agpl-3.0.en.html
 * Text Domain:       BitFire-Security
 * Domain Path:       /bitfire
 */

namespace BitFirePlugin;

use BitFire\BitFire;
use BitFire\Config as CFG;
use BitFire\Request;
use Exception;
use RuntimeException;
use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFin\Hash_Config;

use const BitFire\BITFIRE_VER;
use const BitFire\CONFIG_REQUIRE_BROWSER;
use const BitFire\CONFIG_USER_TRACK_COOKIE;
use const BitFire\FILE_W;
use const BitFire\REQ_USER_LIST;
use const BitFire\STATUS_EACCES;
use const BitFire\WAF_ROOT;
use const BitFire\WAF_SRC;
use const ThreadFin\ENCODE_RAW;

use function BitFire\block_now;
use function BitFire\Data\ip4_pos_to_loc;
use function BitFire\Data\ip4_to_uni;
use function BitFire\Data\ip4_uni_to_pos;
use function BitFire\is_admin;
use function BitFire\set_cookie;
use function BitFire\status_code;
use function BitFireBot\send_browser_verification;
use function BitFirePRO\wp_requirement_check;
use function BitFireSvr\doc_root;
use function BitFireSvr\update_ini_value;
use function ThreadFin\contains;
use function ThreadFin\cookie;
use function ThreadFin\dbg;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\partial_right as ƒixr;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\en_json;
use function ThreadFin\file_recurse;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\icontains;
use function ThreadFin\ip_to_country;
use function ThreadFin\parse_ini;
use function ThreadFin\random_str;
use function ThreadFin\render_file;
use function ThreadFin\un_json;

// If this file is called directly, abort.
if ( ! defined( "WPINC" ) ) { die(); }


/**
 * Begins BitFire firewall, respects bitfire_enabled flag in config.ini
 * We might have already run the firewall if we are auto_prepend, so
 * check if we have loaded and do not double load.  This check
 * is also done in startup.php as a failsafe
 * @since    1.8.0
 */
if (!defined("\BitFire\WAF_ROOT") && !function_exists("\BitFire\on_err")) {
    $f =  __DIR__ . "/startup.php";
    if (file_exists($f)) {
        include_once $f;
    } else {
        return;
    }
    if (function_exists("\ThreadFin\\trace")) {
        trace("wp");
    } else {
        return;
    }
}




/**
 * The code that runs during plugin activation.
 * enable the firewall enable option, and install always on protection
 * on second activation (this is by design and based on "configured" flag)
 * TODO: move this code to -admin
 */
function activate_bitfire() {
    trace("wp_act");

    // make sure the config loader has run
    $config = parse_ini();
    // monitor any errors
    ob_start(function($x) { if(!empty($x)) {
        debug("PHP Warnings: [%s]\n", $x); }
        return $x;
    });

    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    include_once \plugin_dir_path(__FILE__) . "src/server.php";

    $file_name = ini_get("auto_prepend_file");
    if (contains($file_name, "bitfire")) {
        $base_dir = realpath(dirname($file_name));
        CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
        \BitFireSvr\uninstall()->run();
        sleep(1);
        \BitFireSvr\update_ini_value("rm_bitfire", $base_dir)->hide_output()->run();
    } else {
        \BitFireSvr\update_ini_value("rm_bitfire", "")->hide_output()->run();
    }


    // activate BitFire
    \BitfireSvr\bf_activation_effect()->hide_output()->run();

    // run the upgrade function if we have one
    if (function_exists("BitFireSvr\upgrade")) {
        \BitFireSvr\upgrade();
    }
    // TODO: move config data here ...
    if (defined('WP_CONTENT_DIR') && file_exists('WP_CONTENT_DIR')) {
        mkdir(WP_CONTENT_DIR . "/bitfire", 0775, false);
    }

    // install data can be verbose, so redirect to install log
    CFG::set_value("debug_file", false); 
    CFG::set_value("debug_header", false);
    ob_end_clean();

    debug(trace());
}




/**
 * The code that runs during plugin deactivation.
 * toggle the firewall enable option, uninstall
 * TODO: move this code to -admin
 */
function deactivate_bitfire() {
    trace("deactivate");
    // install data can be verbose, so redirect to install log
    CFG::set_value("debug_file", true);
    CFG::set_value("debug_header", false);
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    \BitFireSvr\bf_deactivation_effect()->hide_output()->run();
    debug(trace());
}

// wrapper for wordpress get_inline_script_tag
function bf_script_tag(string $content) : string  {
    if (function_exists('wp_get_inline_script_tag')) {
        return wp_get_inline_script_tag($content);
    }

    return "<script>$content</script>";
}




// we must do this here because by the time bitfire-admin.php loads, content has already been
// rendered.  Don't want to introduce dependency on WordPress with admin-ajax.php calls
function bitfire_init() {

    add_action("wp_enqueue_scripts", function() {
        \wp_register_script("bitfire", plugins_url('/public/bitfire_core.js', __FILE__), [], BITFIRE_VER, false);
        \wp_enqueue_script("bitfire", plugins_url('/public/bitfire_core.js', __FILE__), [], BITFIRE_VER, false);
    });

    $s1 = hrtime(true);
    if (is_user_logged_in()) {
        trace("login");
        include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    }
    $ins = BitFire::get_instance();
    $ins->inspect();

    add_action('shutdown', [$ins, 'shutdown'], 0);

    // attempt to remove ?author= location redirect headers, in case we were not able to 
    // block the request before WordPress added the redirect header...
    // todo: find the handler for ?author links and remove it
    if ($ins->_request->classification & REQ_USER_LIST) {
        add_action('template_redirect', function($x) { header_remove('Location'); } );
    }
 
    if (CFG::enabled('require_full_browser')) {

        if (contains($ins->_request->path, "wp-login.php")) {

            // if the login page is requested and not validated, send the verification script
            if ($ins->ip_data->valid < 1) {
                if (defined('\BitFire\DOCUMENT_WRAP')) {
                    send_browser_verification($ins->_request, $ins->agent, true, false)->run();
                } else {
                    $verify_effect = send_browser_verification($ins->_request, $ins->agent, false, true);
                    // add the verification script to the login page.  even if someone lands
                    // on the login page, we want to make sure they are verified
                    add_action("login_header", function() use ($verify_effect) {
                        echo "<script>" . $verify_effect->read_out() . "</script>\n";
                    });
                }
            }

        } else {

            $verify_effect = send_browser_verification($ins->_request, $ins->agent, false, true);

            // add human detection, admin and frontend are hooked differently
            if (icontains($_SERVER['REQUEST_URI'], "/wp-admin/") && !contains($_SERVER['REQUEST_URI'], 'admin-ajax.php')) {
                add_action('admin_head', function() use ($verify_effect) {
                    echo "<script>".$verify_effect->read_out()."</script>\n";
                }, 1);
            } else {
                add_action('wp_head', function() use ($verify_effect) {
                    wp_add_inline_script("bitfire", $verify_effect->read_out(), "after");
                }, 1);
            }

        }
 
    }



    // make sure we update the cookie!
    /*
    else {
        if ($cookie->is_admin || $cookie->logged_in) {
            $cookie->is_admin = false;
            $cookie->logged_in = false;
            $cookie->unfiltered_html = false;
        }
    }
    // update the cookie if it has changed
    if ($cookie->is_dirty()) {
        die("DIRTY!");
        cookie('_bitf', $cookie->to_cookie());
    }
    */

    // TODO: move this to -admin
    if (CFG::enabled("pro_mfa") && function_exists("\BitFirePRO\sms")) {
        // mfa field display
        //add_action('show_user_profile', '\BitFirePlugin\mfa_field');
        //add_action('edit_user_profile', '\BitFirePlugin\mfa_field');
        // mfa field update
        //add_action("edit_user_profile_update", "\BitFirePlugin\user_edit");
        //add_action("personal_options_update", "\BitFirePlugin\user_edit");
        //add_action("user_register", "\BitFirePlugin\user_add");
    }

    // we want to run API function calls here AFTER loading.
    // this ensures that all overrides are loaded before we run the API
    // TODO: remove this code.  this is run in ->inspect()
    /*
    if (isset($_REQUEST[\BitFire\BITFIRE_COMMAND])) {
        trace("wp_api");
        require_once \BitFire\WAF_SRC."server.php";
        require_once \BitFire\WAF_SRC."api.php";
        $request = BitFire::get_instance()->_request;
        \BitFire\api_call($request)->exit(true)->run();
    }
    */

    // MFA authentication, but only on the login page
    $path     = $ins->_request->path;
    if (contains($path, "wp-login.php")) {
        // XXX ADD MFA HERE
        //add_filter( 'authenticate', 'BitFirePlugin\authenticate', 1, 3 );
    }

    /*
    if (function_exists('BitFirePRO\wp_user_login')) {
        die("user login");
        add_action("wp_login", "\BitFirePRO\wp_user_login", 60, 1);
    }
    */

    $GLOBALS['bf_t1'] += ((hrtime(true) - $s1) / 1e+6);
}

function authenticate( $user, $username, $password ) {

    if (empty($username)) { return; }
    $login_type = (stripos($username, '@') !== false) ? 'email' : 'login';
	$user = get_user_by($login_type, $username );
    // no user, just do the default thing...
    if (empty($user)) { return; }

    $ip = $_SERVER[CFG::str_up("ip_header", "REMOTE_ADDR")] ?? $_SERVER["REMOTE_ADDR"] ?? "127.0.0.1";
    $dir = get_hidden_file("");

    $data = ["result" => "waiting", "time" => time(), "auth" => random_str(32)];
    $file_name = "";

    // todo: check timestamp here...
    file_recurse($dir, function($file) use ($ip, &$file_name) {
        if (strpos($file, $ip) !== false) {
            $file_name = $file;
        }
    });
    
    if (!empty($file_name)) {
        $raw = file_get_contents($file_name);
        $saved = un_json($raw);
        $data = (!empty($saved)) ? $saved : $data;
        $info_file = $file_name;
    } else {
        $info_file = get_hidden_file($data['auth'] . "_{$ip}.auth");
    }

    // now we can do the normal login process...
    if ($data['result'] == 'passed') {
        unlink($info_file);
        cookie("bf_2fa", "pass", 0);
        return $user;
    }

    $data["result"] = "waiting";
    $data["time"] = time();

    file_put_contents($info_file, en_json($data), LOCK_EX);


    $body = "waiting...  [$info_file]
    <form method='POST' id='login'>
    <input name='log' value='$username' type='hidden'>
    <input name='pwd' value='$password' type='hidden'>
    </form>

    <script>
    const es = new EventSource('/wp-content/plugins/bitfire/verify.php', {
        withCredentials: false,
    });
    console.log('event 0...');
    console.log(es);
    window.COUNTER = 0;
    window.STATUS = 'waiting';
    console.log('event 1...');

    var listener = function (event) {

        if (event) {
            if (event.lastEventId) {
                document.getElementById('status').innerText = event.lastEventId;
                if (event.data) {
                    if (event.data.trim() == 'passed') {
                        window.STATUS = 'passed';
                        // alert('AUTHENTICATED');
                        document.getElementById('login').submit();
                        //window.location = 'https://wordpress.bitfire.co/wp-content/plugins/bitfire/verify.php?authenticated';
                    }
                }
            }
        }
    }
    
    /*
    es.onmessage = (event) => {
        console.log('event hit!');
        window.COUNTER += 1;
        console.log(event, window.COUNTER);
        if (event.data == 'waiting') {
            document.getElementById('status').innerText = event.lastEventId;
            return;
        }
        else if (event.data == 'passed') {
            alert('authenticated');
            window.location = 'https://wordpress.bitfire.co/wp-content/plugins/bitfire/verify.php?authenticated';
        }
    };
    es.onerror = (event) => {
        console.log('event error', event);
    };
    */

    es.addEventListener('open', listener);
    es.addEventListener('message', listener);
    //es.addEventListener('error', function(err) { console.log('error', err); console.log('es', es); if (window.STATUS == 'passed') { es.close(); } });
    console.log('polling...');
    


    </script>
    \n";
    $vars = ['custom_css' => "", "header" => "<h1>waiting...</h1>", "title" => "please approve the login via email", "body" => $body, "api_code" => random_str(24)];

    require_once WAF_SRC . "renderer.php";
    $content = render_file(WAF_ROOT . "views/content.html", $vars);
    die($content);
}




/**
 * action called on word press login
 * @since 1.9.2
 * @param string $username 
 * @return void 
 */
function wp_user_login(?string $username) {
    if (!$username) { return; }
    $user = get_user_by("login", $username);
    if (!$user) { return; }

    /*
    $phone = get_user_meta($user->ID, "bitfire_mfa_tel", true);
    $code = get_user_meta($user->ID, "bitfire_mfa_code", true);
    $sent = intval(get_user_meta($user->ID, "bitfire_mfa_sent", true)||0);
    $correct = intval(get_user_meta($user->ID, "bitfire_mfa_correct", true)||0);
    */
    // no phone number on record, we just just login as normal
}


/**
 * update last login time info
 * @param mixed $check 
 * @param mixed $password 
 * @param mixed $hash 
 * @param mixed $user_id 
 * @return void 
 * @throws RuntimeException 
 */
function user_key_verify($user, $username, $password) {

    // user has successfully logged in, create a new key display the waiting page and wait for the user to verify
    if ( $user instanceof \WP_User ) {

        $ip = $_SERVER[CFG::str_up("ip_header", "REMOTE_ADDR")] ?? $_SERVER["REMOTE_ADDR"] ?? "127.0.0.1";
        $dir = get_hidden_file("");
        $file_name = get_hidden_file(random_str(24) . ".$ip.json"); // default to a new random file name
        file_recurse($dir, function($file) use ($ip, &$file_name) {
            if (strpos($file, $ip) !== false) {
                $file_name = $file;
            }
        });

        $secret_file = $file_name;


        $uni = ip4_to_uni($ip);
        $long_names = json_decode(file_get_contents(WAF_ROOT . "data/country_name.json"), true);
        $loc = ip4_pos_to_loc(ip4_uni_to_pos($uni), $long_names);
        $agent = BitFire::get_instance()->agent;
        $key2 = random_str(24);
        $data = ["ip" => $ip, "user_id" => $user->ID, "agent" => $agent, "loc" => $loc, "key" => $key2, "pass" => false];
        $encode_data = en_json($data);
        file_put_contents($secret_file, $encode_data, LOCK_EX);

        // TODO: display the waiting page here with key1
        $page = WAF_ROOT . "views/verify_login.html";
        include $page;
	}
    return $user;
}

/**
 * Add CSP Policy nonce if enabled
 * @param string $nonce 
 * @param null|string $script_tag 
 * @return string 
 */
function add_nonce(string $nonce, ?string $script_tag) : string {
    assert(!empty($script_tag), "cant add nonce to empty script tag");
    // only add the nonce if we don't have one
    if (!contains($script_tag, "nonce=")) {
        return preg_replace("/(id\s*=\s*[\"'].*?[\"'])/", "$1 nonce='$nonce'", $script_tag);
    }
    return $script_tag;
}
/**
 * wp_script_attribute filter for adding nonces.
 * TODO: add integrity check.  Needs an API callback to automatically store the hash integrity
 * @param string $nonce - the per page generated nonce
 * @param array $attributes the script attributes
 * @return array 
 */
function add_nonce_attr(string $nonce, array $attributes) : array {
    $attributes["nonce"] = $nonce;
    return $attributes;
}




/**
 * BEGIN MAIN PLUGIN CODE
 */

// plugin run once wordpress is loaded
// TODO: this should not be run AFTER wp_loaded, only things that have dep on wp_loaded
\add_action("wp_loaded", "BitFirePlugin\bitfire_init");
// update logout function to remove our cookie as well
\add_action("wp_logout", function() { \ThreadFin\cookie("_bitf", null, -1); });
// keep the db transaction log up to date for differential database backups

// make sure authentication is not bypassed
if (function_exists('BitFirePRO\\verify_user_id') && CFG::enabled("rasp_auth")) {
    add_action("auth_cookie_valid", "BitFirePRO\\verify_user_id", 9, 2); 
    add_filter("determine_current_user", "BitFirePRO\\verify_user_id", 65535, 1); 
    add_action("application_password_did_authenticate", "BitFirePRO\\verify_user_id", 65535, 1); 
}



// include the admin code only if we are in the admin section
if (icontains($_SERVER['REQUEST_URI'], "/wp-admin/") && !contains($_SERVER['REQUEST_URI'], 'admin-ajax.php')) {
    include_once __DIR__ . "/bitfire-admin.php";
}

// don't run any protection functions if disabled...
if (!CFG::enabled('bitfire_enabled')) {
    return;
}






// always record the http status code
add_filter('status_header', function($header, $code) { status_code($code); }, 9999, 2);
 
/* user behavior identification
if (CFG::enabled("web_monitor") && stripos($_GET['ii']??"", "M") == false) {
    \wp_register_script("bitfire_monitor", plugin_dir_url(__FILE__) . "public/monitor.js", ["jquery"], "1.0", true);
    \wp_enqueue_script('bitfire_monitor",  plugin_dir_url(__FILE__) . "public/monitor.js", "1.0", false);
}
*/




if (CFG::enabled("rasp_db") && function_exists("\BitFirePRO\query_filter")) {
    \add_filter("query", "BitFirePRO\query_filter");
}

// disable xmlrpc
if (CFG::enabled("block_xmlrpc", false)) {
    remove_action('wp_head', 'rsd_link');
    remove_action('wp_head', 'rest_output_link_wp_head');
    remove_action('wp_head', 'wp_oembed_add_discovery_links');
}

// require authentication for all REST API requests
/*
if (CFG::enabled("rest_auth", true)) {
    add_filter( 'rest_authentication_errors', function( $result ) {
        // just return existing errors
        if (\is_wp_error($result) || $result == true) {
            return $result;
        }

        // require authentication for ALL REST API requests
        if (!is_user_logged_in()) {
            return new \WP_Error('rest_not_logged_in', __( 'You are not currently logged in.' ), array( 'status' => 403));
        }

        // no action, allow the request
        return $result;
    });
}
*/

if (CFG::enabled("csp_policy_enabled")) {
    $nonce = CFG::str("csp_nonce", 'nonce-error');
    // script nonces. Prefer new attribute style for >= 5.7
    if (version_compare($GLOBALS["wp_version"]??"4.0", "5.7") >= 0) {
        add_filter("wp_script_attributes", ƒixl("\BitFirePlugin\add_nonce_attr", $nonce));
        add_filter("wp_inline_script_attributes", ƒixl("\BitFirePlugin\add_nonce_attr", $nonce));
    }
}

// make sure important WordPress calls are legitimate 
// TODO: improve this by integrating to the main inspection engine
if (function_exists('BitFirePRO\wp_requirement_check') && !wp_requirement_check()) {
    $request = $ins->_request;

    block_now(31001, "referer", $request->referer, "new-user.php", 0)->run();
}


// keep the config file synced with the current WordPress install
if (mt_rand(1,10) == 50) {
    if (CFG::str("cms_root") != ABSPATH) { 
        require_once WAF_SRC . "server.php";
        update_ini_value("cms_root", ABSPATH)->run();
    }
    if (defined("WP_CONTENT_DIR") && CFG::str("cms_content_dir") != WP_CONTENT_DIR) {
        require_once WAF_SRC . "server.php";
        update_ini_value("cms_content_dir", WP_CONTENT_DIR)->run();
    }
    // TODO: don't parse protocol here...
    if (CFG::str("cms_content_url") != content_url()) {
        $u1 = parse_url(CFG::str("cms_content_url"));
        $u2 = parse_url(content_url());
        // don't flip the content url on protocol changes...
        if ($u1['scheme'] == $u2['scheme'] &&$u1['scheme'] != 'https') {
            require_once WAF_SRC . "server.php";
            update_ini_value("cms_content_url", content_url())->run();
        }
    }
    if (CFG::str("wp_version") != get_bloginfo('version')) {
        require_once WAF_SRC . "server.php";
        update_ini_value("wp_version", get_bloginfo('version'))->run();
    }
}


// make sure authentication is not bypassed
if (function_exists('BitFirePRO\\verify_user_id') && CFG::enabled("rasp_auth")) {
    add_action("auth_cookie_valid", "BitFirePRO\\verify_user_id", 9, 2);
    add_filter("determine_current_user", "BitFirePRO\\verify_user_id", 65535, 1);
    add_action("application_password_did_authenticate", "BitFirePRO\\verify_user_id", 65535, 1);
}

