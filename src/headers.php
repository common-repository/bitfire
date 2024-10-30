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

namespace BitFireHeader;

use BitFire\UserAgent;
use BitFire\Config as CFG;
use ThreadFin\CacheItem;
use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileData;

use const BitFire\CACHE_HIGH;
use const BitFire\FAIL_ENUMERATION;
use const BitFire\FAIL_SSL_UPGRADE;
use const ThreadFin\DAY;

use function BitFire\flatten;
use function ThreadFin\contains;
use function ThreadFin\cookie;
use function ThreadFin\ends_with;
use function ThreadFin\ƒ_id;
use function ThreadFin\ƒ_inc;
use function ThreadFin\trace;
use function ThreadFin\partial as ƒixl;

const FEATURE_POLICY = array('accelerometer' => 'self', 'ambient-light-sensor' => 'self', 'autoplay' => 'self', 'camera' => 'self', 'geolocation' => '*', 'midi' => 'self', 'notifications' => 'self', 'push' => 'self', 'sync-xhr' => 'self', 'microphone' => 'self', 'gyroscope' => 'self', 'speaker' => 'self', 'vibrate' => 'self', 'fullscreen' => 'self', 'payment' => '*');
const FEATURE_NAMES = array('geolocation', 'midi', 'notifications', 'push', 'sync-xhr', 'microphone', 'gyroscope', 'speaker', 'vibrate', 'fullscreen', 'payment');

const CSP = array('child-src', 'connect-src', 'default-src', 'font-src',
            'frame-src', 'img-src', 'manifest-src', 'media-src', 'object-src', 'prefetch-src',
            'script-src', 'style-src', 'style-src-elem', 'script-src-attr', 'style-src', 
            'style-src-elem', 'style-src-attr', 'worker-src');




// block plugin enumeration.  Do not call if user is a WP admin...
function block_plugin_enumeration(\BitFire\Request $request) : Effect {
    $pass_effect = Effect::new();

    // if we are not configured to block plugin scans, just return
    if (!CFG::enabled("wp_block_scanners")) { return $pass_effect; }

    $filename = basename(strtolower($request->path));
    $file_list = ["readme.txt", "license.txt"];


    # request for a plugin/theme file that does not exist
    if (preg_match("/wp-content\/plugins\/[a-zA-Z0-9_-]+\/(.*)/i", $request->path, $matches) ||
        preg_match("/wp-content\/themes\/[a-zA-Z0-9_-]+\/(.*)/i", $request->path, $matches)) {

        // select random response type
        $path = trim($matches[1]??"");
        $results = [404, 403, 200];
        $result = $results[array_rand($results)];
        $version = random_int(1, 5) .".". random_int(1, 9) ."." . random_int(1,9);

        // force head/post methods to return 403, nginx default behavior
        if ($request->method == "HEAD" || $request->method == "POST") {
            $result = 403;
        }


        // plugin version check
        if (in_array($filename, $file_list) || ends_with($filename, ".css") || empty($path)) {
            // read the file for the response (404, 403, 200)
            $file = FileData::new(\BitFire\WAF_ROOT."/views/nginx.$result.html")->read();
            $content = $file->apply_ln(ƒixl("str_replace", "__VERSION__", $version))->raw();
            // create an effect to send the response
            $stat_id = floor(FAIL_ENUMERATION / 1000);
            $pass_effect
                ->exit(true)
                ->header("Content-Length", strlen($content))
                ->update(new CacheItem("STATS_$stat_id", \Threadfin\ƒ_inc(1), \Threadfin\ƒ_id(0), DAY * 14, CACHE_HIGH))
                ->response_code($result);
            // don't output data for the HEAD method
            if ($request->method != "HEAD") {
                $pass_effect->out($content);
            }
        }
    }

    return $pass_effect;
}


/**
 * add the security headers from config
 */
function send_security_headers(\BitFire\Request $request, UserAgent $agent) : Effect {
    // GUARD, should never be hit
	if (headers_sent() || php_sapi_name() == "cli") { trace("HDR_SENT"); return Effect::new(); }
    trace("HDR");

    $effect = Effect::new();
    if (\Bitfire\Config::enabled("security_headers_enabled")) {
        $effect->chain(core_headers($agent));
    }

    // device permission policy
    if (CFG::enabled('permission_policy')) {
        $effect->header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    }

    // cross origin resource policy
    $policy = CFG::str("cor_policy", "");
    if (!empty($policy)) {
        if (in_array($policy, ["same-site", "same-origin", "cross-origin"])) {
            $effect->header("Cross-Origin-Resource-Policy", $policy);
        }
    }

    // set strict transport security (HSTS)
    if (\Bitfire\Config::enabled("enforce_ssl_1year")) {
        $effect->chain(force_ssl_with_sts());
    }

    // content security policy
    if (\Bitfire\Config::enabled("csp_policy_enabled") && !contains($request->path, "/wp-admin")) {
        $effect = csp_headers($request, $effect);
    }
 
    return $effect;
}

/**
 * create an effect to set http security headers
 * @param UserAgent $agent 
 * @return Effect 
 */
function core_headers(?UserAgent $agent) : Effect {
    // seems excessive to add effect support for removing headers
    header_remove('X-Powered-By');
    header_remove('Server');

    $effect = Effect::new();

    $effect->header("X-Frame-Options", "sameorigin");
    $effect->header("X-Content-Type-Options", "nosniff");
    $effect->header("Referrer-Policy", "strict-origin-when-cross-origin");

    // only turn on the XSS auditor for older browsers
    if ($agent) {
        if (($agent->browser_name == "chrome" && version_compare($agent->ver, "78.0") < 0)
            || ($agent->browser_name == "edge" && version_compare($agent->ver, "17.0") < 0)
            || ($agent->browser_name == "explorer") || ($agent->browser_name == "safari")) {

            
            $effect->header("X-XSS-Protection", ": 1; mode=block");
            trace("oldbr");
        }
    }

    // block for php-sploit framework here, exit with a server error code...
    if ($_SERVER['HTTP_ACCEPT_ENCODING']??'' == "identity") {
        foreach ($_SERVER as $key => $value) {
            if (!is_string($value)) {
                $value = flatten($value);
            }
            if (!empty($value) && stripos($value, "eval(base64_decode") !== false) {
                \BitFire\block_now(16050, $key, $value, 'eval(base64_', CFG::int("block_medium_time", 3600))->run();
            }
        }
    }

    return $effect;
}

/**
 * force redirect to https and enable STS
 * @return Effect 
 */
function force_ssl_with_sts() : Effect {
    $effect = Effect::new();
    $effect->header('Strict-Transport-Security', 'max-age=31536000; preload');
    // find the request scheme (ssl/tls?)
    $scheme = ($_SERVER['HTTP_X_FORWARDED_PROTO']??$_SERVER['HTTP_X_FORWARDED_PROTOCOL']??$_SERVER['HTTP_X_URL_SCHEME']??$_SERVER['REQUEST_SCHEME']??'http');
    // force encryption
    if ($scheme === 'http') {
        if ((empty($_SERVER['HTTPS']) || strtolower($_SERVER['HTTPS']) != 'on') &&
            strtolower($_SERVER['HTTP_X_FORWARDED_SSL']??"") != 'on') {

            // Don't double redirect HTTPS!
            if (!isset($_COOKIE['x-bf-ssl'])) {
                $cache = CacheStorage::get_instance();
                $key_id = floor(FAIL_SSL_UPGRADE / 1000);
                $cache->update_data("STATS_$key_id", ƒ_inc(1), ƒ_id(0), 86400*14, CACHE_HIGH);

                $host = filter_input(INPUT_SERVER, 'HTTP_HOST', FILTER_SANITIZE_URL);
                $uri = filter_input(INPUT_SERVER, 'REQUEST_URI', FILTER_SANITIZE_URL);
                $effect->header('Location', "https://{$host}{$uri}");
                $effect>cookie('x-bf-ssl', '1', 0);
                $effect->exit(true);
            }
        }
    }

    return $effect;
}

// content security policy
function csp_headers(\BitFire\Request $request, \ThreadFin\Effect $effect) : \ThreadFin\Effect
{

    // set a default feature policy
    if (CFG::enabled("csp_policy_enabled") && !contains($request->path, "/wp-admin")) {
        \ThreadFin\trace("csp");
        $report_only = CFG::int("csp_enable_time", 0) > time();

        $header_name = $report_only ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";

        // map the config csp to a more usable KVP format
        $policy = [];
        foreach(\BitFire\Config::arr("csp_policy") as $policy_name => $value) {
            $policy[$policy_name] = $value;
        }

        // transform the policy to a string
        $nonce = \ThreadFin\random_str(16);
        CFG::set_value("csp_nonce", $nonce);

        $csp = \ThreadFin\map_reduce($policy, function($key, $value, $carry) use ($nonce, $request) {
            // skip empty policies
            if (empty($value)) { return $carry; }
            // concat the key and value, add nonce to script-src only
            $fixed_value = $value;
            if ($key === "default-src") {
                $fixed_value .= " 'nonce-$nonce' ";
                $fixed_value .= (contains($request->path, "wp-admin") || CFG::enabled("csp_inline", false)) ? " 'unsafe-inline'" : "";
            }
            return "$carry $key $fixed_value; "; 
        }, !$report_only ? "upgrade-insecure-requests; " : " ");

        $effect->header($header_name, $csp);
    }

    return $effect;
}


 