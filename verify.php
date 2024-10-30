<?php

use ThreadFin\CacheItem;
use ThreadFin\Effect;

use function BitFire\parse_agent;
use function BitFire\process_ip;
use function BitFireSvr\update_common_params;
use function ThreadFin\en_json;
use function ThreadFin\file_recurse;
use function ThreadFin\get_hidden_file;
use function ThreadFin\parse_ini;
use function ThreadFin\random_str;
use function ThreadFin\validate_raw;
use function ThreadFin\ƒ_id;
use function ThreadFin\ƒ_inc;

use BitFire\BrowserState;
use BitFire\Config as CFG;
use ThreadFin\CacheStorage;
use ThreadFin\FileData;
use ThreadFin\Hash_Config;

use const BitFire\BOT_VALID_JS;
use const BitFire\CACHE_HIGH;
use const BitFire\CACHE_LOW;
use const BitFire\CACHE_STALE_OK;
use const BitFire\COMMON_PARAMS;
use const BitFire\EVIL_PARAMS;
use const ThreadFin\ENCODE_RAW;
use const ThreadFin\HOUR;

if (!defined('BitFire\WAF_ROOT')) {
    define('BitFire\WAF_ROOT', realpath(__DIR__) . DIRECTORY_SEPARATOR);
    define('BitFire\BLOCK_DIR', \BitFire\WAF_ROOT . 'blocks');
    define('BitFire\WAF_SRC', \BitFire\WAF_ROOT . 'src' . DIRECTORY_SEPARATOR);
    define('BitFire\TYPE', 'WORDPRESS');
    define('ThreadFin\view\VIEW_ROOT', \BitFire\WAF_ROOT . "views");
}

// error handler registers shutdown function (log_it) and fatal error handler
require_once \BitFire\WAF_SRC . 'const.php';
require_once \BitFire\WAF_SRC . 'util.php';
require_once \BitFire\WAF_SRC . 'bitfire_pure.php';
require_once \BitFire\WAF_SRC . 'storage.php';
require_once \BitFire\WAF_SRC . 'bitfire.php';
require_once \BitFire\WAF_SRC . 'botfilter.php';
require_once \BitFire\WAF_SRC . "server.php";



// handle the verification request / answer
$json_str = file_get_contents('php://input');
CFG::set(parse_ini());
$remote_ip = process_ip($_SERVER);

if (!empty($json_str)) {
    $data = json_decode($json_str, true);
    require_once \BitFire\WAF_SRC . 'botfilter.php';


    $agent = parse_agent($_SERVER['HTTP_USER_AGENT'], $_SERVER['HTTP_ACCEPT_ENCODING']??'');
    BrowserState::$do_not_create = true;
    $effect = Effect::new()->out('verification failed')->exit(true);

    $config = new Hash_Config('sha256', 86400 * 7, 24);

    // correct answer, client side state
    if (isset($data['_bfa'])) {
        $parts = explode('.', $data['_bfa']);
        $pass = validate_raw($parts[0], $parts[1], $parts[2], CFG::str("secret"), $config);

        if ($pass) {
            // set cookie and ip data to verified

            // set ip data
            $effect->update(new CacheItem(
                'IP_' . $remote_ip,
                function ($ip_data) {
                    $ip_data->valid = BOT_VALID_JS;
                    $ip_data->browser_state = BrowserState::JS | BrowserState::VERIFIED;
                    return $ip_data;
                },
                function () use ($remote_ip, $agent) {
                    return \BitFire\new_ip_data($remote_ip, $agent, BrowserState::JS | BrowserState::VERIFIED);
                }, HOUR, CACHE_LOW | CACHE_STALE_OK
            ));
            // set cookie
            //$effect->cookie($state->to_cookie(), 'verified_state');
            $effect->cookie('3', 'verified_state');
            $effect->out("verified", ENCODE_RAW, true);

            $learning = (CFG::int('dynamic_exceptions') > time());
            $cache = CacheStorage::get_instance();
            $cache->update_data("STAT_19", ƒ_inc(1), ƒ_id(0), 86400*14, CACHE_HIGH);

            unset($_GET['_bfa']);
            update_common_params($_GET, $remote_ip, $learning);
        } else {
            setcookie('_bff', '1');
        }
    }

    $effect->run();
    exit();
}


$hidden_dir = get_hidden_file("");

$key = (isset($_GET['authenticate'])) ? substr($_GET['authenticate'] . random_str(32), 0, 32) : $remote_ip;

// file format is auth-string_ip.auth
$file_names = file_recurse($hidden_dir, function($file) use ($key) {
    return (strpos($file, $key) !== false) ? $file : "";
});

$file_name = $file_names[0]??"";



// no auth file for this IP
if (empty($file_name)) {
    if (isset($_GET['authenticate'])) {
        die("invalid authentication");
    }
    die("no auth file!");
}


// perform the authentication
if (isset($_GET['authenticate'])) {
    $raw = file_get_contents($file_name);
    if (!empty($raw)) {
        $data = json_decode($raw, true);
        if (!empty($data)) {
            $data['result'] = 'passed';
            file_put_contents($file_name, en_json($data), LOCK_EX);
            die("authenticated, you may now close this window...\n");
        } else {
            die("server data corrupted, please re-login.\n");
        }
    }
    die("server data not found, please re-login.\n");
}


$info_file = $file_name;


// just in case...
session_start();
session_write_close();
ignore_user_abort();



header('Content-Type: text/event-stream');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: no-store');
header('Connection: keep-alive');
header("X-FILE: $info_file");


echo ":" . str_repeat(" ", 2048) . "\n"; // 2 kB padding for IE
echo "retry: 0\n";
echo "event: ping\n";

// wait up to 1.5 minutes
$ctr = 0;
while($ctr++ < 90) { 
    $time = time();

    // file_put_contents("/tmp/log.txt", "RESULT: $result\n", FILE_APPEND);

    $result = "waiting";
    $raw = file_get_contents($info_file);
    if (!empty($raw)) {
        $data = json_decode($raw, true);
        $data['file'] = $file_name;
        if (!empty($data)) {
            $result = $data['result']??'failed';
        }
    }

    /*
    if (random_int(1,5) == 3) {
        $result = "pass";
        $data['result'] = $result;
        file_put_contents($info_file, en_json($data), LOCK_EX);
    }
    */
    
    //echo "event: status\n";
    echo "id: ". time() . "\n";
    echo "data: $result\n\n";
    ob_flush();
    flush();

    if (connection_aborted()) {
        break;
    }

    sleep(1);
    if ($data['result'] == "passed") {
        exit();
    }
}


$time = time();
$result = "timeout";
echo "id: $time\ndata: $timeout\n\n";
ob_flush();
flush();