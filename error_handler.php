<?php
namespace BitFire;

use function BitFireSvr\update_ini_value;
use function ThreadFin\trace;
use function ThreadFin\debug;
use BitFire\Config as CFG;

/**
 * set the default error handler while running bitfire 
 * @return bool 
 */
function on_err($errno, $errstr, $err_file, $err_line, $context = null): bool {
    static $double_err = false;
    static $to_send    = [];
    if ($double_err) { return false; }
    $double_err        = true;

    // send any errors that have been queued, errno -99 is called in shutdown handler
    if ($errno < -99) {

        array_walk($to_send, function ($data) {
            if (!has_been_sent($data)) {
                if (function_exists('ThreadFin\debug')) {
                    $data['debug'] = debug(null);
                    $data['trace'] = trace(null);
                }

                $msg = sprintf("host=%s&file=%s&line=%s&errno=%s&errstr=%s&phpver=%s&type=%s&ver=%s&bt=%s", 
                    urlencode($_SERVER['HTTP_HOST']??'local'), urlencode($data['err_file']), urlencode($data['err_line']), urlencode($data['errno']),
                    urlencode($data['errstr']), urlencode($data['php_ver']), urlencode($data['type']), urlencode($data['ver']), urlencode(json_encode($data['bt'])));
                // don't send errors from the error handler (this could cause endless loop)
                if (stripos($msg, 'error_handler') !== false) {
                    return;
                }

                $url = (INFO . "err.php?ver=".BITFIRE_VER."&$msg");
                // file_get_contents is simpler or better portability
                if (ini_get("allow_url_fopen") == 1) {
                    file_get_contents($url);
                }
                // trivial curl fallback
                else if (function_exists('curl_init')) {
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_exec($ch);
                    curl_close($ch);
                }
            }
        });
        return $double_err = false;
    }

    $data = [
        'ver' => BITFIRE_VER,
        'type' => \BitFire\TYPE,
        'errno' => $errno,
        'errstr' => $errstr,
        'err_file' => $err_file,
        'err_line' => $err_line,
        'php_ver' => phpversion(),
    ];

    // if enabled, notify bitfire that an error occurred in the codebase
    if (class_exists('Bitfire\Config') && CFG::enabled('send_errors', true)) {
        $data['bt'] = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        $to_send[] = $data;
    }

    return $double_err = false;
}

/**
 * check if we have already sent this error. if not, write to the error sent file
 * @param array $data 
 * @return bool 
 */
function has_been_sent(array $data) : bool {

    static $known = null;
    $err_file = \BitFire\WAF_ROOT . 'data/errors.json';

    // check if we have already sent this error. 
    if ($known === null) {
        if (!file_exists($err_file)) {
            touch($err_file);
        }
        $known = json_decode(file_get_contents($err_file), true);
        if (empty($known)) { return false; }
    }

    foreach ($known as $err) {
        if ($err['errno'] == $data['errno'] &&
            $err['err_line'] == $data['err_line'] &&
            $err['err_file'] == $data['err_file']) {
                return true;
            }
    }

    // write error data if we have not seen this error before
    $known[] = $data;
    if (file_exists($err_file) && is_writable($err_file)) {
        @file_put_contents($err_file, json_encode($known, JSON_PRETTY_PRINT), LOCK_EX);
    }

    return false;
}

// capture any bitfire fatal errors
// send any errors that have been queued after the page has been served
register_shutdown_function(function () {

    $s1 = hrtime(true);
    // make sure data is always logged
    if (!isset($_GET['BITFIRE_API']) && class_exists('\BitFire\Config') && Config::enabled(CONFIG_ENABLED)) {
        log_it();
    }

    $GLOBALS['bf_t1'] = $GLOBALS['bf_t1']??0 + ((hrtime(true) - $s1) / 1e+6);
    debug('complete [%.2fms] [%s]', ($GLOBALS['bf_t1']), trace());

    $e = error_get_last();
    // if last error was from bitfire, log it
    if (
    is_array($e) 
    && in_array($e['type']??-1, [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR]) 
    && stripos($e['file'] ?? '', 'bitfire') > 0) {
        $e['ver'] = BITFIRE_VER;
        $e['e_type'] = 'FATAL';
        $e['id'] = uniqid();
        $e['php_ver'] = phpversion();
        $e['ref_id'] = $_SERVER['REQUEST_URI']??"na";

        $encoded = array_map(function ($k, $v) {
            return "$k=" . urlencode($v);
        } , array_keys($e), array_values($e));

        $url_params = join('&', $encoded);
        // don't allow endless loops
        if (stripos($url_params, 'error_handler') !== false) {
            return;
        }

        file_get_contents(INFO . "err.php?" . $url_params);
        echo "<h1>Fatal Error Detected.</h1><p>please contact support - info@bitslip6.com</p><p>Reference: {$e['id']}</p>\n";

        require_once WAF_SRC . "server.php";
        if (function_exists('BitFireSvr\update_ini_value')) {
            $i = BitFire::get_instance();
            if (!empty($i)) {
                if (!empty($i->agent)) {
                    if (! $i->agent->bot) {
                        \BitFireSvr\update_ini_value('bitfire_enabled', 'false')->run();
                        echo "<p>bitfire has been disabled.</p>\n";
                    }
                }
            }
        }


    }

    // send any errors that have been queued after the page has been served
    on_err(-100, "", "", 0);
});


// capture any bitfire errors
$error_handler = set_error_handler('\BitFire\on_err');