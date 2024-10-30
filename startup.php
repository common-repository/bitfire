<?php
namespace BitFire;

use BitFire\Config as CFG;

use function ThreadFin\debug;
use function ThreadFin\parse_ini;

// enable php assertions
const ASSERT = false;

// do not double include
if (defined('BitFire\\WAF_ROOT')) {
    header('x-bitfire: plug inc 2x');
    return;
}
// PHP version guard
if (PHP_VERSION_ID < 70400) {
    header('x-bitfire: php7.4 required, ' . PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION . " found");
    return;
}
if (stripos(PHP_OS, 'win') === 0) {
    header('x-bitfire: windows not supported');
    return;
}





// enable/disable assertions via debug setting
if (ASSERT) {
    $zend_assert = @assert_options(ASSERT_ACTIVE, true);
} else {
    $zend_assert = assert_options(ASSERT_ACTIVE, 0);
}


// system root paths and firewall timing info
$GLOBALS['bf_s1'] = hrtime(true);
const DS = DIRECTORY_SEPARATOR;
if (!defined('BitFire\WAF_ROOT')) {
    define('BitFire\WAF_ROOT', realpath(__DIR__) . DS);
    define('BitFire\BLOCK_DIR', \BitFire\WAF_ROOT . 'blocks');
    define('BitFire\WAF_SRC', \BitFire\WAF_ROOT . 'src' . DS);
    define('BitFire\TYPE', 'WORDPRESS');
    define('ThreadFin\view\VIEW_ROOT', \BitFire\WAF_ROOT . "views");
}

// error handler registers shutdown function (log_it) and fatal error handler
include \BitFire\WAF_ROOT . 'error_handler.php';
include \BitFire\WAF_SRC . 'const.php';

// load the firewall program code
include \BitFire\WAF_SRC . 'bitfire.php';

try {
    // don't attempt to serve bot images for bots that don't exist..
    if (strpos($_SERVER['REQUEST_URI']??"", '/bitfire') !== false) {
        // if we hit this code, it's a request for an unknown browser, don't let it hit the app 
        if (substr($_SERVER['REQUEST_URI'], -5) == '.webp') {
            header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T', time() + (60 * 60))); // 1 hour
            die(file_get_contents(WAF_ROOT . 'public/browsers/unknown_bot.webp'));
        }
        header('x-bitfire: plug inc');
    }

    // load the config file
    CFG::set(parse_ini());
    // date call is expensive, only run this if we are actually logging
    if (CFG::enabled('debug_file', false) || CFG::enabled('debug_header', false)) {
        debug('  --> bitfire %s [%s:%s] @%s', BITFIRE_SYM_VER, $_SERVER['REQUEST_METHOD'], substr($_SERVER['REQUEST_URI'], 0, 80), date('D M j G:i:s'));
    }

    // handle IP level blocks
    if (CFG::enabled('allow_ip_block')) {
        include \BitFire\WAF_ROOT . 'ip_blocking.php';
    }

    // call any required bitfire setup code
    bitfire_init();

    // if the user is logged in, then we will run the code from the plugin...
    $auth_cookies = array_filter($_COOKIE, function ($value, $key) {
        $a = strpos($key, 'wordpress_');
        return ($a === 0) && strlen($value) > 64;
    }, ARRAY_FILTER_USE_BOTH);

    // user is not logged in, so we will run the firewall code here.
    // if they are logged in, the code will run from the wordpress handler so that we
    // have access to the user functions
    if (empty(CFG::str("cms_root")) || count($auth_cookies) < 2) {
        $bitfire = \Bitfire\BitFire::get_instance();
        $bitfire->inspect();
    }

} catch (\Exception $e) {
    \BitFire\on_err($e->getCode(), $e->getMessage(), $e->getFile(), $e->getLine());
}


$GLOBALS['bf_t1'] = $GLOBALS['bf_t1']??0 + ((hrtime(true) - $GLOBALS['bf_s1']) / 1e+6);

// clean up the error handler and assertion settings
restore_error_handler();
// restore default assertion level
if (ASSERT) {
    assert_options(ASSERT_ACTIVE, $zend_assert);
}

// reset display errors to none, enable this after adding settings to GUI
/*
$ppf = ini_get("auto_prepend_file");
if (!empty($ppf) && stripos($ppf, "bitfire") !== false && stripos($ppf, "display_errors") !== false) {
    ini_set("display_errors", CFG::enabled("display_errors", false));
}
*/


// add support for startup chaining
$autoload = CFG::str('auto_prepend_file');
if (!empty($autoload) && file_exists($autoload)) {
    @include $autoload;
}

