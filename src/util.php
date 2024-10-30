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

namespace ThreadFin;

use const BitFire\BITFIRE_VER;
use const BitFire\CONFIG_CACHE_TYPE;
use const BitFire\CONFIG_ENCRYPT_KEY;
use const BitFire\CONFIG_USER_TRACK_COOKIE;
use const BitFire\FILE_R;
use const BitFire\FILE_RW;
use const BitFire\FILE_W;
use const BitFire\STATUS_OK;
use const BitFire\WAF_ROOT;
use const BitFire\WAF_SRC;

use ArrayAccess;
use \BitFire\Config as CFG;
use \BitFire\Block as Block;
use InvalidArgumentException;
use ReflectionClass;
use RuntimeException;
use stdClass;

use function BitFire\log_it;
use function BitFire\on_err;
use function BitFireChars\save_config2;
use function BitFireSvr\update_ini_value;
use function ThreadFin\HTTP\http;
use function \ThreadFin\partial as ƒixl;
use function \ThreadFin\partial_right as ƒixr;

//if (defined("ThreadFin\EN")) { return; }
//define("BitFire\_TF_UTIL", 1);


const DS = DIRECTORY_SEPARATOR;
const WEEK=86400*7;
const DAY=86400;
const HOUR=3600;
const MINUTE=60;

const ENCODE_RAW=1;
const ENCODE_SPECIAL=2;
const ENCODE_HTML=3;
const ENCODE_BASE64=4;

interface packable {
    public function pack() : string;
    public static function unpack(string $data);
}

/**
 * Complete filesystem abstraction
 * @package ThreadFin
 */
class FileData {
    /** @var string $filename - full path to file on disk */
    public $filename;
    /** @var int $num_lines - number of lines of content */
    public $num_lines;
    /** @var array $lines - file content array of lines */
    public $lines = array();
    public $debug = false;
    public $size = 0;
    public $content = "";
    /** @var bool $exists - true if file or mocked content exists */
    public $exists = false;
    /** @var bool $readable - true if file is readable */
    public $readable = false;
    /** @var bool $readable - true if file is writeable */
    public $writeable = false;

    public $lock = false;
    protected $_fh;

    protected static $fs_data = array();
    protected $errors = array();

    /**
     * mask file system with mocked $content at $filename
     * @param string $filename 
     * @param string $content 
     */
    public static function mask_file(string $filename, string $content) {
        FileData::$fs_data[$filename] = $content;
    }

    /**
     * @return array of any errors that may have occurred
     */
    public function get_errors() : array { return $this->errors; }

    /**
     * @param bool $enable enable or disable debug mode
     * @return FileData 
     */
    public function debug_enable(bool $enable) : FileData {
        $this->debug = $enable;
        return $this;
    }

    /**
     * preferred method of creating a FileData object
     */
    public static function new(string $filename, bool $lock = false) : FileData {
        return new FileData($filename, $lock);
    }

    /**
     * set the next read operation to locking
     * @return FileData 
     */
    public function lock() : FileData {
        $this->lock = true;
        return $this;
    }

    public function __construct(string $filename, bool $lock = false) {
        $this->filename = $filename;
        $this->lock = $lock;
        if (isset(FileData::$fs_data[$filename])) {
            $this->exists = $this->writeable = $this->readable = true;
            $this->size = strlen(FileData::$fs_data[$filename]);
        } else {
            $this->exists = file_exists($filename);
            $this->writeable = is_writable($filename);
            $this->readable = is_readable($filename);
            if ($this->exists) {
                $this->size = filesize($filename);
            }
        }
    }

    /**
     * This could be improved by marking content clean/dirty and joining only dirty content
     * @return string the raw file contents
     */
    public function raw() : string {
        if (empty($this->lines)) {
            if (isset(FileData::$fs_data[$this->filename])) {
                return FileData::$fs_data[$this->filename];
            } else {
                return file_exists($this->filename) ? file_get_contents($this->filename) : "";
            }
        }
        // XXX if file is read with NO newlines, then join will need newlines...
        // maybe we should loop over lines and append a newline if missing for each line
        return join("", $this->lines);
    }


    /**
     * read the data from disk and store in lines
     * @return FileData 
     */
    public function read($with_newline = true) : FileData {
        // mock data, and raw reads
        if (isset(FileData::$fs_data[$this->filename])) {
            $this->lines = explode("\n", FileData::$fs_data[$this->filename]);
            $this->num_lines = count($this->lines);
        }
        else {
            if ($this->exists) {
                $size = filesize($this->filename);
                if ($size > 1024*1024*10) {
                    $this->errors[] = "File too large to read: $this->filename";
                    return $this;
                }


                // read the file and lock it
                if ($this->lock) {
                    $this->_fh = fopen($this->filename, "r+");
                    if (!empty($this->_fh)) {
                        flock($this->_fh, LOCK_EX);
                        $buffer = "";
                        while(feof($this->_fh) === false) {
                            $buffer .= fread($this->_fh, 8192);
                        }
                        $this->lines = explode("\n", $buffer);
                        if ($with_newline) {
                            $this->lines = array_map(ƒixr('\ThreadFin\append_str', "\n"), $this->lines);
                        }
                    }
                } else {
                    // just read the file (no locking)
                    $new_line_flag = ($with_newline) ? 0 : FILE_IGNORE_NEW_LINES;
                    $this->lines = file($this->filename, $new_line_flag);
                }

                // count lines and handle any error cases...
                if ($this->lines === false) {
                    debug("unable to read %s", $this->filename);
                    $this->lines = [];
                    $this->num_lines = 0;
                } else {
                    $this->num_lines = count($this->lines);
                }

                if ($this->debug) {
                    debug("FS(r) [%s] (%d)lines", $this->filename, $this->num_lines);
                }

                // make sure lines is a valid value
                if ($size > 0 && $this->num_lines < 1) {
                    debug("empty file %s", $this->filename);
                    $this->lines = [];
                }

            } else {
                debug("file does not exist: %s", $this->filename);
                $this->errors[] = "unable to read, file does not exist";
            }
        }
        return $this;
    }

    /**
     * MUTATE $lines
     * @param callable $fn apply function to every line in file.
     * @return FileData 
     */
    public function apply_ln(callable $fn) : FileData {
        if ($this->num_lines > 0) {
            $this->lines = $fn($this->lines);
            $this->num_lines = count($this->lines);
        } else {
            $this->errors[] = "unable to apply fn[".func_name($fn)."] has no lines";
        }
        return $this;
    }

    /**
     * return the number of bytes in all lines (excluding newlines...)
     * @return int 
     */
    public function count_bytes() : int {
        $bytes = 0;
        foreach ($this->lines as $line) { $bytes += strlen($line); }
        return $bytes;
    }

    /**
     * MUTATE $lines
     * @return FileData with lines joined and json decoded
     */
    public function un_json() : FileData {
        // UGLY, refactor this
        if (count($this->lines) > 0) {
            $data = join("\n", $this->lines);
            $result = false;
            if (!empty($data) && is_string($data)) {
                $result = un_json($data);
            }
            if (is_array($result)) {
                $this->lines = $result;
                $this->num_lines = count($this->lines);
            }
            else {
                $this->lines = array();
                $this->errors[] = "json decode failed";
            }
        }
        return $this;
    }
    /**
     * MUTATE $lines
     * @param callable $fn apply function to $this, must return a FileData objected
     * @return FileData FileData mutated FileData with data from returned $fn($this)
     */
    public function apply(callable $fn) : FileData {
        if ($this->num_lines > 0) {
            $tmp = $fn($this);
            $this->lines = $tmp->lines;
            $this->num_lines = count($tmp->lines);
            $this->filename = $tmp->filename;
            $this->exists = $tmp->exists;
        }
        return $this;
    }
    /**
     * @param callable $fn array_filter on $this->lines with $fn
     * @return FileData 
     */
    public function filter(callable $fn) : FileData {
        $this->lines = array_filter($this->lines, $fn);
        $this->num_lines = count($this->lines);
        //if (!empty($this->content)) { $this->content = join("\n", $this->lines); }
        return $this;
    }

    /**
     * @param string $text test to append to FileData
     * @return FileData 
     */
    public function append(string $text) : FileData {
        $lines = explode("\n", $text);
        $check_line = $lines[0]??"";
        foreach ($lines as $line) {
            if (!empty($line) && strlen($line) > 5) {
                $check_line = $line;
                break;
            }
        }
        if (!empty($check_line)) {
            if (!in_array($check_line, $this->lines)) {
                foreach ($lines as $line) {
                    $this->lines[] = "$line\n";
                }
            }
        }
        return $this;
    }

    /**
     * MUTATES $lines
     * @param callable $fn array_map on $this->lines with $fn
     * @return FileData 
     */
    public function map(callable $fn) : FileData {
        $this->num_lines = count($this->lines);
        if ($this->num_lines > 0) {
            $this->lines = array_map($fn, $this->lines);
        } else {
            trace("E_MAP");
        }
        return $this;
    }

    /**
     * reduces all $lines to a single value
     * @param callable $fn ($carry, $item)
     * @return FileData 
     */
    public function reduce(callable $fn, $initial = NULL) : ?string {
        return array_reduce($this->lines, $fn, $initial);
    }

    public function __invoke() : array {
        return $this->lines;
    }

    // return a file modification effect for current FileData
    public function file_mod($mode = 0, $mtime = 0) : FileMod {
        return new FileMod($this->filename, $this->raw(), $mode, $mtime);
    }

    /**
     * @return int the file modification time, or 0 if the file does not exist
     */
    public function mtime() : int {
        if ($this->exists) {
            return filemtime($this->filename);
        }
        return 0;
    }

    public function unlock() {
        if (!empty($this->_fh)) {
            flock($this->_fh, LOCK_UN);
        }
    }

    public function close() : void {
        if (!empty($this->_fh)) {
            $this->unlock();
            fclose($this->_fh);
        }
    }
}

    
    

// developer debug functions
function mark(?string $msg = null) {
    static $last = 0; if (is_null($msg)) { return $last; }
    $last = microtime(true); trace($msg);
}
function dbg($x, $msg="") {$m=htmlspecialchars($msg); $z=(php_sapi_name() == "cli") ? print_r($x, true) : htmlspecialchars(print_r($x, true)); echo "<pre>\n[$m]\n($z)\n" . join("\n", debug(null)) . "\n" . debug(trace(null));
    $now = microtime(true); $last = mark(null); $ms = "-";
    if ($last > 0) {
        $time = $now - $last;
        $ms = sprintf("%0.3f", $time * 1000);
    }
    debug_print_backtrace();
    die("\nFIN [$ms]");
}
function do_for_each(array $data, callable $fn) { $r = array(); foreach ($data as $elm) { $r[] = $fn($elm); } return $r; }
function do_for_all_key(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key); } }
function do_for_all_key_value(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key, $item); } }
function find_regex_reduced($value) : callable { return function($initial, $argument) use ($value) { return (preg_match("/$argument/", $value) <= 0 ? $initial : $value); }; }
function starts_with(string $haystack, string $needle) { return (substr($haystack, 0, strlen($needle)) === $needle); } 
function ends_with(string $haystack, string $needle) { return strrpos($haystack, $needle) === \strlen($haystack) - \strlen($needle); } 
function ends_with_any(string $haystack, array $needles) {
    $hay_len = \strlen($haystack);
    foreach ($needles as $needle) {
        if (strrpos($haystack, $needle) === $hay_len - \strlen($needle)) {
            return true;
        }
    }
    return false;
}
function random_str(int $len) : string { return substr(strtr(base64_encode(random_bytes($len)), '+/=', '___'), 0, $len); }
function un_json(?string $data="") : ?array {
    if (empty($data)) { return []; }
    $d = trim($data, "\n\r,");
    $j = json_decode($d, true, 32); $r = [];
    if (is_array($j)) { $r = $j; }
    else { 
        $max_len = min(24, strlen($d)); 
        debug("ERROR un_json [%s ... %s]", substr($d, 0, $max_len), substr($d, -$max_len));
        return null;
    }
    return $r; }
function en_json($data, $pretty = false) : string { 
    $mode = $pretty ? JSON_PRETTY_PRINT : 0;
    $j = json_encode($data, $mode);
    if ($j == false && function_exists('BitFire\on_err')) {
        $enum = json_last_error();
        $msg = json_last_error_msg();
        // XXX replace with caller file:line
        on_err($enum, $msg, __FILE__, __LINE__);
    }
    return ($j == false) ? "" : $j;
}
function contains(?string $haystack, $needle) : bool { if(is_array($needle)) { foreach ($needle as $n) { if (!empty($n) && strpos($haystack, $n) !== false) { return true; } } return false; } else { return strpos($haystack, $needle) !== false; } }
function icontains(?string $haystack, $needle) : bool { if(is_array($needle)) { foreach ($needle as $n) { if (!empty($n) && stripos($haystack, $n) !== false) { return true; } } return false; } else { return stripos($haystack, $needle) !== false; } }
// return the $index element of $input split by $separator or '' on any failure
function at(?string $input, string $separator, int $index, string $default='') : string {
    if (empty($input)) { return ''; }
    $parts = explode($separator, $input);
    return (isset($parts[$index])) ? $parts[$index] : $default;
}

/** return (bool)!$input */
function ø(bool $input) : bool { return !$input; }
function find_fn(string $fn) : callable { if (function_exists("BitFirePlugin\\$fn")) { return "BitFirePlugin\\$fn"; } if (function_exists("BitFire\\$fn")) { return "BitFire\\$fn"; } error("no plugin function: %s", $fn); return "BitFire\\id"; }
function find_const_arr(string $const, array $default=[]) : array { 
    if (defined("BitFirePlugin\\$const")) { return constant("BitFirePlugin\\$const"); }
    if (defined("BitFire\\$const")) { return constant("BitFire\\$const"); }
    return $default;
}

// set key on object|array data to value if key is currently not set

function set_if_empty($data, $key, $value) { if (is_object($data) && (!isset($data->$key) || empty($data->$key))) { $data->$key = $value; } if (is_array($data) && (!isset($data[$key]) || empty($data[$key]))) { $data[$key] = $value; } return $data; }

// find an element that matches !empty($fn(x)) or NULL
function find(array $list, callable $fn) { foreach ($list as $item) { $x = $fn($item); if (!empty($x)) { return $x; }} return NULL; }
function ƒ_id($data = '') : callable { return function () use ($data) { return $data; }; }
function ƒ_inc($amount = 1) : callable { return function ($input) use ($amount) { trace("INC:$input:$amount"); return intval($input) + $amount; }; }
function ƒ_match($match = '') : callable { return function ($input) use ($match) { return $match == $input; }; }
function fn_carry($fn) { return function($carry, $item) use ($fn) {
    $carry[] = $fn($item);
    return $carry;
    };
}

/**
 * map a binary string to a map of ints, and increment a counter
 * @param int $key_id map key to increment
 * @param int $max_items max items in map (each entry is 5 bytes)
 * @return callable (string) : string
 */
function ƒ_map_inc(int $key_id, int $max_items) : callable {
    return function (string $raw) use ($key_id, $max_items) : string {
        // store the data compact in <128 bytes
        $map = (!empty($raw)) ? array_int_map_unpack($raw) : [];
        // limit number of items, remove older entries with low counts...
        if (count($map) > $max_items) {
            arsort($map);
            $map = array_slice($map, 0, $max_items);
        }
        // increment the key and return packed array, store as single byte key id
        $map[$key_id] = (isset($map[$key_id])) ? $map[$key_id] + 1 : 1;

        trace("map_inc:$key_id = {$map[$key_id]}");
        return array_int_map_pack($map);
    };
}

function array_add_value(array $keys, callable $fn) : array { $result = array(); foreach($keys as $x) {$result[$x] = $fn($x); } return $result;}
function append_str(string $input, string $to_append) : string { return $input . $to_append; }

function len(string $input) : int { return function_exists('\mb_strlen') ? mb_strlen($input) : poly_strlen($input); }

function compact_array(?array $in) : array { $result = []; foreach ($in as $x) { $result[] = $x; } return $result; }

function array_int_map_pack(array $data) : string {
    $output = '';
    foreach ($data as $key => $value) {
        $output .= pack("CV", $key, $value);
    }
    return $output;
}

function array_int_map_unpack(string $data) : array {
    $output = [];
    for ($i=0, $m = len($data); $i<$m; $i+=5) {
        $value = unpack('Ckey/Vval', substr($data, $i, 5));
        if ($value !== false) {
            $output[$value['key']] = $value['val'];
        }
    }
    return $output;
}


// polyfill for mb_strlen
function poly_strlen($s) {
    for ($i=0; $i<192; $i++) {
        if (!isset($s[$i])) { break; }
    }
    return $i;
}


// map keys from data into object public properties
function map_to_object(array $data, $object) {
    foreach ($data as $key => $value) {
        if ($value !== NULL && !empty($value)) {
            $object->$key = $value;
        }
    }
    return $object;
}



/**
 * return sub directories for a single directory. non-recursive. non-pure
 * @param string $dirname to search
 * @return array 
 */
function get_sub_dirs(string $dirname) : array {
    $dirs = array();
    if (!file_exists($dirname)) { debug("unable to find sub-dirs [%s]", $dirname); return $dirs; }

    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false) {
            $path = $dirname . '/' . $file;
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            if (is_dir($path) && $dirname !== $path && !is_link($path)) {
                $dirs[] = $path;
			}
        }
        \closedir($dh);
    }

    return $dirs;
}


/**
 * recursively perform a function over directory traversal.
 */
function file_recurse(string $dirname, callable $fn, string $regex_filter = NULL, array $result = array(), $max_results = 20000) : array {
    $max_files = 20000;
    $result_count = count($result);
    if (!file_exists($dirname)) { 
        debug("[%s] not exist", $dirname);
        return $result;
    }

    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false && $max_files-- > 0 && $result_count < $max_results) {
            $path = $dirname . '/' . $file;
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            if (($regex_filter != NULL && preg_match($regex_filter, $path)) || $regex_filter == NULL) {
                $x = $fn($path);
                if (!empty($x)) { $result[] = $x; $result_count++; }
            }
            if (is_dir($path) && !is_link($path)) {
                if (!preg_match("#\/uploads\/?$#", $path)) {
                    $result = file_recurse($path, $fn, $regex_filter, $result, $max_results);
                    $result_count = count($result);
                }
			}
        }
        \closedir($dh);
    }

    return $result;
}




/**
 * yield all matching files in a directory recursively
 */
function index_yield(string $index_file, int $max_lines = 200) : ?\Generator {
    if (!file_exists($index_file)) { return NULL; } 
    static $counter = 0;
    static $yielded = 0;

    $fh = fopen($index_file, "r+");
    $size = filesize($index_file);
    if ($size <= 2) { return NULL; }

    $block_size = 384;
    $truncate_size = 0;
    $read_size = 0;
    $last_read = $size;
    $next_ptr = max(0, $size - $block_size);
    //$next_ptr = 0;
    $line = "";

    $full_read = 0;
    while($yielded < $max_lines && $next_ptr >= 0 && $last_read > 0 && ++$counter < $max_lines*2) {
        if (fseek($fh, $next_ptr, SEEK_SET) < 0) { 
            continue;
        }

        if ($next_ptr == 0) { 
            $block_size = 1024;
        }
        $tmp = fread($fh, $block_size);
        $idx2 = strrpos(rtrim($tmp), "\n");
        if (!$idx2) {
            continue;
        }
        $line = substr($tmp, $idx2);
        $read_size = strlen($line);
        $full_read += $read_size;
        //$full_size = strlen($tmp);
        $next_ptr = max(0, $next_ptr - $read_size);

        $line = trim($line);
        if (substr($line, 0, 1) !== DS) { 
            $line = DS . $line;
        }

        if (!file_exists($line)) {
            continue;
        }
        $yielded++;
        yield $line;
    }

    if ($last_read >= $size) {
        $parts = explode(".php", $tmp);
        foreach ($parts as $part) {
            yield trim($part . ".php");
        }
    }

    fseek($fh, 0, SEEK_SET);
    rewind($fh);
    fflush($fh);

    // only truncate to last newline!!
    $r = ftruncate($fh, max(0, $size - $full_read + 1));
    if (!$r) {
        error("unable to truncate index file");
    }
    //$r_txt = ($r) ? "TRUE" : "FALSE";
    rewind($fh);
    fclose($fh);
    if ($size - $truncate_size < 256) {
        return NULL;
    }
}


/**
 * yield all matching files in a directory recursively
 * only used in api.php
 */
function file_index(string $dirname, string $include_regex_filter = NULL, callable $write_fn, bool $root = true) {
    if (!is_dir($dirname)) { return; }
    static $examined = [];
    // reset the counter for root calls
    if ($root) { $examined = []; }

    $backup_regex = "/".str_replace(DS, "\\".DS, $dirname)."\\".DS."wp-content\\".DS."updraft\\".DS."/";
    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false) {
            // skip "dot" files
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            $path = $dirname . DS . $file;


            // recurse if it is a directory
            if (is_dir($path)) {
                // disallow directory recursion loops
                if (isset($examined[$path])) { continue; }
                // mark this path as examined
                $examined[$path] = 1;

                file_index($path, $include_regex_filter, $write_fn, false);
            } else {

                // check if the path matches the regex filter, or has no filter
                if (($include_regex_filter != NULL && preg_match($include_regex_filter, $path)) || $include_regex_filter == NULL) {
                    //debug("yield ($yielded) [$counter] < $skip_files ($max_files)");
                    if (preg_match($backup_regex, $path)) { continue; }
                    $write_fn("$path\n");
                }
            }
        }
        \closedir($dh);
    }
}



/**
 * returns a function that will cache the call to $fn with $key for $ttl
 * NOTE: $fn must return an array or a string (see: load_or_cache)
 */
function memoize(callable $fn, string $key, int $ttl) : callable {
    return function(...$args) use ($fn, $key, $ttl) {
        if (CFG::str(CONFIG_CACHE_TYPE) !== 'nop') {
            return CacheStorage::get_instance()->load_or_cache($key, $ttl, ƒixl($fn, ...$args));
        }
        else {
            debug("unable to memoize [%s]", func_name($fn));
            return $fn(...$args);
        }
    };
}

/**
 * functional helper for partial application
 * lock in left parameter(s)
 * $log_it = partial("log_to", "/tmp/log.txt"); // function log_to($file, $content)
 * assert_eq($log_it('the log line'), 12, "partial app log to /tmp/log.txt failed");
 */
function partial(callable $fn, ...$args) : callable {
    return function(...$x) use ($fn, $args) { return $fn(...array_merge($args, $x)); };
}

/**
 * same as partial, but reverse argument order
 * lock in right parameter(s)
 * $minus3 = partial_right("minus", 3);  //function minus ($subtrahend, $minuend)
 * assert_eq($minus3(9), 3, "partial app of -3 failed");
 */
function partial_right(callable $fn, ...$args) : callable {
    return function(...$x) use ($fn, $args) { return $fn(...array_merge($x, $args)); };
}


/**
 * Effect runner helper
 */
function header_send(string $key, ?string $value) : void {
    if (headers_sent($file, $line)) {
        if (php_sapi_name() == 'cli') { return; }
        $msg = sprintf("headers already sent in %s:%d, unable to send: [%s:%s]", $file, $line, $key, $value);
        if (function_exists('on_err')) {
            on_err(2, $msg, $file, $line);
        }
    } else {
        $content = ($value != null) ? "$key: $value"  : $key;
        header($content);
    }
}


class FileMod {
    public $filename;
    public $content;
    public $write_mode = FILE_RW;
    public $mod_time;
    public $append;
    public $atomic;
    public function __construct(string $filename, string $content, int $write_mode = 0, int $mod_time = 0, bool $append = false, bool $atomic = false) {
        $this->filename = $filename;
        $this->content = $content;
        $this->write_mode = $write_mode;
        $this->mod_time = $mod_time;
        $this->append = $append;
        $this->atomic = $atomic;
    }
}


/**
 * abstract away effects
 */
class Effect {
    private $out = '';
    private $cookie = '';
    private $response = 0;
    private $hide_output = false;
    private $status = STATUS_OK;
    private $exit = false;
    private $headers = array();
    private $cache = array();
    public $file_outs = array();
    private $api = array();
    private $unlinks = array();
    private $errors = array();

    public static function new() : Effect { assert(func_num_args() == 0, "incorrect call of Effect::new()"); return new Effect(); }
    public static $NULL;

    // response content effect
    public function out(string $line, int $encoding = ENCODE_RAW, bool $replace = false) : Effect { 
        switch ($encoding) {
            case ENCODE_SPECIAL:
                $tmp = htmlspecialchars($line); 
                break;
            case ENCODE_HTML:
                $tmp = htmlentities($line); 
                break;
            case ENCODE_BASE64:
                $tmp = base64_encode($line); 
                break;
            default:
                $tmp = $line; 
                break;
        }
        if ($replace) { $this->out = $tmp; }
        else { $this->out .= $tmp; }
        return $this;
    }
    // response header effect
    public function header(string $name, ?string $value) : Effect { $this->headers[$name] = $value; return $this; }
    // remove any response headers
    public function clear_headers() : Effect { $this->headers = array(); return $this; }
    // response cookie effect
    public function cookie(string $value, string $id = "") : Effect { $this->cookie = $value; return $this; }
    // response code effect
    public function response_code(int $code) : Effect { $this->response = $code; return $this; }
    // update cache entry effect
    public function update(CacheItem $item) : Effect { $this->cache[$item->key] = $item; return $this; }
    // exit the script effect (when run is called), 2 helpers for setting error conditions, newline added to $out
    public function exit(bool $should_exit = true, ?int $status = null, ?string $out = null) : Effect { 
        $this->exit = $should_exit; 
        if ($status != null) {
            assert(is_numeric($status), "exit status must be numeric [$status]");
            $this->status = $status;
        }
        if ($out != null) { $this->out .= "\n$out"; }
        return $this;
    }
    // an effect status code that can be read later
    public function status(int $status) : Effect { $this->status = $status; return $this; }
    // an effect to write a file to the filesystem.  if a previous entry for the same file exists, it is overwritten
    public function file(FileMod $mod) : Effect { assert(!empty($mod->filename), "file problem %s"); 
        // if not appending, we want to overwrite any current content for same file
        if (! $mod->append) {
            $outs = array_filter($this->file_outs, function($x) use ($mod) { return $x->filename != $mod->filename; });
            $outs[] = $mod;
            $this->file_outs = $outs;
        }
        // appending, so just add to the list of edits
        else {
            $this->file_outs[] = $mod;
        }
        return $this;
    }
    // one liner for api output
    public function api(bool $success, string $note, array $data=[]) : Effect { $this->api['success'] = $success; $this->api['note'] = $note; $this->api['data'] = $data; return $this; }
    // add a file to the list of files to remove
    public function unlink(string $filename) : Effect { $this->unlinks[] = $filename; return $this; }
    // don't display any output
    public function hide_output(bool $hide = true) : Effect { $this->hide_output = $hide; return $this; }

    public function chain(Effect $effect) : Effect { 
        $this->out .= $effect->read_out();
        $this->cookie .= $effect->read_cookie();
        $this->response = $this->set_if_default('response', $effect->read_code(), 0);
        $this->status = $this->set_if_default('status', $effect->read_status(), STATUS_OK);
        $this->exit = $this->set_if_default('exit', $effect->read_exit(), false);
        $this->set_if_default('headers', $effect->read_headers(), [], true);
        $this->set_if_default('cache', $effect->read_cache(), []);
        $this->set_if_default('file_outs', $effect->read_files(), []);
        $this->set_if_default('api', $effect->read_api(), [], true);
        $this->set_if_default('unlinks', $effect->read_unlinks(), []);
        return $this;
    }

    // helper function for effect chaining
    protected function set_if_default($pname, $value, $default, $hash = false) {
        if (is_array($this->$pname) && !empty($value)) {
            if (is_array($value)) {
                $this->$pname = array_merge($this->$pname, $value);
            } else {
                $this->$pname[] = $value;
            }
        }
        else if (!empty($value) && $this->$pname === $default) { return $value; }
        return $this->$pname;
    }

    // return true if the effect will exit 
    public function read_exit() : bool { return $this->exit; }
    // return the effect content
    public function read_out(bool $clear = false) : string { $t = $this->out; if ($clear) { $this->out = ""; } return $t; }
    // return the effect headers
    public function read_headers() : array { return $this->headers; }
    // return the effect cookie (only 1 cookie supported)
    public function read_cookie() : string { return $this->cookie; }
    // return the effect cache update
    public function read_cache() : array { return $this->cache; }
    // return the effect response code
    public function read_code() : int { return $this->response; }
    // return the effect function status code
    public function read_status() : ?int { return $this->status; }
    // return the effect filesystem changes
    /** @return array<FileMod>  */
    public function read_files() : array { return $this->file_outs; }
    // return the API result output
    public function read_api() : array { return $this->api; }
    // return the list of files to unlink
    public function read_unlinks() : array { return $this->unlinks; }
    // return  the list of errors after a run, should be empty
    public function read_errors() : array { return $this->errors; }

    // TODO: monitor runner for failures and log/report them
    public function run() : Effect {
        // http response
        if ($this->response > 0) {
            trace("CODE {$this->response}");
            http_response_code($this->response);
        }

        // cookies
        if (CFG::enabled('cookies_enabled') && !empty($this->cookie)) {
            if (!headers_sent($file, $line)) {
                // remove any previously set cookie header
                cookie('_bitf', $this->cookie, HOUR);
            } else {
                $this->errors[] = "cookie headers already sent {$file}:{$line}";
            }
        }

        // send custom headers
        if (count($this->headers) > 0) {
            if (!headers_sent($file, $line)) {
                do_for_all_key_value($this->headers, '\ThreadFin\header_send');
            } else {
                $this->errors[] = "header headers already sent {$file}:{$line} " . en_json($this->headers);
            }
        }

        
        // update cache entries
        if (!empty($this->cache)) {
            $items = array_values($this->cache);
            $cache = CacheStorage::get_instance();
            array_walk($items, function (CacheItem $item) use ($cache) {
                $cache->update_data($item->key, $item->fn, $item->init, $item->ttl, $item->flags);
            });
        }

        // write all effect files
        foreach ($this->file_outs as $file) {
            assert(!empty($file->filename), "can't write to null file: " . en_json($file));
            $len = strlen($file->content);

            $mods = ($file->append) ? FILE_APPEND | LOCK_EX : LOCK_EX;
            debug("FS(w) [%s] (%d)bytes", $file->filename, $len);

            // create the path if we need to
            $dir = dirname($file->filename);
            if (!file_exists($dir)) {
                if (!mkdir($dir, 0755, true)) {
                    $this->errors[] = "unable to mkdir -r [$dir]";
                }
            }

            // ensure write-ability
            if (file_exists($file->filename)) {
                if (!is_writeable($file->filename)) {
                    if (!chmod($file->filename, FILE_RW)) {
                        $this->errors[] = "unable to make {$file->filename} writeable";
                    }
                }
            }

            // write to a temp file, check it, then rename it atomically
            $tmp_file = $file->filename . "." . random_int(0xFF, 0xFFFFFF);
            $written = file_put_contents($tmp_file, $file->content, $mods);

            // write failed - original file is not corrupted!
            if ($written != $len) {
                $e = error_get_last();
                debug("file mod write error [%s] (%d/%d bytes)", basename($file->filename), $written, $len);
                $this->errors[] = "failed to write file: $file->filename " . strlen($file->content) . " bytes. " . en_json($e);
                @unlink($tmp_file);
            }
            // temp write success
            else {
                // rename failed
                if (!rename($tmp_file, $file->filename)) {
                    $this->errors[] = "failed to rename temp file to: $file->filename " . strlen($file->content) . " bytes";
                }
                // rename success, new data is now written to $file->filename, update permissions, mod time
                else {
                    if ($file->mod_time > 0) { if (!touch($file->filename, $file->mod_time)) { $this->errors[] = "unable to set {$file->filename} mod_time to: " . $file->mod_time; } }
                    if ($file->write_mode > 0) { if (!chmod($file->filename, $file->write_mode)) { $this->errors[] = "unable to chmod {$file->filename} perm: " . $file->write_mode; } }
                }
            }
        }

        // allowable: backup files, WordFence waf loader if it is an emulation file
        // unknown files: (not plugins, themes or core WordPress files)
        do_for_each($this->unlinks, function ($x) {
            debug("unlink %s", $x);
            recursive_delete($x);
            if (is_file($x)) {
                if (!unlink($x)) {
                    $this->errors[] = "unable to delete file $x";
                }
            } else if (is_dir($x)) {
                $t = $this;
                file_recurse($x, function($file) use (&$t) {
                    if (!unlink($file)) {
                        $this->errors[] = "unable to recursive delete file $file";
                    }
                });
                if (!rmdir($x)) {
                    $this->errors[] = "unable to delete directory $x";
                }
            }
        });

        // output api and error data if we are not set to hide it
        if (!$this->hide_output) {
            // API output, force JSON
            if (!empty($this->api)) {
                header_send("content-type", "application/json");
                $this->api['out'] = $this->out;
                $this->api['errors'] = $this->errors;
                if (count($this->errors) > 0) { $this->api['success'] = false; }
                $api_out = en_json($this->api);
                trace("API SZ:" . strlen($api_out));
                if (!$api_out) {
                    debug("unable to encode api response: [%d] (%s)", json_last_error(), json_last_error_msg());
                }
                echo $api_out;
            }
            // standard output
            else if (strlen($this->out) > 0) {
                echo $this->out;
            }
        }

        if (!empty($this->errors)) {
            debug("ERROR effect: %s", json_encode($this->errors, JSON_PRETTY_PRINT));
            if (function_exists("\BitFire\on_err")) {
                on_err(1000, json_encode($this->errors, JSON_PRETTY_PRINT), __FILE__, __LINE__);
            }
        } 

        if ($this->exit) {
            if (isset($GLOBALS['bf_s1'])) {
                $GLOBALS['bf_t1'] = $GLOBALS['bf_t1']??0 + ((hrtime(true) - $GLOBALS['bf_s1']) / 1e+6);
            } else if (!isset($GLOBALS['bf_t1'])) {
                $GLOBALS['bf_t1'] = 0.0;
            }
            $err_h = set_error_handler(null);
            if (empty($err_h)) {
                debug('self exit complete [%.2fms] (%s) [%s]', ($GLOBALS['bf_t1']), $err_h, trace());
            }
            exit();
        }

        return $this;
    }

    // return the number of errors occurred after a run(). should return 0
    public function num_errors() : int {
        return count($this->errors);
    }
}
Effect::$NULL = Effect::new();

// https://stackoverflow.com/questions/5707806/
function recursive_copy(string $source, string $dest) {
    mkdir($dest, 0755);

    /** @var \RecursiveDirectoryIterator $iterator */
    foreach ($iterator = new \RecursiveIteratorIterator(
    new \RecursiveDirectoryIterator($source, \RecursiveDirectoryIterator::SKIP_DOTS),
    \RecursiveIteratorIterator::SELF_FIRST) as $item) {
        if ($item->isDir()) {
            mkdir($dest . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
        } else {
            copy($item, $dest . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
        }
    }
}

// https://stackoverflow.com/questions/3338123/
function recursive_delete(string $dir) {
    if (is_dir($dir)) { 
        $objects = scandir($dir);
        foreach ($objects as $object) { 
            if ($object != "." && $object != "..") { 
                if (is_dir($dir. DIRECTORY_SEPARATOR .$object) && !is_link($dir."/".$object)) {
                    recursive_delete($dir. DIRECTORY_SEPARATOR .$object);
                }
                else {
                    unlink($dir. DIRECTORY_SEPARATOR .$object); 
                }
            } 
        }
        rmdir($dir); 
    } 

}


interface MaybeI {
    public static function of($x) : MaybeI;
    /**
     * call $fn (which has an external effect) on the value if it is not empty
     */
    public function effect(callable $fn) : MaybeI;
    public function then(callable $fn, bool $spread = false) : MaybeI;
    public function map(callable $fn) : MaybeI;
    public function keep_if(callable $fn) : MaybeI;
    /** execute $fn runs if maybe is not empty */
    public function do(callable $fn, ...$args) : MaybeI;
    /** execute $fn runs if maybe is empty */
    public function do_if_not(callable $fn, ...$args) : MaybeI;
    public function empty() : bool;
    public function set_if_empty($value) : MaybeI;
    public function errors() : array;
    public function value(string $type = null);
    public function append($value) : MaybeI;
    public function size() : int;
    public function extract(string $key, $default = false) : MaybeI;
    public function index(int $index) : MaybeI;
    public function isa(string $type) : bool;
    public function __toString();
    public function __isset($object) : bool;
}


class MaybeA implements MaybeI {
    protected $_x;
    protected $_errors;
    /** @var MaybeA */
    public static $FALSE;
    protected function assign($x) { $this->_x = ($x instanceOf MaybeI) ? $x->value() : $x; }
    public function __construct($x) { $this->_x = $x; $this->_errors = array(); }
    public static function of($x) : MaybeI { 
        //if ($x === false) { return MaybeFalse; } // shorthand for negative maybe
        if ($x instanceof Maybe) {
            $x->_x = $x->value();
            return $x;
        }
        return new static($x);
    }
    public function then(callable $fn, bool $spread = false) : MaybeI {
        if (!empty($this->_x)) {
            $this->assign(
                ($spread) ?
                $fn(...$this->_x) :
                $fn($this->_x)
            );
            if (empty($this->_x)) { $this->_errors[] = func_name($fn) . ", created null [" . var_export($this->_x, true) . "]"; }
        } else {
            $this->_errors[] = func_name($fn) . ", [" . var_export($this->_x, true) . "]";
        }

        return $this;
    }
    public function map(callable $fn) : MaybeI { 
        if (is_array($this->_x) && !empty($this->_x)) {
            $this->_x = array_map($fn, $this->_x);
            if (empty($this->_x)) { $this->_errors[] = func_name($fn) . ", created null [" . var_export($this->_x, true) . "]"; }
        } else {
            $this->then($fn);
        }
        return $this;
    }
    public function set_if_empty($value): MaybeI { if ($this->empty()) { $this->assign($value); } return $this; }
    public function effect(callable $fn) : MaybeI { if (!empty($this->_x)) { $fn($this->_x); } else { 
        $this->_errors[] = func_name($fn) . ", null effect! [" . var_export($this->_x, true) . "]";
    } return $this; }
    public function keep_if(callable $fn) : MaybeI { if (!empty($this->_x) && $fn($this->_x) === false) { $this->_errors[] = func_name($fn) . " if failed"; $this->_x = NULL; } return $this; }
    /** execute $fn runs if maybe is not empty */
    public function do(callable $fn, ...$args) : MaybeI { if (!empty($this->_x)) { $this->assign($fn(...$args)); } else { 
        $this->_errors[] = func_name($fn) . ", null effect! [" . var_export($this->_x, true) . "]";
    } return $this; }
    /** execute $fn runs if maybe is empty */
    public function do_if_not(callable $fn, ...$args) : MaybeI { if (empty($this->_x)) { $this->assign($fn(...$args)); } return $this; }
    public function empty() : bool { return empty($this->_x); } // false = true
    public function errors() : array { return $this->_errors; }
    public function value(string $type = null) { 
        $result = $this->_x;

        switch($type) {
            case 'str':
            case 'string':
                if (empty($this->_x)) { return ""; }
                $result = strval($this->_x);
                break;
            case 'int':
                if (empty($this->_x)) { return 0; }
                $result = intval($this->_x);
                break;
            case 'array':
                if (empty($this->_x)) { return []; }
                $result = is_array($this->_x) ? $this->_x : ((empty($this->_x)) ? array() : array($this->_x));
                break;
            case 'bool':
                if (empty($this->_x)) { return false; }
                return (bool)$this->_x;
        }
        return $result;
    }
    public function append($value) : MaybeI { $this->_x = (is_array($this->_x)) ? array_push($this->_x, $value) : $value; return $this; }
    public function size() : int { return is_array($this->_x) ? count($this->_x) : ((empty($this->_x)) ? 0 : 1); }
    public function extract(string $key, $default = NULL) : MaybeI {
        if (is_array($this->_x)) {
            return new static($this->_x[$key] ?? $default);
        } else if (is_object($this->_x)) {
            return new static($this->_x->$key ?? $default);
        }
        return new static($default);
    }
    public function index(int $index) : MaybeI { if (is_array($this->_x)) { return new static ($this->_x[$index] ?? NULL); } return new static(NULL); }
    public function isa(string $type) : bool { return $this->_x instanceof $type; }
    public function __toString() { return is_array($this->_x) ? $this->_x : (string)$this->_x; }
    public function __isset($object) : bool { debug("isset"); if ($object instanceof MaybeA) { return (bool)$object->empty(); } return false; }
    public function __invoke(string $type = null) { return $this->value($type); }
}
class Maybe extends MaybeA {
    public function __invoke(string $type = null) { return $this->value($type); }
}
class MaybeBlock extends MaybeA {
    public function __invoke(string $type = null) { return $this->_x; }
}
class MaybeStr extends MaybeA {
    public function __invoke(string $type = null) { if (empty($this->_x)) { return ""; } return is_array($this->_x) ? $this->_x : (string)$this->_x; }
    public function compare(string $test) : bool { return (!empty($this->_x)) ? $this->_x == $test : false; }
}
Maybe::$FALSE = MaybeBlock::of(NULL);


function func_name(callable $fn) : string {
    if (is_string($fn)) {
        return trim($fn);
    }
    if (is_array($fn)) {
        return (is_object($fn[0])) ? get_class($fn[0]) : trim($fn[0]) . "::" . trim($fn[1]);
    }
    return ($fn instanceof \Closure) ? 'closure' : 'unknown';
}


// web-filter only
function recache2(string $in) : array {
    trace("RC".strlen($in));
    $path = explode("\n", decrypt_ssl(sha1(CFG::str("encryption_key")), $in)());
    trace("DE".count($path));
    $foo = array_reduce($path, function ($carry, $x) {
        if (!isset($carry['tmp'])) { $carry['tmp'] = $x; }
        else { $carry[$x] = $carry['tmp']; unset($carry['tmp']); }
        return $carry;
    }, array());
    if (empty($foo)) { return []; }
    unset($foo['tmp']);
    return $foo;
}

function recache2_file(string $filename) : array {
    if (!file_exists($filename)) { trace("rc2[]"); return array(); }
    return recache2(file_get_contents($filename));
}



/**
 * Encrypt string using openSSL module
 * @param string $text the message to encrypt
 * @param string $password the password to encrypt with
 * @return string message.iv
 */
function encrypt_ssl(string $password, string $text) : string {
    if (function_exists('openssl_encrypt')) {
        $iv = random_str(16);
        return openssl_encrypt($text, 'AES-128-CBC', $password, 0, $iv) . "." . $iv;
    }
    return base64_encode($text);
}

/**
 * aes-128-cbc decryption of data, return raw value
 * PURE
 */ 
function raw_decrypt(string $cipher, string $iv, string $password) : string {
    if (function_exists('openssl_decrypt')) {
        return openssl_decrypt($cipher, 'AES-128-CBC', $password, 0, $iv);
    }
    return base64_decode($cipher);
}

/**
 * Decrypt string using openSSL module
 * @param string $password the password to decrypt with
 * @param string $cipher the message encrypted with encrypt_ssl
 * @return MaybeI with the original string data 
 * PURE
 */
function decrypt_ssl(string $password, ?string $cipher) : MaybeI {
    // assert($password && strlen($password) >= 8, "password must be at least 8 characters");
    if (empty($cipher) || strlen($cipher) < 8) { 
        debug("wont decrypt with no encryption data");
        return MaybeStr::of(NULL);
    }

    $decrypt_fn = ƒixr("ThreadFin\\raw_decrypt", $password);

    $a = MaybeStr::of($cipher)
        ->then(ƒixl("explode", "."))
        ->keep_if(fn($x) => count($x) == 2)
        ->then($decrypt_fn, true);
    return $a;
}


/**
 * calls $carry $fn($key, $value, $carry) for each element in $map
 * allows passing optional initial $carry, defaults to empty string
 * PURE as $fn, returns $carry
 */
function map_reduce(array $map, callable $fn, $carry = "") {
    foreach($map as $key => $value) { $carry = $fn($key, $value, $carry); }
    return $carry;
}


/**
 * map each value in $map to $fn($value) and return the result. 
 * if $fn($value) returns NULL, the key is not added to the result
 */
function map_map_value(?array $map, callable $fn) : array {
    $result = [];
    if (empty($map)) { return $result; }

    foreach($map as $key => $value) {
        $tmp = $fn($value);
        if ($tmp !== NULL) {
            $result[(string)$key] = $tmp;
        }
    }
    return $result;
}


//  calls $fn($key, $value) on $data, return value will be a list, not a map
function array_map_value(callable $fn, array $data) : array {
    return array_map($fn, array_keys($data), array_values($data));
}


/**
 * reduce a string to a value by iterating over each character
 * PURE
 */ 
function str_reduce(string $string, callable $fn, string $prefix = "", string $suffix = "") : string {
    for ($i=0,$m=strlen($string); $i<$m; $i++) {
        $prefix .= $fn($string[$i]);
    }
    return $prefix . $suffix;
}


/**
 * match address 
 * @return bool 
 */
function cidr_match(string $address, string $subnetAddress, int $subnetMask) : bool {
    static $cache = [];
    $address = $cache[$address]??ip2long($address);
    $subnetAddress = $cache[$address]??ip2long($subnetAddress);
    $mask = -1 << (32 - $subnetMask);
    $subnetAddress &= $mask; // subnet wasn't correctly aligned
    $r = $address & $mask;
    return (($r) == $subnetAddress) && $subnetMask >= 0;
}


// write debug message return NULL
function debugN(string $fmt, ...$args) : ?bool {
    debug($fmt, ...$args);
    return NULL;
}

// write debug message and return 0
function debugZ(string $fmt, ...$args) : int {
    debug($fmt, ...$args);
    return 0;
}

// write debug message and return false
function debugF(string $fmt, ...$args) : bool {
    debug($fmt, ...$args);
    return false;
}


// allow trace to be over ridden
function trace(?string $msg = null, bool $clear = false) : string {
    static $r = "";
    if ($msg == null) { if ($clear) { $r = ""; } return $r; }
    $r .= "$msg, ";
    return "";
}

/**
 * call the error handler.  This will create at most 1 new error entry in errors.json
 * @param null|string $fmt 
 * @param mixed $args 
 * @return void 
 * @throws RuntimeException 
 */
function error(?string $fmt, ...$args) : void {
    debug($fmt, ...$args);
    $line = str_replace(array("\r","\n",":"), array(" "," ",";"), sprintf($fmt, ...$args));
    $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
    $idx = isset($bt[1]) ? 1 : 0;
    \BitFire\on_err(-1, $line, $bt[$idx]["file"], $bt[$idx]["line"]);
    if (isset($bt[2])) {
        \BitFire\on_err(2, $line, $bt[2]["file"], $bt[2]["line"]);
    }
}

function format_chk(?string $fmt, int $args) : bool {
    if ($fmt == null) { return true; }
    return(substr_count($fmt, "%") === $args);
}

/**
 * add a line to the debug file (SLOW, does not wait until processing is complete)
 * NOT PURE
 */
function debug(?string $fmt, ...$args) : ?array {
    assert(class_exists('\BitFire\Config'), "programmer error, call debug() before config is loaded");
    assert(format_chk($fmt, count($args)), "programmer error, format string does not match number of arguments [$fmt]");

    static $idx = 0;
    static $len = 0;
    static $log = [];
    static $early_exit = -1; 

    // format any objects or arrays for debug
    foreach ($args as &$arg) { 
        if (is_array($arg) || is_object($arg)) { $arg = json_encode($arg, JSON_PRETTY_PRINT); }
        // else { $arg = str_replace("%", "%%", $arg); }
    }


    $f = get_hidden_file("/debug.log");
    //$log = debug(null);
    $mode = (file_exists($f) && filesize($f) > 1024*1024*4) ? LOCK_EX : FILE_APPEND;
    file_put_contents($f, sprintf($fmt, ...$args) . "\n", FILE_APPEND);
    return [];

    // first call, figure out if we are exiting early. this executes 1 time
    if ($early_exit === -1) {
        $early_exit = (!CFG::enabled("debug_file") && !CFG::enabled("debug_header")) ? 1 : 0;
    }
    // if we are not debugging, return early
    if ($early_exit === 1 || empty($fmt)) {
        return (empty($fmt)) ? $log : null;
    }

    // ugly AF
    if ($fmt === null) { return $log; }

    $line = "";
    // write debug to headers for quick debug
    if (CFG::enabled("debug_header")) {
        $line = str_replace(array("\r","\n",":"), array(" "," ",";"), @sprintf($fmt, ...$args));
        if (!headers_sent() && $idx < 24) {
            $s = sprintf("x-bf-%02d: %s", $idx, substr($line, 0, 1024));
            $len += strlen($s);
            if ($len < 3000) {
                header($s);
            }
        }
    }

    // write to file
    if (CFG::enabled("debug_file")) {
        if ($idx === 0) {
            register_shutdown_function(function () {
                $f = get_hidden_file("/debug.log");
                $log = debug(null);
                $mode = (file_exists($f) && filesize($f) > 1024*1024*4) ? LOCK_EX : LOCK_EX | FILE_APPEND;
                file_put_contents($f, join("\n", $log), $mode);
            });
        }
        $line = sprintf($fmt, ...$args);
        if (starts_with($fmt, "ERROR")) {
            $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
            //print_r($bt);
            $b1 = isset($bt[2]) ? ($bt[2]['file']??'??'.':'.$bt[2]['line']??'??') : 'no-bt2';
            $b2 = isset($bt[3]) ? ($bt[3]['file']??'??'.':'.$bt[3]['line']??'??') : 'no-bt3';
            $line = "$line\nB1: $b1\nB2: $b2";
        }
    }
    
    $idx++;
    if (!empty($line)) { $log[] = $line; }
    return null;
}




/**
 * sets a cookie in a browser in various versions of PHP
 * NOT PURE 
 */
function cookie(string $name, ?string $value, int $exp = DAY) : void {
    if (!CFG::enabled("cookies_enabled")) { debug("wont set cookie, disabled"); return; }
    if ($value != '1' && $value != '3') { // always set a javascript client side cookie!
        if (count($_COOKIE) == 0) { debug('no cookie support'); return; }
        if (!isset($_COOKIE['wordpress_test_cookie'])) { debug('cookie not logged in'); return; }
    }

    if (headers_sent($file, $line)) { debug("unable to set cookie, headers already sent (%s:%d)", $file, $line); return; }
    if (PHP_VERSION_ID < 70300) { 
        setcookie($name, $value, time() + $exp, '/; samesite=strict', '', false, false);
    } else {
        setcookie($name, $value, [
            'expires' => time() + $exp,
            'path' => '/',
            'domain' => '',
            'secure' => false,
            'httponly' => false,
            'samesite' => 'strict'
        ]);
    }
}


/**
 * replace file contents inline, $find can be a regex or string
 */
function file_replace(string $filename, string $find, string $replace, int $mode = 0) : Effect {
    $fn_name = ($find[0] == "/") ? "preg_replace" : "str_replace";
    $fn = partial($fn_name, $find, $replace);

    $file_mod = FileData::new($filename)->read()->map($fn)->file_mod($mode);
    return Effect::new()->file($file_mod);
}


/**
 * return an effect to create a ini_info.php file which sets
 * a variable $ini_type to the type of ini file used. we do
 * this here because some wordpress servers do not always
 * allow us to write php files on any request.
 * @return Effect 
 */
function make_config_loader() : Effect {
    $effect = Effect::new();
    if (defined("BitFire\WAF_INI")) { return $effect->out(\BitFire\WAF_INI)->hide_output(); }


    // FIRST, lets verify that we already have a valid config
    // if so we bail out early here...
    $parent = dirname(WAF_ROOT, 1);
    $file = \BitFire\WAF_ROOT."ini_info.php";
    if (file_exists($file)) {
        $secret_key = "";
        include $file;
        $config_file = $parent . "/bitfire_{$secret_key}/config.ini";
        if (file_exists($config_file)) {
            define("BitFire\WAF_INI", $config_file);
            return $effect->out($config_file)->hide_output();
        }
    }
    // ini_info was invalid, reset the key
    $secret_key = "";

    // we don't know where the config is because there is no ini_info file
    // probably a first run, or a new install, lets find it
    // find all old configs
    $config_dirs = glob("{$parent}/bitfire_??????????");

    // get the creation/modification time so we can find most recent
    $dir_with_time = array_map(function($dir) {
        return [ "dir" => $dir, "time" => filemtime($dir) ];
    }, $config_dirs);
    usort($dir_with_time, function($a, $b) {
        return $a["time"] - $b["time"];
    });
    // if we have existing dirs, then lets use the most recent config
    if (count($dir_with_time) > 0) {
        $newest = array_pop($dir_with_time);
        if (preg_match("/bitfire_(\w+)/", $newest["dir"], $matches)) {
            $secret_key = $matches[1];
            while($next = array_pop($dir_with_time)) {
                // delete all but the newest
                $effect->unlink($next["dir"]);
            }
        }
    }
    // no old configs, lets create a new one
    if (empty($secret_key)) {
        $secret_key = random_str(10);
        // check if the hidden config has not yet been moved and move it
        $path = $parent . "/bitfire_{$secret_key}/";
        $orig_config = WAF_ROOT . "hidden_config";
        if (file_exists($orig_config)) {
            rename($orig_config, $path);
        }
    }

    // we should have a secret key by now, lets update the ini_info file
    if (!empty($secret_key)) {
        $markup = "<?"."php \$secret_key = '$secret_key'; ";
        if (function_exists("shmop_open")) {
            $markup .= '$ini_type = "shmop";';
        } else {
            $markup .= '$ini_type = "opcache";';
        }
        $effect->file(new FileMod(\BitFire\WAF_ROOT."ini_info.php", $markup));
    }

    $path = $parent . "/bitfire_{$secret_key}/";
    define("BitFire\WAF_INI", $path . "config.ini");
    return $effect->out($path . "config.ini")->hide_output();
}



/**
 * get the path to a hidden file
 * @param string $file_name the name of the file
 * @param (null|string)|null $secret_key - the secret key as stored in the ini_info.php file
 * @return string - the realpath to the file
 */
function get_hidden_file(string $file_name, ?string $secret_key = null) : string {
    static $path = null;
    //if (php_sapi_name() === "cli") { return getcwd() . "/$file_name"; }

    // use the secret key passed to us
    if (!empty($secret_key)) {
        $parent = dirname(WAF_ROOT, 1);
        $path = realpath($parent . "/bitfire_{$secret_key}/") . "/";
    }
    // fall back to the secret key in the ini_info file
    if (empty($path)) {
        $path = dirname(make_config_loader()->read_out(), 1) . "/";
    }
    return $path . $file_name;
}

/**
 * load the config from the secret config location
 * @return array 
 * @throws RuntimeException 
 */
function parse_ini() : array {
    //$ini_type = "opcache";

    $loader = make_config_loader()->run();
    $config_file = $loader->read_out();
    $cache_config_file = $config_file . ".php";

    // return a core config with everything off if the config file is not found...
    if (!file_exists($config_file)) {
        return [
            "bitfire_enabled" => false,
            "allow_ip_block" => false,
            "security_headers_enabled" => false,
            "log_everything" => false,
            "web_filter_enabled" => false,
            "require_full_browser" => false,
            "whitelist_enable" => false,
            "blacklist_enable" => false,
            "cache_type" => "nop",
            "ip_header" => "remote_addr",
            "wizard" => false
        ];
    }

    // get the ini file modification time
    $mod_time = @filemtime($config_file);

    // if the file modification time is newer than the cached data, reload the config
    // if (!isset($options[1]) || $options[1] < $mod_time) {
    if (!file_exists($cache_config_file) || filemtime($cache_config_file) < $mod_time) {
        
        $config = parse_ini_file($config_file, false, INI_SCANNER_TYPED);
        //$c = count($config);
        //die("config [$c]\n");
        if (is_array($config) && count($config) > 20) {
            // ensure that passwords are always hashed
            $pass = $config['password']??'disabled';
            if (strlen($pass) < 40 && $pass != 'disabled' && $pass != 'configure') {
                $hashed = hash('sha3-256', $pass);
                $config['password'] = $hashed;
                require_once WAF_SRC . "server.php"; // make sure we have the correct function loaded
                update_ini_value('password', $hashed)->run();
            }
            $s = var_export($config, true);
            $priority = "1";
            $exp = time() + 86400*7; 
            $data = "<?php \$value = $s; \$priority = $priority; \$success = (time() < $exp);";
            file_put_contents($cache_config_file, $data, LOCK_EX) == strlen($data);
        }
        else {
            require_once WAF_SRC . "server.php";
            $config = save_config2($config_file);
        }
    }

    if (file_exists($cache_config_file)) {
        include $cache_config_file;
        if (isset($value) && count($value) > 20) {
            $config = $value;
        } else {
            // does not exist.. don't delete if the config edit failed!
            unlink($cache_config_file);
        }
    }

    // if we have a pro key, then download the latest pro version of code
    check_pro_ver($config["pro_key"]??"");
    if (!defined("BitFire\LOG_NUM")) {
        define("BitFire\LOG_NUM", 327680);
    }

    return $config;
}



/**
 * impure fetch pro code and install
 * @param string $pro_key 
 */
function check_pro_ver(string $pro_key) {
    // pro key and no pro files, download them UGLY, clean this!
    if (!is_writable(\BitFire\WAF_SRC)) {
        // TODO: add WordPress notice from here....
        debug("unable to write PRO file to [%s]", \BitFire\WAF_SRC);
        return;
    }

    $profile = \BitFire\WAF_SRC . "proapi.php";
    if (strlen($pro_key) > 20 && (!file_exists($profile) || (file_exists($profile) && @filesize(\BitFire\WAF_SRC."proapi.php") < 512))) {
        trace("DOWN_PRO");
        $email = "unknown";
        $name = "unknown";
        if (defined("WPINC") && function_exists("wp_get_current_user")) {
            $user = \wp_get_current_user();
            $name = $user->user_firstname . " " . $user->user_lastname;
        }
        $out = \BitFire\WAF_SRC."pro.php";
        $content = http("POST", "https://bitfire.co/getpro.php", array("name" => $name, "email" => $email, "release" => \BitFire\BITFIRE_VER, "key" => $pro_key, "domain" => $_SERVER['SERVER_NAME'],"filename" => "pro.php"));
        debug("downloaded pro code [%d] bytes", strlen($content->content));
        if ($content && strlen($content->content) > 512) {
            if (@file_put_contents($out, $content->content, LOCK_EX) !== strlen($content->content)) { debug("unable to write [%s]", $out); };
            $content = http("POST", "https://bitfire.co/getpro.php", array("name" => $name, "email" => $email, "release" => \BitFire\BITFIRE_VER, "key" => $pro_key, "domain" => $_SERVER['SERVER_NAME'], "filename" => "proapi.php"));
            debug("downloaded proapi code [%d] bytes", strlen($content->content));
            $out = \BitFire\WAF_SRC."proapi.php";
            if ($content && strlen($content->content) > 100) {
                if (@file_put_contents($out, $content->content, LOCK_EX) !== strlen($content->content)) { debug("unable to write [%s]", $out); };
            }
        }
    }
}


/**
 * effect with cache prevention headers
 * PURE: IDEMPOTENT, REFERENTIAL INTEGRITY
 */
function cache_prevent(Effect $effect = null) : Effect {
    if ($effect == null) {
        $effect = new Effect();
    }
    $effect->header("cache-control", "no-store, private, no-cache, max-age=0");
    $effect->header("expires", gmdate('D, d M Y H:i:s \G\M\T', 100000));
    $effect->header("vary", "*");
    return $effect;
}


// return date in utc time
function utc_date(string $format) : string {
    return date($format, utc_time());
}

function utc_time() : int {
    return time() + date('Z');
}


// only used in botfilter
function array_shuffle(array $in) : array {
    $out = array();
    while(($m = count($in))>0) {
        $t = array_splice($in, random_int(0, $m) , 1);
        $out[] = $t[0]??0;
    }
    return $out;
}

/**
 * returns a maybe with tracking data or an empty monad...
 * PURE!
 */
function decrypt_tracking_cookie(?string $cookie_data, string $encrypt_key, string $src_ip, string $agent) : MaybeI {
    static $r = null;
    // don't bother decrypting if we have no cookie data
    if (empty($cookie_data)) { return MaybeStr::of(false); }
    if ($r === null) { $r = MaybeStr::of(false); }

    $r->do_if_not(function() use ($cookie_data, $encrypt_key, $src_ip, $agent) {

        return decrypt_ssl($encrypt_key, $cookie_data)
            ->then("ThreadFin\\un_json")
            ->keep_if(function($cookie) use ($src_ip, $agent) {
                if (!isset($cookie['wp']) && !isset($cookie['ip']) && !isset($cookie['lck']) && !isset($cookie['mfa'])) {
                    debug("invalid decrypted cookie [%s] ", var_export($cookie, true));
                    return false;
                } else if (isset($cookie['ip'])) {
                    $src_ip_crc = crc32($src_ip);
                    $cookie_match = (is_array($cookie) && (intval($cookie['ip']??0) == intval($src_ip_crc)));
                    $time_good = ((intval($cookie['et']??0)) > time());
                    $agent_good = crc32($agent) == $cookie['ua'];
                    if (!$cookie_match) { debug("cookie ip does not match"); }
                    if (!$time_good) { debug("cookie expired"); }
                    if (!$agent_good) { debug("agent mismatch live: [%s] [%d] cookie:[%d]", $agent, crc32($agent), $cookie['ua']??0); }
                    return ($cookie_match && $time_good && $agent_good);
                } else { return true; }
            });
    });
    return $r;
}



/**
 * @depends CFG:cms_root, cms_content_dir, cms_content_url, _SERVER: DOCUMENT_ROOT
 * @return string URL path to the public folder
 */
function get_public(?string $path = null) : string {
    // try and find the path to the public folder ourself (for standalone installs)
    $public = realpath(__DIR__ . "/../public/$path").DS;
    $dr = realpath($_SERVER['DOCUMENT_ROOT']??".");
    $public = str_replace($dr, "", $public);
    if ($path !== null) { $public = rtrim($public, "/"); }
    // if we have a cms configuration, use that
    if (CFG::enabled("cms_root")) {
        $path = ($path === null) ? "" : $path;
        if (file_exists(CFG::str("cms_content_dir") . "/plugins/bitfire/public/$path")) {
            $public = CFG::str("cms_content_url")."/plugins/bitfire/public/$path";
        }
    }
    return $public;
}

function _b(string $text, $before = "") : string {
    return (string)$before . _($text);
}

function _t(string $text) : string {
    return $text;
}


/**
 * @param mixed $data 
 * @return array [compressed_data, uncompressed_size, type]
 */
function compress($data) : array {
    $type = "serialize";
    // we have a header we can write cache data to...
    if (function_exists('\igbinary_serialize')) {
        $compress = \igbinary_serialize($data);
        $type = "igbinary";
    } else if (function_exists('\msgpack_unpack')) {
        $compress = \msgpack_pack($data);
        $type = "msgpack";
    } else {
        $compress = serialize($data);
    }
    return [base64_encode($compress), strlen($data), $type];
}


/**
 * return original data from compressed data
 * @param array $data 
 * @return mixed 
 */
function uncompress(array $data) {
    $compress = base64_decode($data[0]);
    switch ($data[2]) {
        case "igbinary":
            return \igbinary_unserialize($compress);
        case "msgpack":
            return \msgpack_unpack($compress);
        default:
            return unserialize($compress);
    }
}


class Entity implements ArrayAccess {
    public function __construct() { }

    public function offsetExists($offset): bool {
        return isset($this->$offset);
    }

    #[\ReturnTypeWillChange]
    public function offsetGet($offset) {
        return $this->$offset;
    }

    public function offsetSet($offset, $value): void {
        $this->$offset = $value;
    }

    public function offsetUnset($offset): void {
        unset ($this->$offset);
    }

    /**
     * take a string of JSON and return an entity of this class
     * @param string $json 
     * @throws InvalidArgumentException is json is invalid
     * @return static 
     */
    public static function from_json(string $json, string $root = "") {
        $data = json_decode($json, false, 512, JSON_ERROR_SYNTAX);
        if ($data === NULL) {
            throw new InvalidArgumentException("error decoding json into " . static::class . " : " . json_last_error_msg());
        }
        return cast(static::class, $data, $root);
    }
}



function cast_assign(Entity $entity, stdClass $obj) {

    foreach ($obj as $key => $value) {
        if (is_array($value)) {
            $t = get_class($entity->$key);
            if (substr($t, -5) == "_List") {
                $class = substr($t, 0, -5);
                $entity->$key = new $t($value, $class);
                continue;
            }
        } else if (is_object($value)) {
            if (!isset($entity->$key)) {
                $rc = new ReflectionClass($entity);
                if (!$rc->hasProperty($key)) {
                    throw new InvalidArgumentException(get_class($entity) . " does not have property named [$key]");
                }
                $rp = $rc->getProperty($key);
                $t = (string)$rp->getType();
            } else {
                $t = get_class($entity->$key);
            }
            $obj = new $t();
            $entity->$key = cast_assign($obj, $value);
        } else {
            $entity->$key = $value;
        }
    }
    return $entity;
}

function cast(string $type, stdClass $obj, $root = "") {
    if ($root !== "") {
        return cast_assign(new $type(), $obj->$root);
    }
    return cast_assign(new $type(), $obj);
}

class Hash_Config {
    public string $hash;
    public int $valid_seconds;
    public int $trim_len;
    public function __construct($hash = "sha256", $valid_seconds = HOUR * 6, $trim_len = 99) {
        $this->hash = $hash;
        $this->valid_seconds = $valid_seconds;
        $this->trim_len = $trim_len;
    }
}

// create a new hmac code for validate_code
function make_code(string $secret, Hash_Config $config, int $time = 0) : string {
    $iv = strtolower(random_str(12));
    if ($time == 0) {
        $time = time();
    }
    $data = "$iv.$time";
    $h = hash_hmac($config->hash, $data, $secret, false);
    $hash = substr($h, 0, $config->trim_len);
    return "{$hash}.{$iv}.{$time}";
}

function validate_raw(string $test_hmac, string $iv, string $time, string $secret, Hash_Config $config) : bool {
    $t = intval($time);
    $secret = strlen($secret) < 5 ? "default" : $secret;
    $data = ($t === 0) ? $iv : "{$iv}.{$time}";
    $h = hash_hmac($config->hash, $data, $secret, false);
    $d3 = substr($h, 0, $config->trim_len);

    $diff = time() - $t;
    if ($t > 0 && $diff > $config->valid_seconds) {
        $hours = floor($config->valid_seconds / HOUR);
        debug("hmac expired (%d hour maximum) [%s] %s", $hours, $diff, $test_hmac);
        return false;
    }

    return hash_equals($d3, $test_hmac);
}

// validate $hash was generated with make_code($secret)
function validate_code(string $hash, string $secret, ?Hash_Config $config = null) : bool {
    $parts = explode(".", $hash);
    if ($config === null) { $config = new Hash_Config(); }
    return validate_raw($parts[0]??"", $parts[1]??"", $parts[2]??"", $secret, $config);
}
