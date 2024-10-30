<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 */

namespace ThreadFin;
use \BitFire\Config as CFG;

use function BitFireSvr\add_ini_value;
use function BitFireSvr\update_ini_value;

use const BitFire\CACHE_LOW;
use const BitFire\Data\CACHE;
use const BitFire\WAF_ROOT;
use const BitFire\WAF_SRC;

/**
 * generic storage interface for temp / permanent storage
 */
interface Storage {
    public function save_data(string $key_name, $data, int $ttl) : bool;
    public function load_data(string $key_name);
    public function load_or_cache(string $key_name, int $ttl, callable $generator);
    public function update_data(string $key_name, callable $fn, callable $init, int $ttl);
    public function delete();
}

/**
 * Abstraction around a single cache entry
 */
class CacheItem {
    public $key;
    public $fn;
    public $init;
    public $ttl;
    public $flags;

    public function __construct(string $key_name, callable $fn, callable $init, int $ttl, int $flags = CACHE_LOW) {
        $this->key = $key_name;
        $this->fn = $fn;
        $this->init = $init;
        $this->ttl = $ttl;
        $this->flags = $flags;
    }
}

/**
 * trivial cache abstraction with support for apcu, shared memory and zend opcache 
 */
class CacheStorage implements Storage {
    protected static $_type = 'nop';
    protected static $_instance = null;
    protected $_shmop = null;
    public $expires = -1;

    /**
     * delete all stored cache data including shmop and semaphores
     * @return void 
     */
    public function delete() {
        // remove semaphores
        $opt = (PHP_VERSION_ID >= 80000) ? true : 1;
        if (function_exists('sem_get')) {
            $sem = sem_get(0x228AAAE7, 1, 0660, $opt);
            if ($sem) { sem_remove($sem); }
            // remove all semaphores...
            for ($i = 0; $i < 16; $i++) {
                $sem = sem_get(CFG::int("cache_token") + $i, 1, 0660, $opt);
                if ($sem) { sem_remove($sem); }
            }
        }

        // remove any old op cache
        do_for_each(glob(WAF_ROOT."data/*.profile", GLOB_NOSORT), 'unlink');
        do_for_each(glob(WAF_ROOT."data/objects/*", GLOB_NOSORT), 'unlink');

        include_once \BitFire\WAF_ROOT."src/cuckoo.php";
        if (class_exists("\ThreadFin\cuckoo")) {
            cuckoo::delete();
        } else {
            debug("no cuckoo present");
        }
    }

    /**
     * get a reference to cache singleton
     * @param null|string $type - default to config value. 'apcu', 'shmop', 'opcache'
     * @return CacheStorage 
     */
    public static function get_instance() : CacheStorage {
        if (self::$_instance === null) {
            $type = CFG::str("cache_type", "nop");

            self::$_instance = new CacheStorage($type);
            // incase we have old cache, delete it and recreate it to refactor the memory space
            if (CFG::enabled("mem_refactor") == false) {
                self::$_instance->delete();
                self::$_instance = new CacheStorage($type);
                require_once WAF_SRC . "server.php";

                // make sure we set that memory has been refactored in config...
                add_ini_value("mem_refactor", "true", "shared memory refactored")->run(); 
                update_ini_value("mem_refactor", "true")->run(); 
            }
        }
        return self::$_instance;
    }


    /**
     * set the cache type and create new implementation
     */
    protected function __construct(?string $type = 'nop') {
        assert(in_array(self::$_type, ['nop', 'shmop', 'opcache']), "must call set_type before using cache");
        if ($type === "shmop" && function_exists('shmop_open')) {
            require_once \BitFire\WAF_SRC . "cuckoo.php";
            $this->_shmop = new cuckoo();
            self::$_type = $type;
        }
        else {
            // one in 500 requests - clean the cache
            if ($type == "opcache" && mt_rand(0, 500) < 2) {
                $this->clean_cache();
            }
            self::$_type = $type;
        }
    }

    public function export() {
        if (isset($this->_shmop)) {
            return $this->_shmop->export();
        }
    }

    public function get_cuckoo() {
        return $this->_shmop;
    }

    // called by constructor to delete expired files older than 1 hour
    public function clean_cache() {
        // 0.5% cleanup old cache files
        $cache_file_list = glob(WAF_ROOT."data/objects/*");
        $t = time();
        array_walk($cache_file_list, function ($file) use ($t) {
            $success = false;
            $path = realpath($file);
            // delete expired stuff older than 12 day
            if (file_exists($path) && $t > filemtime($path) + (HOUR * 12)) {
                @include ($path);
                if (!$success) {
                    @unlink($file);
                }
            }
        });
    }


    /**
     * @return string opcode cache file path for a given key
     */
    protected function key2name(string $key) : string {
        $dir =  \BitFire\WAF_ROOT . "data/objects/";
        if (!file_exists($dir)) {
            mkdir($dir, 0775, true);
        }
        return $dir . $key;
    }

    /**
     * save data to key name
     */
    public function save_data(string $key_name, $data, int $seconds, int $priority = CACHE_LOW) : bool {
        assert(self::$_type !== null, "must call set_type before using cache");

        switch (self::$_type) {
            case "shmop":
                if (!empty($this->_shmop)) {
                    $success = $this->_shmop->write($key_name, $seconds, $data, $priority);
                    if ($success) {
                        trace("OKW+:$key_name");
                    } else {
                        trace("FAIL_W+:$key_name");
                    }
                    return $success;
                } else {
                    trace("FAIL_w+:$key_name");
                }
                return false;
            case "opcache":
                $object_file = $this->key2name($key_name);
                // remove cache data
                if ($data === null || $seconds < 0) { 
                    if (file_exists($object_file)) {
                        return unlink($this->key2name($key_name));
                    }
                }
                // store cache data
                else {
                    $s = var_export($data, true);
                    $exp = time() + $seconds; 
                    $data = "<?php \$value = $s; \$priority = $priority; \$success = (time() < $exp);";
                    return file_put_contents($object_file, $data, LOCK_EX) == strlen($data);
                }
            default:
                return false;
        }
    }

    /**
     * this function is non-blocking. will return null if lock cannot be acquired
     * @param string $key_name 
     * @param int $lock_type 
     * @return resource|SysvSemaphore|null 
     */
    public static function lock(string $key_name, int $lock_type = 1) {
        $sem = null;

        // acquire semaphore lock
        if (function_exists('sem_acquire') && CFG::str('lock_type', 'flock') == "sem") {
            $opt = (PHP_VERSION_ID >= 80000) ? true : 1;
            $sem = sem_get(CFG::int('cache_token') + $lock_type, 1, 0666, $opt);
            if (!empty($sem)) {
                trace("LCK-$lock_type");
                return (sem_acquire($sem, true)) ? $sem : null;
            }
            // fall back to flock
            else {
                require_once WAF_SRC . "server.php";
                update_ini_value("lock_type", "flock")->run();
            }
        }

        // flock fallback..
        $base_dir = get_hidden_file("bitfire_locks");
        if (!file_exists($base_dir)) {
            mkdir($base_dir, 0775, true);
        }
        $lock_file = $base_dir."/$key_name-$lock_type".php_sapi_name();
        $fp = fopen($lock_file, "w+");

        // 1% of the time clean up old lock files
        if (random_int(1,100) == 50) {
            trace("CLEAN_LOCKS");
            $files = glob($base_dir."/*");
            foreach ($files as $file) {
                if (filemtime($file) < (time() - 60)) {
                    @unlink($file);
                }
            }
        }

        if (!empty($fp) && is_resource($fp)) {
            return flock($fp, LOCK_EX | LOCK_NB, $block) ? $fp : null;
        }
        return null;
    }
    
    // unlock the semaphore if it is not null
    public static function unlock($sem) {
        if ($sem != null) {
            $t = gettype($sem);
            if ($t == "resource") {
                flock($sem, LOCK_UN);
            }
            else if ($t == "object") {
                sem_release(($sem));
            }
        }
    }

    /**
     * update cache entry @key_name with result of $fn or $init if it is expired.
     * NOTE!: DATA IS LOCKED, READ, UPDATED AND UNLOCKED
     * return the cached item, or if expired, init or $fn
     * @param $update_fn($data) called with the original value, saves with returned value
     */
    public function update_data(string $key_name, callable $update_fn, callable $init_fn, int $ttl, int $priority = CACHE_LOW) {
        // handle no cache case first
        if (self::$_type == 'nop') { return $init_fn(); }

        // reduce contention by using 16 different semaphore locks ... 
        $lock_id = crc32($key_name) % 16;
        $sem = $this->lock($key_name, $lock_id);
        $data = $this->load_data($key_name);
        if ($data === null) {
            trace("INIT!");
            $data = $init_fn();
        }
        $updated = $update_fn($data);

        $this->save_data($key_name, $updated, $ttl, $priority);
        $this->unlock($sem);
        return $updated;
    }

    public function load_data(string $key_name, $init = null, ?string $type = null) {



        $value = null;
        $success = false;

        switch (self::$_type) {
            case "shmop":
                $tmp = $this->_shmop->read($key_name, $type);
                $success = ($tmp !== NULL);
                $value = ($success) ? $tmp : NULL;
                break;
            case "opcache":
                $file = $this->key2name($key_name);
                if (file_exists($file)) {
                    @include($file);
                    // remove expired data
                    if (!$success) {
                        @unlink($file);
                    }
                }
                break;
            default: 
                break;
        }

        if ($success) {
            // load failed
            if (is_bool($value) && !$value) {
                return (is_callable($init)) ? $init() : $init;
            }
            // type checking..
            if ($type !== null) {
                if (gettype($value) == $type || $value instanceof $type) {
                    trace("OKT[$key_name]");
                    return $value;
                }
                return $init;
            }
            trace("OKR[$key_name]");
            return $value;
        }

        trace("MISS[$key_name]");
        return ($init !== null && is_callable($init)) ? $init() : $init;
    }

    /**
     * load the data from cache, else call $generator
     */
    public function load_or_cache(string $key_name, int $ttl, callable $generator) {
        if (($data = $this->load_data($key_name)) === null) {
            $data = $generator();
            assert(is_array($data) || is_string($data), "$key_name generator returned invalid data (" . gettype($data) . ")");
            $this->save_data($key_name, $data, $ttl);
        }
        // assert(is_array($data) || is_string($data), "$key_name cache returned invalid data (" . gettype($data) . ")");
        return $data;
    }

    public function clear_cache() : void {
        switch (self::$_type) {
            case "shmop":
                trace("CLR_CH");
                $this->_shmop->clear();
                break;
        }
    }
}

