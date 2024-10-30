<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * Shared memory LRU cuckoo cache. Caches client IPData in memory and internal server statistics.
 * 
 * memory layout: [header/memory, header/memory, header/memory,...]
 * keys map to 2 headers, if one header is occupied, the other is used.
 * memory locations are 128 bytes.  custom packed data is stored in 
 * the memory location. This is MUCH more efficient than serialization
 * and allows for much better memory usage.
 */

namespace ThreadFin;

use BitFire\Config;
use BitFire\IPData;
use ValueError;

use const BitFire\CACHE_HIGH;
use const BitFire\CACHE_IGB;
use const BitFire\CACHE_LOW;
use const BitFire\CACHE_MSG_PAK;
use const BitFire\CACHE_PACK;
use const BitFire\CACHE_SERIAL;
use const BitFire\CACHE_STALE_OK;
use const BitFire\P16;
use const BitFire\P32;
use const BitFire\P8;
use const BitFire\PS;

use function BitFireSvr\update_ini_value;

const CUCKOO_SLOT_SIZE_BYTES = 19;
const CUCKOO_EXP_SIZE_BYTES = 6;
const CUCKOO_CHUNK = 128;
const CUCKOO_MEM_CHUNK = CUCKOO_CHUNK + CUCKOO_SLOT_SIZE_BYTES;
const CUCKOO_MAX_SIZE = 4096;
const CUCKOO_MIN_FREE = 4096 * 64;


const CUCKOO_MEM_EXTRA  = 8; // num bytes at end of memory segment

const CUCKOO_STAT_SIZE  = 4096; // reserve 4KB for stats


const CUCKOO_DATA_HDR_SIZE = 19;
const CUCKOO_DATA_UNPACK = P32 . 'preamble/' . P32 . 'hash1/' . P32 . 'hash2/' . P32 . 'expires/' . 
    P16 . 'len/' . P8 . 'flags/' . 'a'. CUCKOO_CHUNK .'data';
const CUCKOO_DATA_PACK = P32 . P32 . P32 . P32 . P16 . P8 . 'a' . CUCKOO_CHUNK;





class cuckoo_ctx
{
    public $rid;
    public int $mem_start;
    public int $mem_end;
    public int $slots;
    public int $now;
    public int $chunk_size;

    public int $preamble;

    /**
     * @param int $offset to write $data to
     * @param string $data cuckoo_data_prep packed data 
     * @param int $expected_len if passed, will log error if write length does not match
     * @return bool return true if write was successful
     */
    public function write_raw(int $offset, string $data, int $expected_len = 0): bool {
        assert($offset >= 0 && !empty($data), "invalid write offset/data");
        assert(($offset + $expected_len) <= $this->mem_end + CUCKOO_MEM_EXTRA, "write offset past end of memory segment: $offset / $expected_len");
        assert(strlen($data) <= CUCKOO_MEM_CHUNK, "data too large to write to cache: " . strlen($data) . " / " . CUCKOO_CHUNK);

        if (function_exists('shmop_write') == false) {
            return false;
        }

        $wrote = shmop_write($this->rid, $data, $offset);
        if ($expected_len == 0) { $expected_len = strlen($data); }

        if ($wrote == 0 || $expected_len > 0 && $wrote != $expected_len) {
            trace("w+fail($wrote/$expected_len)@$offset");
            return debugN("shmop unable to write %d bytes @%d", $expected_len, $offset);
        }

        return true;
    }

    public function read(int $offset, int $len, string $packing) : ?array {
        assert($offset >= 0 && $len > 0, "invalid read offset/len ($offset / $len)");
        assert($offset <= $this->mem_end, "read past end of memory: $offset, {$this->mem_end}");

        if (function_exists('shmop_write') == false) {
            return false;
        }

        try {
            $bytes = shmop_read($this->rid, $offset, $len);
        } catch(ValueError $e) {
            debug("value error, deleting cache to recreate stats memory");
            shmop_delete($this->rid);
        }
        if ($bytes === false) {
            trace("r_fail:$len@$offset");
            debug("shmop unable to read %d bytes @%d", $len, $offset);
            return null;
        }

        $result = unpack($packing, $bytes);
        if (is_array($result)) {
            return $result;
        }
        trace("pak_fail:$len@$offset");
        debug("unpack failed: %d bytes @%d", $len, $offset);
        return null;
    }
}


class cuckoo_header
{
    public int $hash1;
    public int $hash2;
    // the maximum length of the memory segment pointed to by this header
    public int $len;
    public int $flags;
    public int $expires;
    public $data;
    public string $key = '';
    public int $preamble;

    public function __construct(string $key = '') {
        $this->key = $key;
    }

    public static function from(array $properties): cuckoo_header
    {
        $header = new cuckoo_header();
        foreach ($properties as $key => $value) {
            $header->$key = $value;
        }
        return $header;
    }

}


/**
 * find a key's 2 locations 
 * @param string $key
 * @param int $ttl - time to live in seconds, 0 to not set
 * @param int $flags - CACHE_HIGH or CACHE_LOW
 */
function new_header(string $key, int $ttl = 0, int $flags = 0): cuckoo_header
{
    static $preamble = null;
    if ($preamble == null) {
        $preamble = Config::int('cache_preamble', 1622747953);
    }
    $expires = $ttl > 0 ? time() + $ttl : 0;
    $header = new cuckoo_header($key);
    $header->hash1 = crc32($key);
    $header->hash2 = crc32("alt-$key-alt");
    $header->key = $key;
    $header->expires = $expires;
    $header->flags = $flags;
    $header->preamble = $preamble;

    return $header;
}


/**
 * note: right now, only on IPData is support for CACHE_PACK
 * @param array $header 
 * @return null|string 
 */
function cuckoo_deprep(array $header, ?string $type = null) {
    if (empty($header['data'])) {
        return null;
    }
    $x = null;
    $data = substr($header['data'], 0, $header['len']);
    if ($header['flags'] & CACHE_IGB) {
        $x = \igbinary_unserialize($data);
        if (empty($x)) {
            debug("igbinary unserialize");
        }
    } else if ($header['flags'] & CACHE_MSG_PAK) {
        $x = msgpack_unpack($data);
    } else if ($header['flags'] & CACHE_SERIAL) {
        $x = unserialize($data);
    } else if ($header['flags'] & CACHE_PACK) {
        if ($header['len'] > 90) {
            $x = IPData::unpack($header['data']);
        }
    }
    else {
        $x = $data;
    }
    return (empty($x)) ? null : $x;
}


/**
 * prep $item for writing to cache, strings are written as is, objects are serialized
 * @return string CUCKOO_DATA_PACK, ($flags, strlen($data), $data)
 */
function cuckoo_prep_data(int $preamble, cuckoo_header $header) : ?string {
    // debug("cuckoo_prep: %s", json_encode($header));
    if (is_object($header->data) && $header->data instanceof \ThreadFin\packable) {
        trace("PAK");
        $data = $header->data->pack();
    }
    else if (!is_string($header->data)) {
        // we have a header we can write cache data to...
        if (function_exists('\igbinary_serialize')) {
            trace("IGB");
            $data   = \igbinary_serialize($header->data);

            $header->flags |= CACHE_IGB;
        } else if (function_exists('\msgpack_unpack')) {
            $data   = \msgpack_pack($header->data);
            $header->flags |= CACHE_MSG_PAK;
        } else {
            trace("SRL");
            $data   = serialize($header->data);
            $header->flags |= CACHE_SERIAL;
        }
    }
    else {
        trace("STR");
        $data = $header->data;
    }


    $len = strlen($data);
    if ($len > CUCKOO_CHUNK) {
        trace("FAT_DATA");
        return null;
    }
    $header->len = $len;
    /*
    if ($header->flags & CACHE_IGB) {
        $x = substr($data, 0, $len);
        $o1 = igbinary_unserialize($data);
        $o2 = igbinary_unserialize($x);
        dbg([$data, $x, $o1, $o2], "IGB DEBUG");
    }
    debug("igb deser: (%s)", $o1);
    trace("LN:$len");
    */

    // return the cuckoo packed data
    return pack(CUCKOO_DATA_PACK, $preamble, $header->hash1, $header->hash2,
        $header->expires, $header->len, $header->flags, $data);
}




function header_match(cuckoo_header $header1, array $header2) : bool 
{
    $m = ($header2['preamble'] == Config::int('cache_preamble', 1622747953) &&
        $header1->hash1 === $header2['hash1'] && $header1->hash2 === $header2['hash2']);
    return $m;
}


/**
 * 
 * @param cuckoo_ctx $ctx - memory pointer
 * @param cuckoo_header $header to write
 * @param array $slot_data  existing slot header data
 * @param int $loc - slot location top write to
 * @return bool 
 */
function cuckoo_write_data_helper(cuckoo_ctx $ctx, cuckoo_header $header, array $slot_data, int $loc) : bool {
    // guard
    if (empty($slot_data) || $slot_data['preamble'] != $ctx->preamble) {
        return false;
    }

    // expired or new value is higher priority, replace it (not working without var set????)
    $e = $slot_data['expires']??0;
    // expired data
    if ($e < $ctx->now) {
        trace("E+");
        return $ctx->write_raw($loc, cuckoo_prep_data($ctx->preamble, $header));
    }
    // higher priority
    if ($header->flags >= CACHE_HIGH) {
        trace("H+");
        return $ctx->write_raw($loc, cuckoo_prep_data($ctx->preamble, $header));
    }
    // same cache entry, update it
    else if (header_match($header, $slot_data)) {
        trace("M+");
        return $ctx->write_raw($loc, cuckoo_prep_data($ctx->preamble, $header));
    }
    // if the existing entry is NOT high priority, and 30 min or older, overwrite it..
    else if ($header->flags & CACHE_HIGH == 0 && ($e - 1800) < $ctx->now) {
        trace("U+");
        return $ctx->write_raw($loc, cuckoo_prep_data($ctx->preamble, $header));
    }
    trace("Fail-:$loc");
    return false;
}


/**
 * find a header for writing, if null is returned, cache write is not possible
 * @param string $data - the already prepped data
 * @param int $size - if known, else will be computed
 */
function cuckoo_write_data(cuckoo_ctx $ctx, cuckoo_header $header): bool
{
    $slot1 = $header->hash1 % $ctx->slots;
    $loc1 = $slot1 * (CUCKOO_MEM_CHUNK);
    $cache_header1 = $ctx->read($loc1, CUCKOO_MEM_CHUNK, CUCKOO_DATA_UNPACK);

    // data wrote to slot 1 successfully :)
    if (cuckoo_write_data_helper($ctx, $header, $cache_header1, $loc1)) {
        trace ("S1+");
        return true;
    } else {
        debug("cuckoo write fail!");
    }

    $slot2 = $header->hash2 % $ctx->slots;
    $loc2 = $slot2 * (CUCKOO_MEM_CHUNK);
    $cache_header2 = $ctx->read($loc2, CUCKOO_MEM_CHUNK, CUCKOO_DATA_UNPACK);
    // write to slot 2 ok :)
    if (cuckoo_write_data_helper($ctx, $header, $cache_header1, $loc2)) {
        trace ("S2+");
        return true;
    } else {
        debug("cuckoo write fail!");
    }

    // both memory locations are valid, overwrite lower priority, or the oldest
    $h1 = $cache_header1['flags']??0 & CACHE_HIGH;
    $h2 = $cache_header2['flags']??0 & CACHE_HIGH;
    $m1 = $header->flags & CACHE_HIGH;
    $loc = 0;
    // don't overwrite high priority data with low priority data :(
    if (!$m1 && $h1 && $h2) {
        return false;
    }
    // both low priority, or everything is high priority, overwrite the oldest data
    else if ((!$h1 && !$h2) || ($m1 && $h1 && $h2)) {
        $loc = ($cache_header1['expires']??0 < $cache_header2['expires']??0) ? $loc1 : $loc2;
    }
    // overwrite the one that is not high priority
    else {
        $loc = ($h1) ? $loc2 : $loc1;
    }

    return $ctx->write_raw($loc, cuckoo_prep_data($ctx->preamble, $header));
}




/**
 * if $key begins with STAT_, it will return the raw stat data for stat num NUM
 * NOTE: stats never expire and live for the life of the memory segment
 * @param cuckoo_ctx $ctx 
 * @param string $key 
 * @param null|string $type 
 * @return array|int|null|string 
 */
function cuckoo_read_data(cuckoo_ctx $ctx, string $key, ?string $type = null)
{

    // read raw stat data numbers
    if (\ThreadFin\starts_with($key, "STAT_")) {
        $stat_num = intval(substr($key, 5));
        $result = 0;
        if ($stat_num > 0 && $stat_num < 768) {
            $loc = ($ctx->mem_end - CUCKOO_STAT_SIZE) + ($stat_num * 4);
            $data = $ctx->read($loc, 4, P32 . 'stat');
            if (is_array($data)) {
                $result = intval($data['stat']);
                // something strange here, stats should never be negative or over 128K
                if ($result < 0 || $result > 128000) {
                    debug("stat error: %d", $result);
                    $ctx->write_raw($loc, pack(P32, 0), 4);
                }
            }
        }

        return $result;
    }

    $header = new_header($key);

    $slot1 = $header->hash1 % $ctx->slots;
    $loc1 = $slot1 * (CUCKOO_MEM_CHUNK);
    $disk_header = $ctx->read($loc1, CUCKOO_MEM_CHUNK, CUCKOO_DATA_UNPACK);

    $fresh = ($disk_header['flags'] & CACHE_STALE_OK) || $disk_header['expires'] > $ctx->now;
    if ($fresh && header_match($header, $disk_header)) {
        return cuckoo_deprep($disk_header, $type);
    }

    $slot2 = $header->hash2 % $ctx->slots;
    $loc2 = $slot2 * (CUCKOO_MEM_CHUNK);
    $disk_header = $ctx->read($loc2, CUCKOO_MEM_CHUNK, CUCKOO_DATA_UNPACK);
    $fresh = ($disk_header['flags'] & CACHE_STALE_OK) || $disk_header['expires'] > $ctx->now;
    if ($fresh && header_match($header, $disk_header)) {
        return cuckoo_deprep($disk_header, $type);
    }

    return null;
}


/**
 * 
 * memory is laid out like:
 * [LRU_HASH_ENTRY],[LRU_HASH_ENTRY]..X.items,[MEM_EXP],[MEM_EXP]..X.items,[MEM],[MEM]..X.items
 * LRU_HASH_ENTRY - hash_key,expires_ts,size,full|empty
 * MEM_EXP - expires_ts
 * MEM - chunk X chunk size bytes
 */
function cuckoo_init_memory($rid, int $num_items, int $chunk_size): void
{
    // some rules about our cache
    assert($num_items <= 65535, "max 64K items in cache");
    assert($chunk_size <= 1024, "max base chunk_size 1K");
    trace("shmop_init:$num_items:$chunk_size");

    $header   = new_header("init");
    $header->expires = 0;
    $preamble = Config::int('cache_preamble', 1622747953);
    $block    = cuckoo_prep_data($preamble, $header);

    // write all slot headers and memory blocks, save memory by writing in chunks
    // php string building is slow, so we use array_walk to write in chunks
    $slots = range(0, $num_items - 1);
    array_walk($slots, function ($x) use ($rid, $block, $chunk_size) {
        @shmop_write($rid, $block, ($x * $chunk_size));
    });

    //  0 out the stat memory
    $block = pack(P32, 0);
    for ($i=0; $i<768; $i++) {
        @shmop_write($rid, $block, ($num_items * $chunk_size) + ($i * 4));
    }
}

/**
 * helper function to open shared memory segment.  if the segment does not exist, 
 * it will be created and initialized.
 * @param int $size_in_bytes - size of memory segment to create
 * @param int $token - a unique key for the memory segment, 
 * @param bool $reduced - set to true when the memory segment size has been reduced
 * @return int - the shared memory id, or 0 on error
 */
function cuckoo_open_mem(int $size_in_bytes, int $token, bool $reduced = false) 
{
    // can't allocate enough memory to be useful
    if ($size_in_bytes < 192000) {
        require_once WAF_DIR . 'src/server.php';
        update_ini_value('cache_type', 'opcache')->run();
        return 0;
    }

    if (function_exists('shmop_open') == false) {
        require_once WAF_DIR . 'src/server.php';
        update_ini_value('cache_type', 'opcache')->run();
        return false;
    }

    // debug("shmop_open token: $token bytes: $size_in_bytes");
    $id = @shmop_open($token, 'w', 0666, $size_in_bytes + CUCKOO_MEM_EXTRA);

    // need to determine the size of the segment, and if it's miss-matched, maybe init the extra mem segment?  possibly add a delete method?
    // requires a little more research
    // unable to attach/create memory segment, recreate it...
    if ($id === false) {
        $e = error_get_last();
        $msg = $e['message'];
        debug("unable to attach shmop [%s]", $msg);
        if (!empty($e) && contains($msg, 'allocate')) {
            return cuckoo_open_mem($size_in_bytes - 128000, $token, true);
        }
        else if (icontains($msg, 'no such')) {
            $id = @shmop_open($token, 'c', 0666, $size_in_bytes + CUCKOO_MEM_EXTRA);
        }
        else {
            // connect failed, we probably have an old mem segment that is not large enough
            $id = @shmop_open($token, 'w', 0, 0);
            if ($id) {
                @shmop_delete($id);
            }
            // not attaching, fallback to opcache type
            else {
                require_once WAF_DIR . 'src/server.php';
                update_ini_value('cache_type', 'opcache')->run();
            }
        }

        if ($id === false) {
            debug("unable to open shared memory size [%d] token:[%s]", $size_in_bytes, dechex($token));
            return 0;
        } else {
            debug("created new shared memory segment: %d bytes", $size_in_bytes);
        }

        $slots = floor(($size_in_bytes - CUCKOO_STAT_SIZE) / (CUCKOO_CHUNK + CUCKOO_SLOT_SIZE_BYTES));
        cuckoo_init_memory($id, $slots, CUCKOO_MEM_CHUNK);
    } else if ($reduced) {
        debug("NOTICE: reduced cache size to %d bytes", $size_in_bytes);
        require_once WAF_DIR . 'src/server.php';
        update_ini_value("cache_size", $size_in_bytes)->run();
    }
    return $id;
}

/**
 * connect to the existing shared memory or initialize new shared memory
 * @param int $items = 4096
 * @param int $chunk_size = 1024
 * @param int $mem = 1114112
 * @param bool $force_init = false
 */
function cuckoo_connect(int $items = 4096, int $chunk_size = 2048, int $mem = 0): ?cuckoo_ctx
{
    $token = Config::int("cache_token", 1234560);
    $mem_end = (($items + 1) * CUCKOO_MEM_CHUNK) + CUCKOO_STAT_SIZE;

    $rid = cuckoo_open_mem($mem_end, $token);
    if ($rid != 0) {
        $ctx = new cuckoo_ctx();
        $ctx->rid = $rid;
        $ctx->mem_start = 0;
        $ctx->mem_end = $mem_end;
        $ctx->slots = $items;
        $ctx->now = time();
        $ctx->chunk_size = $chunk_size;
        $ctx->preamble = Config::int('cache_preamble', 1622747953);

        return $ctx;
    }

    return null;
}


class cuckoo
{
    public static ?cuckoo_ctx $ctx;
    public function __construct()
    {
        $size = Config::int("cache_size", 1470000);
        if ($size == 0) { 
            require_once WAF_DIR . 'src/server.php';
            update_ini_value('cache_type', 'opcache')->run();
            self::$ctx = null;
        } else {
            $slots = floor($size / CUCKOO_MEM_CHUNK);
            self::$ctx = cuckoo_connect($slots, CUCKOO_CHUNK, $size);
        }
    }

    public function export()
    {
        file_put_contents(get_hidden_file("mem_export.bin"), @shmop_read(self::$ctx->rid, 0, self::$ctx->mem_end + 16));
    }

    // returns original data or null if it could not be read
    public static function read(string $key, ?string $type = null)
    {
        return cuckoo_read_data(self::$ctx, $key, $type);
    }

    public static function write(string $key, int $ttl, $storage, int $priority = CACHE_LOW) : bool
    {
        // write raw stat data numbers
        if (\ThreadFin\starts_with($key, "STAT_")) {
            //debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 4);
            //debug("BT: %s", debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 4)
            $stat_num = intval(substr($key, 5));
            if ($stat_num > 0 && $stat_num < 768) {
                $loc = (self::$ctx->mem_end - CUCKOO_STAT_SIZE) + ($stat_num * 4);
                $data = pack(P32, $storage);
                return self::$ctx->write_raw($loc, $data, 4);
            }

            return false;
        }

        $header = new_header($key, $ttl, $priority);
        $header->flags |= ($storage instanceof packable) ? CACHE_PACK : 0;
        $header->data = $storage;

        return cuckoo_write_data(self::$ctx, $header);
    }

    public static function clear()
    {
        cuckoo_init_memory(self::$ctx, floor(Config::int('cache_size', 1470000) / CUCKOO_CHUNK), CUCKOO_CHUNK);
    }

    public static function delete(): bool
    {
        if (function_exists('shmop_delete') == false) {
            return false;
        }

        $size = Config::int("cache_size", 1470000);
        $slots = floor($size / CUCKOO_MEM_CHUNK);
        $token = Config::int("cache_token", 1234560);
        $mem_end = (($slots + 1) * CUCKOO_MEM_CHUNK) + CUCKOO_STAT_SIZE;
        $rid = (empty(self::$ctx->rid)) ? cuckoo_open_mem($mem_end, $token)  : self::$ctx->rid;
        return @shmop_delete($rid);
    }
}
