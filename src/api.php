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

use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use BitFire\Config as CFG;
use RuntimeException;
use ThreadFin\CacheItem;
use ThreadFin\Hash_Config;
use ThreadFinDB\DB;

use const BitFire\Data\CODE_BOOK;
use const ThreadFin\DAY;

use function BitFire\Data\hydrate_log;
use function BitFire\Data\ip4_pos_to_loc;
use function BitFire\Data\ip4_uni_to_pos;
use function BitFireBot\host_to_domain;
use function BitFireBot\hydrate_any_bot_file;
use function BitFireBot\ip_to_domain;
use function BitFireSvr\add_ini_value;
use function BitFireSvr\hash_file3;
use function BitFireSvr\parse_scan_config;
use function BitFireSvr\update_ini_value;
use function ThreadFin\array_map_value;
use function ThreadFin\contains;
use function ThreadFin\en_json;
use function ThreadFin\ends_with;
use function ThreadFin\file_recurse;
use function ThreadFin\partial_right as ƒixr;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\random_str;
use function ThreadFin\un_json;
use function ThreadFin\debug;
use function ThreadFin\debugN;
use function ThreadFin\file_index;
use function ThreadFin\file_replace;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\HTTP\http_wait;
use function ThreadFin\HTTP\httpp;
use function ThreadFin\icontains;
use function ThreadFin\trace;
use function ThreadFin\ƒ_id;
use function ThreadFinDB\dump_database;

require_once \BitFire\WAF_SRC . "server.php";
require_once \BitFire\WAF_SRC . "cms.php";


/**
 * make $dir_name if it does not exist, mode FILE_RW, 0755, etc
 * @impure
 * @return bool true if directory was newly created, or if it exists
 */
function make_dir(string $dir_name, int $mode) : bool {
    if (!file_exists(dirname($dir_name))) {
        return mkdir(dirname($dir_name), $mode, true);
    }
    return true;
}



/**
 * add an exception to exceptions.json
 * @pure
 * @API
 */
function rem_api_exception(\BitFire\Request $r) : Effect {
    assert(isset($r->post['uuid']) || isset($r->post['agent']), "uuid or agent is required");
    $uuid = $r->post['uuid']??NULL;

    // an effect and the exception to add
    $effect = Effect::new();

    // load exceptions from disk
    if (isset($r->post['uuid'])) {
        $file = get_hidden_file("exceptions.json");
        $exceptions = FileData::new($file)->read()->un_json();
        if ($exceptions === null) {
            debug("json read error in exceptions.json");
            return $effect->api(false, "exception file corrupted");
        } else {
            $removed = array_filter($exceptions(), function ($x) use ($uuid) {
                return ($x['uuid'] != $uuid);
            });
        }

        // nothing added, exception already exists
        if (count($removed) == count($exceptions())) {
            $effect->api(false, "exception does not exist");
        }
        // new exception added
        else if (count($removed) < count($exceptions())) {
            $effect->api(true, "exception removed");
            $effect->file(new FileMod($file, json_encode($removed, JSON_PRETTY_PRINT), FILE_RW));
        }
        // any other case
        else {
            $effect->api(false, "unable to remove exception from $file");
        }
    } else if (isset($r->post['agent'])) {

        $agent = $r->post['agent'];

        $file = get_hidden_file("browser_allow.json");
        $exceptions = FileData::new($file)->read()->un_json();
        if ($exceptions === null) {
            debug("json read error in exceptions.json");
            return $effect->api(false, "exception file corrupted");
        } 

        $data = $exceptions();
        $type = (filter_var($agent, FILTER_VALIDATE_IP)) ? 'ip' : 'ua';
        $new = ["ip" => $data['ip'], "ua" => $data['ua']];

        $new[$type] = array_filter($data[$type], function ($key, $value) use ($agent) {
            return ($value != $agent);
        }, ARRAY_FILTER_USE_BOTH);

        // nothing added, exception already exists
        $new_count = count($new[$type]);
        $old_count = count($data[$type]);

        if ($new_count == $old_count) {
            $effect->api(false, "rule does not exist");
        }
        // new exception added
        else if ($new_count < $old_count) {
            $effect->api(true, "rule removed");
            $effect->file(new FileMod($file, json_encode($new, JSON_PRETTY_PRINT)));
        }
        // any other case
        else {
            $effect->api(false, "unable to remove rule from $file");
        }

    }

    // return the result
    return $effect;
}

/**
 * add an exception to exceptions.json
 * @pure
 */
function add_api_exception(\BitFire\Request $r) : Effect {
    //assert(isset($r->post['path']), "path is required");
    assert(isset($r->post['code']), "code is required");
    $param = $r->post['param']??NULL;
    $r->post["action"] = "add_exception";
    httpp(INFO."zxf.php", base64_encode(json_encode($r->post)));

    // an effect and the exception to add

    // special handling of bot exceptions
    $effect = Effect::new();
    if ($r->post['code'] == 24002 || $r->post['code'] == 25001) {
        $r->post['action'] = "pass_ua";
        return bot_action($r);
    }

    // all other exceptions, previous block returns...
    $ex = new \BitFire\Exception((int)$r->post['code'], random_str(8), $param, $r->post['path']??'');

    // load exceptions from disk
    $file = get_hidden_file("exceptions.json");
    $exceptions = FileData::new($file)->read()->un_json()->map('\BitFire\map_exception');

    // add new exception (will not double add)
    $updated_exceptions = add_exception_to_list($ex, $exceptions());

    // nothing added, exception already exists
    if (count($updated_exceptions) == count($exceptions())) {
        $effect->api(false, "exception already exists");
    }
    // new exception added
    else if (count($updated_exceptions) > count($exceptions())) {
        $effect->api(true, "exception added");
        $effect->file(new FileMod($file, json_encode($updated_exceptions, JSON_PRETTY_PRINT), FILE_RW));
    }
    // any other case
    else {
        $effect->api(false, "unable to add exception to $file");
    }

    // return the result
    return $effect;
}



/**
 * @pure
 * @param Request $r 
 * @return void 
 */
function download(\BitFire\Request $r) : Effect {
    assert(isset($r->get["filename"]), "filename is required");

	$effect = Effect::new();
    $root = \BitFireSvr\cms_root() . "/";
	$filename = trim($r->get['filename'], "/");
    $path = $root . $filename;

    // alert / block download
    if ($filename == "alert" || $filename == "block") {
        $effect->header('Content-Type', 'application/json');
        // TODO: move to server functions
        $config_name = ($filename == "alert") ? get_hidden_file("alerts.json") : get_hidden_file("blocks.json");
        $report_file = \ThreadFin\FileData::new(CFG::file($config_name))->read();
        $report_file->apply_ln('array_reverse')
            ->map('\ThreadFin\un_json');
        $data = json_encode($report_file->lines, JSON_PRETTY_PRINT);
        $filename .= ".json";
    }
	else {
        $effect->header('Content-Type', 'application/x-php');
        // FILE NAME GUARD
        if (! ends_with($filename, "php") || icontains($filename, RESTRICTED_FILES)) {
            return $effect->api(false, "invalid file.", ["filename" => $filename]);
        }
        // load data
        $file = FileData::new($path);
        if (!$file->exists) {
            return $effect->api(false, "no file.", ["filename" => $path]);
        }
        $data = $file->raw();
    }

    if (!isset($r->get['direct'])) {
        $base = basename($filename);
        $effect->header("content-description", "File Transfer")
        ->header('Content-Disposition', 'attachment; filename="' . $base . '"')
        ->header('Expires', '0')
        ->header('Cache-Control', 'must-revalidate')
        ->header('Pragma', 'private')
        ->header('Content-Length', (string)strlen($data));
    }
    $effect->out($data);
    return $effect;
}

function malware_files(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    $malware_file = WAF_ROOT . "/data/malware_files.json";
    $data = [
        "total" => intval($request->post["total"]),
        "malware" => intval($request->post["malware"]),
        "time" => time()];
    $file = new FileMod($malware_file, en_json($data), FILE_RW);
    $effect->file($file);
    $effect->api(true, "malware files updated");
    return $effect; 
}


/**
 * 
 * @param array $ips - list of ips to convert
 * @param array $domains - list of already converted domains format: domain.com:ip1.ip2.ip3
 * @return string 
 */
function ips_to_domains(array $ips, array $domains = []) : string {
    $cache = [];
    // cache already found domains

    foreach(array_keys($ips) as $ip) {
        $ip2 = substr($ip, 0, strrpos($ip, "."));
        if (isset($cache[$ip2])) { continue; }
        $cache[$ip2] = true;
        $domain_list[] = ip_to_domain($ip);
    }

    return implode(",", array_unique($domain_list));
}





function bot_action(\BitFire\Request $request) : Effect {

    $effect = Effect::new();

    $action = $request->post["action"]??"unknown";
    // if we are editing browser settings (usually "bot" browsers)
    if (in_array($action, ["pass_ip", "block_ip", "pass_ua", "block_ua"])) {

        // get the type, value and setting from request
        $setting = contains($action, "pass") ? 1 : 0;
        $type = contains($action, "ua") ? "ua" : "ip";
        $value = $request->post[$type]??"";
        $value = ($value == "none") ? "" : $value;

        // read the browser file
        $allow_file = FileData::new(get_hidden_file("browser_allow.json"))->read()->un_json();
        // update file
        $allow_file->lines[$type][$value] = $setting;
        $content = json_encode($allow_file->lines, JSON_PRETTY_PRINT);
        // return new effect to update file
        $effect->file(new FileMod(get_hidden_file("browser_allow.json"), $content));
        $effect->api(true, "updated browser allow data");



        // set the UA to allow any
        if ($type == "ua") {
            $agent = parse_agent($value);
            $bot_dir = get_hidden_file("bots");
            $bot_data = \BitFireBot\load_bot_data2($agent);
            $bot_data->manual_mode = BOT_ALLOW_ANY;
            $bot_data->valid = 1;

            $file_name = get_hidden_file('bots/'.crc32($agent->trim).'.js');
            file_put_contents($file_name, serialize($bot_data), LOCK_EX);
        }
        // block or unblock the IP
        else if ($type == "ip") {
            $block_file = \BitFire\BLOCK_DIR . DS . $value;
            if ($setting == 0) {
                touch($block_file, time() + (DAY * 365));
            } else {
                unlink($block_file);
            }
        }

        return $effect;
    }

    // purge old bots...
    if ($request->post["action"] == "purge") {
        $bot_dir = get_hidden_file("bots");
        $bot_files = glob("{$bot_dir}/*.json");

        array_walk($bot_files, function($file) {
            $bot = unserialize(file_get_contents($file));
            // remove broken files
            if (!$bot) { unlink($file); return; }
            // don't remove known bots
            if ($bot->valid)  { return; }
            if (!icontains($bot->vendor, "unknown"))  { return; }

            // remove old bots
            if (filemtime($file) + (DAY * 7) < time()) {
                unlink($file);
            }

            // remove bots with no or 1 hit
            if ($bot->hit + $bot->miss <= 1) {
                unlink($file);
            }

        });

        return $effect->api(true, "purged old bots", ["count" => count($bot_files)]);
    }



    $id = intval($request->post["bot"]);
    $ip = filter_var($request->post["ip"]??"", FILTER_VALIDATE_IP);

    $lookup = [];
    $bot_dir = get_hidden_file("bots");
    $info_file = "{$bot_dir}/{$id}.js";
    if ($request->post["action"] == "rm") {
        $effect->unlink($info_file);
        $effect->api(true, "bot remove", ["id" => $id]);
        return $effect;
    }
    $fd = FileData::new($info_file);
    if ($fd->exists) {
        trace("BOT_RM");
        $bot_data = hydrate_any_bot_file($info_file);
        //$bot_data = unserialize($fd->raw(), ["allowed_classes" => ["BitFire\BotSimpleInfo"]]);
        if (!$bot_data) {
            $effect->unlink($info_file);
            return $effect->api(false, "unable to load bot file $id");
        }
    } else {
        return $effect->api(false, "bot file $id does not exist");
    }

    if (! $bot_data instanceof \BitFire\BotSimpleInfo) {
        return $effect->api(false, "bot data corruption");
    }
    if ($request->post["action"] == "no") {
        trace("BOT_NO");
        $bot_data->manual_mode = BOT_ALLOW_NONE;
        $bot_data->configured = true;
        $effect->api(true, "bot block all", ["id" => $id, "domain" => $bot_data->domain, "mode" => $bot_data->manual_mode]);
    }
    else if ($request->post["action"] == "any") {
        trace("BOT_ANY");
        $bot_data->manual_mode = BOT_ALLOW_ANY;
        $bot_data->configured = true;
        $effect->api(true, "bot allow any", ["id" => $id, "domain" => $bot_data->domain, "mode" => $bot_data->manual_mode]);
    }
    else if (in_array($request->post["action"], ["known", "unknown"])) {
        trace("BOT_KNOWN");
        $bot_data->valid = $request->post["action"] == "known";
        $bot_data->configured = true;
        //if (empty($bot_data->vendor) || !icontains($bot_data->vendor, "unknown")) {
            $bot_data->vendor = $request->post['action'];//($bot_data->vendor == "Unknown Bot." && $bot_data->valid) ? $bot_data->name : $bot_data->vendor;
        //}
        $effect->api(true, "bot classify known", ["id" => $id, "domain" => $bot_data->domain, "valid" => $bot_data->valid]);
    }
    else if ($request->post["action"] == "junk") {
        trace("BOT_JUNK");
        $bot_data->manual_mode = BOT_ALLOW_NONE;
        $bot_data->valid = 0;
        $bot_data->configured = true;
        $bot_data->vendor = "junk";
        $effect->api(true, "bot classify known", ["id" => $id, "domain" => $bot_data->domain, "valid" => $bot_data->valid]);
    }

    else if ($request->post["action"] == "auth") {
        $bot_data->manual_mode = BOT_ALLOW_AUTH;
        $bot_data->configured = true;
        trace("BOT_AUTH");
        $domain_list = explode(",", $bot_data->domain);

        foreach($bot_data->ips as $the_ip => $value) {
            debug("ip [%s]", $the_ip);
            if (strlen($the_ip) < 7) { continue; }
            if (isset($lookup[$the_ip])) { continue; }
            $lookup[$the_ip] = true;
            $domain_list[] = ip_to_domain($the_ip);
        }
        $bot_data->domain = implode(",", array_unique($domain_list));
        debug("allowed domain [%s]", $bot_data->domain);
        $effect->api(true, "bot auth", ["id" => $id, "domain" => $bot_data->domain, "mode" => $bot_data->manual_mode]);
    }
    else if ($request->post["action"] == "rest") {
        $bot_data->manual_mode = BOT_ALLOW_RESTRICT;
        $bot_data->configured = true;
        trace("BOT_REST");
        $bot_data->domain = ips_to_domains($bot_data->ips);
        debug("allowed domain [%s]", $bot_data->domain);
        $effect->api(true, "bot auth", ["id" => $id, "domain" => $bot_data->domain, "mode" => $bot_data->manual_mode]);
    }
    else if ($request->post["action"] == "lock_ip") {
        $bot_data->ips[$ip] |= REQ_BLOCKED;
        debug("blocked ip [%s]", $ip);
        $effect->api(true, "bot ip $ip blocked", ["id" => $id, "ip" => $ip, "message" => "$ip blocked"]);
    }
    else if ($request->post["action"] == "unlock_ip") {
        $bot_data->ips[$ip] &= ~REQ_BLOCKED;
        debug("allowed ip [%s]", $ip);
        $effect->api(true, "bot ip $ip un-blocked", ["id" => $id, "ip" => $ip, "message" => "$ip un-blocked"]);
    }
    else if ($request->post["action"] == "ignore_ip") {
        unset($bot_data->ips[$ip]);
        debug("removed ip [%s]", $ip);
        $effect->api(true, "bot ip $ip ignored", ["id" => $id, "ip" => $ip, "message" => "$ip removed"]);
    }
    // update the bot access file, but keep the modification time the same
    $mtime = filemtime($info_file);
    $effect->file(new FileMod($info_file, json_encode($bot_data, JSON_PRETTY_PRINT), FILE_RW, $mtime));
    return $effect;
}



/**
 * get all ip info detail from bitfire servers
 * @param Request $request 
 * @return Effect 
 */
function get_ip_info(\BitFire\Request $request) : Effect {
    $z0 = microtime(true);
    $effect = Effect::new();
    $id = intval($request->post["bot_id"]??0);
    if (empty($id)) {
        return $effect->api(false, "invalid bot id");
    }

    $bot = hydrate_any_bot_file(get_hidden_file("bots/{$id}.js"));

    $z1 = microtime(true);
    //$response = http2("POST", "https://bitfire.co/ip_info.php", base64_encode(json_encode($bot_list->ips)));
    //$ip_info = json_decode($response->content);

    $long_names = json_decode(file_get_contents(WAF_ROOT . "data/country_name.json"), true);

    $z2 = microtime(true);
    static $dom_cache = [];
    $ip_info = array_map_value(function($ip, $classification) use ($long_names, $id, &$dom_cache) {
        $split = explode(".", $ip);
        $info = ['city' => 'unknown', 'id' => $id, 'country' => 'unknown', 'ip' => $ip, 'domain' => 'no reverse dns', 'category' => '', 't1' => microtime(true)];
        if (count($split) > 2) {
            $part_ip = $split[0] . "." . $split[1] . "." . $split[2];
            if (!isset($dom_cache[$part_ip])) {
                $domain = host_to_domain(gethostbyaddr($ip));
                $dom_cache[$part_ip] = $domain ?: "no dns entry";
            }
            $info['domain'] = $dom_cache[$part_ip];
            $loc = ip4_pos_to_loc(ip4_uni_to_pos(\BitFire\Data\ip4_to_uni($ip)), $long_names);
            $info['city'] = $loc->city;
            $info['country'] = $loc->country;
        }
        foreach (REQ_NAMES as $name => $mask) {
            if ($classification & $mask) {
                $info['category'] .= "<span class='badge bg-".REQ_COLOR[$name]."'>$name</span> ";
            }
        }

        $info['t2'] = microtime(true) - $info['t1'];
        return $info;
    }, $bot->ips);

    $z3 = microtime(true);
    //return $effect->api(true, "success", [$z3, $z2, $z1, $z0]);
    return $effect->api(true, "success", $ip_info);
}




/**
 * replace an array value in the ini file
 * @param Request $request 
 * @return Effect 
 */
function replace_array_value(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    $name = $request->post["param"];

    // remove all lines with $name[]
    $file_no_array = FileData::new(WAF_INI)->read()->filter(function($line) use ($name) {
        return ! contains($line, "{$name}[]");
    });

    // add new values
    $value_list = explode(",", $request->post["value"]);
    foreach ($value_list as $value) {
        if (!empty($value)) {
            $file_no_array->lines[] = "{$name}[] = \"$value\"\n";
        }
    }
    $file_no_array->lines[] = "\n";

    // write the new file
    $effect->file(new FileMod(WAF_INI, join("", $file_no_array->lines)));

    // remove the old cache entry and force a new parse
    $effect->update(new CacheItem("parse_ini", ƒ_id(), ƒ_id(), -86400, CACHE_HIGH));
    $effect->api(true, "updated");
 
    return $effect;
}


function general_scan(\BitFire\Request $request) : Effect {
    require_once WAF_SRC . "diff.php";
    require_once WAF_SRC . "cms.php";
    $root = \BitFireSvr\cms_root();
    ini_set("max_execution_time", 245);
    $offset = intval($request->post['offset']);

    $config = parse_scan_config(CFG::arr("malware_config"));
    $index_file = get_hidden_file("file.index");
    if ($offset == 0) {
        $reg_ex = ($config->non_php == 1) ? NULL : '/.*\.php$/';
        $ctx = fopen($index_file, "w+");
        $write_fn = ƒixl('fwrite', $ctx);
        file_index($root, $reg_ex, $write_fn);
        fclose($ctx);
        copy($index_file, $index_file . ".bak");
    }

    // for reading php files
    if (defined("BitFirePRO")) { stream_wrapper_restore("file"); }

    $ini_limit = ini_get('memory_limit');
    $memory_mb = 22; // default to low reasonable value 
    if (preg_match('/^(\d+)(.)$/', $ini_limit, $matches)) {
        if ($matches[1] == 'M') {
            $memory_mb = intval($matches[1]);
        }
        else if ($matches[2] == 'G') {
            $memory_mb = intval($matches[1])*1024;
        }
    }
    $memory_mb = max($memory_mb, 96); // target 96MB - (batch size 240)

    $batch_size = floor($memory_mb / .6);
    $list = scan_filesystem($index_file, $offset, $batch_size, parse_scan_config(CFG::arr("malware_config")));

    $list2 = [];
    foreach ($list as $item) {
        $req_fn = '/[\@\s\(\);\/](?:header|\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*|mail|fwrite|file_put_contents|create_function|call_user_func|call_user_func_array|uudecode|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru)\s*(?:\[[^\]]*?\])?\s*(?:(?:#[^\n]*\n)|(?:\/\/[^\n]*\n)|(?:\/\*.*?\*\/))?\(\s*(?:[\.\$_]*)?/misS';
        if (!preg_match($req_fn, file_get_contents($item->path), $matches)) {
        } else {
            $list2[] = $item;
        }
    }


    $effect = Effect::new()->api(true, "hashed " . $list->num_scanned . " skipped " . $list->num_skipped . " mem: " . memory_get_peak_usage(), array("basename" => basename($root), "complete" => $list->complete, "found" => count($list2), "dir" => $root, "batch_size" => $batch_size, "skip_count" => $list->num_skipped, "file_count" => $list->num_scanned, "data" => base64_encode(json_encode(array_values($list2)))));
    if (count($list) > 0) {
        http2("POST", "https://bitfire.co/malware.php?src=".$_SERVER['HTTP_HOST'], base64_encode(json_encode($list->_list)));
    }
    return $effect;
}



/**
 * need to test these 2 enrichment functions
 * @param mixed $ver 
 * @param mixed $dir_without_plugin_name 
 * @param mixed $hash_slice 
 * @return array<array-key, mixed> 
 */
function batch_enrich($hash_slice, ?ScanConfig $config = null) {
    assert(count($hash_slice) < 24, "curl multi can only handle 24 at a time");

    if ($config == null) {
        $config = parse_scan_config(CFG::arr("malware_config"));
    }

    //debug("batch_enrich (%s) (%s) (%s)", $ver, $dir_without_plugin_name, json_encode($hash_slice));

    if (function_exists("curl_multi_init")) {
        $mh = curl_multi_init();
    } else {
        $mh = null;
    }
    $enrich_fn = ƒixl('\BitFire\enrich_hashes', $mh);

    // WTF DOES THIS NOT WORK? SEE debug.log [updraftplus]
    $enriched1 = array_map($enrich_fn, $hash_slice);
    //debug("enriched1 : (%s)", json_encode($enriched1));

    // debug("waiting... (%s)", json_encode($hash_slice));
    if (!empty($mh)) {
        http_wait($mh);
    }
    $enriched2 = array_map(ƒixr('\BitFire\enrich_hashes2', $mh, $config), $enriched1);
    //debug("enriched2 : (%s)", json_encode($enriched2));

    if (function_exists("curl_multi_close")) {
        curl_multi_close($mh);
    }

    return $enriched2;
}




/**
 * download a BitFire release
 * @param string $version 
 * @return Effect 
 */
function download_tag(string $version, string $dest) : Effect {
    // download the archive TODO: check checksum
    $link = "https://github.com/bitslip6/bitfire/archive/refs/tags/{$version}.tar.gz";
    $resp_data = http2("GET", $link, "");
    $check_data = http2("GET", "https://bitfire.co/releases/{$version}.md5");
    $test_md5 = md5($resp_data->content);
    // checksum mismatch
    if ($test_md5 !== $check_data->content) {
        return Effect::new()->status(STATUS_ECOM);
    }
    return Effect::new()->status(STATUS_OK)->file(new FileMod($dest, $resp_data->content));
}

// only called for standalone installs, not plugins
function upgrade(\BitFire\Request $request) : Effect {
    $v = preg_replace("/[^0-9\.]/", "", $request->post['ver']);
    if (\version_compare($v, BITFIRE_SYM_VER, '<')) { 
        debug("version not current [%s]", $v);
        return Effect::new()->api(false, "version is not current");
    }

    // ensure that all files are writeable
    file_recurse(\BitFire\WAF_ROOT, function ($x) {
        if (!is_writeable($x)) { 
            return Effect::new()->api(false, "unable to upgrade: $x is not writeable");
        }
    });

    // allow php file manipulation
    stream_wrapper_restore("file");

    // download and verify no errors
    $dest = \BitFire\WAF_ROOT."data/{$v}.tar.gz";
    $e = download_tag($v, $dest);
    $e->run();
    if ($e->num_errors() > 0) {
        return Effect::new()->api(false, "error downloading and saving release", $e->read_errors());
    }
    

    //  extract archive
    $target = \BitFire\WAF_ROOT . "data";
    require_once \BitFire\WAF_SRC."tar.php";
    $success = \ThreadFin\tar_extract($dest, $target) ? "success" : "failure";
    

    // replace files
    file_recurse(\BitFire\WAF_ROOT."data/bitfire-{$v}", function (string $x) use ($v) {
        $base = basename($x);
        if (is_file($x) && $base != "config.ini") {
            $root = str_replace(\BitFire\WAF_ROOT."data/bitfire-{$v}/", "", $x);
            if (!rename($x, \BitFire\WAF_ROOT . $root)) { debug("unable to rename [%s] - %s", $x, $root); }
        }
    });

    $cwd = getcwd();
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect->api($success, "upgraded with [$dest] in [$cwd]");
}

 
// FIX RESPONSE: 
function delete(\BitFire\Request $request) : Effect {

    $root = \BitFireSvr\cms_root();

    $effect = Effect::new();
    $f = $request->post['value'];
    $name = $request->post['name']??'';

    if (stristr($f, "..") !== false) { return $effect->api(false, "refusing to delete relative path [$f]"); }

    if (strlen($f) > 1) {
        $out1 = $root . $f.".bak.".mt_rand(10000,99999);
        $src = $root . $f;

        if (!file_exists($src)) { return $effect->api(false, "refusing to delete non-existent file [$src] ($f) ($name)"); } 
        $src = $root . DIRECTORY_SEPARATOR . $name . DIRECTORY_SEPARATOR . $f;
        if (!file_exists($src)) { return $effect->api(false, "refusing to delete non-existent file [$src] ($f) ($name)"); } 

        $quarantine_path = str_replace($root, \BitFire\WAF_ROOT."quarantine/", $out1);
        debug("moving [%s] to [%s]", $src, $quarantine_path);
        make_dir($quarantine_path, FILE_EX);
        if (!is_writable($src)) { chmod($src, FILE_RW); }
        if (is_writable($src)) {
            if (is_writeable($quarantine_path)) {
                $r = rename($src, "{$quarantine_path}{$f}");
                $effect->api(true, "renamed {$quarantine_path}{$f} ($r)");
            } else {
                $r = unlink($src);
                debug("unable to quarantine [%s] unlink:(%s)", $src, $r);
                $effect->api(true, "deleted {$src} ($r)");
            }
        } else {
            debug("permission error quarantine [%s]", $src);
            $effect->api(false, "delete permissions error '$src'");
        }
    } else {
        $effect->api(false, "no file to delete");
    }
   return  $effect;
}


function set_pass(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    debug("save pass");
    if (strlen($request->post['pass1']??'') < 8) {
        return $effect->api(false, "password is too short");
    }
    $p1 = hash("sha3-256", $request->post['pass1']??'');
    debug("pass sha3-256 %s ", $p1);
    $pass = file_replace(\BitFire\WAF_INI, "password = 'default'", "password = '$p1'")->run()->num_errors() == 0;
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    exit(($pass) ? "success" : "unable to write to: " . \BitFire\WAF_INI);
}


// TODO: refactor UI to check api success value
function remove_list_elm(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    // guards
    if (!isset($request->post['config_name'])) { return $effect->api(false, "missing config parameter"); }
    if (!isset($request->post['config_value'])) { return $effect->api(false, "missing config value parameter"); }
    if (!isset($request->post['index'])) { return $effect->api(false, "missing index parameter"); }

    $v = substr($request->post['config_value'], 0, 80);
    $n = $request->post['config_name'];
    if (!in_array($n, \BitFireSvr\CONFIG_KEY_NAMES)) { return $effect->api(false, "unknown parameter name"); }

    $effect = update_ini_value("{$n}[]", "!", "$v");
    if ($effect->read_status() != STATUS_OK) {
        return $effect->api(false, "error updating ini status: " . $effect->read_status());
    }

    // SUCCESS!
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect->api(true, "updated");
}

// modify to use FileData
// FIX RESPONSE: 
function add_list_elm(\BitFire\Request $request) : Effect {
    $effect = Effect::new();

    // guards
    if (!isset($request->post['config_name'])) { return $effect->api(false, "missing config parameter"); }
    if (!isset($request->post['config_value'])) { return $effect->api(false, "missing config value parameter"); }

    $value = substr($request->post['config_value'], 0, 80);
    $name = $request->post['config_name'];
    if (!in_array($name, \BitFireSvr\CONFIG_KEY_NAMES)) { return $effect->api(false, "unknown parameter name"); }

    $effect = add_ini_value("{$name}[]", $value)->api(true, "config.ini updated");
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect;
}

// install always on protection (auto_prepend_file)
function install(?\BitFire\Request $request = null) : Effect {
    // CALL SERVER AND KEEP THIS CHECK HERE
    if (isset($_SERVER['IS_WPE'])) {
        $note = "WPEngine has a restriction which prevents that here.  Please go to WordPress plugin page and disable then re-enable this plugin to activate always-on.";
        return Effect::new()->exit(true, STATUS_FAIL, $note)->api(false, $note);
    }

    $effect = \BitFireSvr\install();
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect;
}

// uninstall always on protection (auto_prepend_file)
function uninstall(\BitFire\Request $request) : Effect {
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return \BitFireSvr\uninstall();
}


function toggle_config_value(\BitFire\Request $request) : Effect {

    // handle fixing write permissions
    if ($request->post["param"] == "unlock_config") {
        $result = chmod(\BitFire\WAF_INI, 0664);
        return Effect::new()->api(true, "updated 2", ["file" => WAF_INI, "mode" => 0664, "result" => $result]);
    }
    // handle toggle on/off to values
    if ($request->post["param"] == "cor_policy") {
        $value = (in_array($request->post["value"], ["false", "off"])) ? "" : "same-origin";
        $request->post["value"] = $value;
    }

    debug("update config [%s]", WAF_INI);

    // ugly fix for missing valid domain line
    $config = FileData::new(WAF_INI)->read();

    if ($config->num_lines < 1) {
        file_replace(WAF_INI, "; domain_fix_line", "valid_domains[] = \"\"\n; domain_fix_line")->run();
    }

    // update the config file
    $effect = \BitFireSvr\update_ini_value($request->post["param"], $request->post["value"]);
    // handle auto_start install
    if ($request->post["param"] == "auto_start") {
        $effect->chain(\BitFireSvr\install());
    } 
    if ($request->post["param"] == "notification_email") {
        $name = "";
        if (function_exists('wp_get_current_user')) {
            $user = wp_get_current_user();
            $name = $user->first_name;
        }
        http2("POST", INFO."zxf.php", base64_encode(json_encode(["action" => "notify", "host" => $_SERVER['HTTP_HOST'], "first" => $name, "name" => $request->post["value"]])));
    }
    $effect->api(true, "updated");
    $effect->hide_output(false);
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect;
}

/**
 * path is crc32 of path, trim is crc32 of trimmed content
 * @param Request $request 
 * @return Effect - the API response
 */
function allow(\BitFire\Request $request) : Effect {
    require_once WAF_ROOT . "src/server.php";
    // preamble
    $file_name = get_hidden_file("hashes.json");
    $effect = Effect::new();
    $data = un_json($request->post_raw);
    if ($data === null || !isset($data["path"])) {
        return $effect->api(false, "invalid json sent to BitFire API");
    }
    //debug("data\n%s", json_encode($data, JSON_PRETTY_PRINT));
    $type_fn = "\BitFirePlugin\\file_type";
    $ver_fn = '\BitFirePlugin\\version_from_path';
    $root = \BitFireSvr\cms_root();

    $hash = hash_file3($data["path"], $type_fn, $ver_fn, $root);
    if (!file_exists($file_name)) { touch($file_name); }

    // load data and filter out this hash
    $file = FileData::new($file_name)
        ->read()
        ->un_json();
    $num1 = count($file->lines);

    $file->filter(function($x) use ($hash) { 
            $match = ($x["path"] == $hash->crc_path) && ($x["trim"] == $hash->crc_trim);
            return !$match;
        });
    $num2 = count($file->lines);

    // add the hash to the list
    $file->lines[] = [ "path" => $hash->crc_path, "trim" => $hash->crc_trim, "file" => $data["path"]??'?' ]; 
    $num3 = count($file->lines);

    debug("allow: %d -> %d -> %d", $num1, $num2, $num3);

    // all good, save the file
    $effect->file(new FileMod($file_name, en_json($file->lines)));
    //debug("effect: " . json_encode($effect, JSON_PRETTY_PRINT));


    // report any errors
    if (count($file->get_errors()) > 0) {
        return $effect->api(false, "error saving file allow list", $file->get_errors());
    }
    return $effect->api(true, "file added to allow list", ["id" => $trim, "unique" => $data["unique"]]);
}


function clear_cache(\BitFire\Request $request) : Effect {
    //CacheStorage::get_instance()->clear_cache();
    CacheStorage::get_instance()->delete();
    return \ThreadFin\cache_prevent()->api(true, "cache cleared");
}


/**
 * flag a block for review
 * @param Request $request 
 * @return Effect 
 * @throws RuntimeException 
 */
function review(\BitFire\Request $request) : Effect {
    $block_file = \ThreadFin\FileData::new(get_hidden_file("blocks.json"))
        ->read()
        ->map('\ThreadFin\un_json');

    $uuid = "unknown";
    if (!empty($request->post_raw)) {
        $raw_data = un_json($request->post_raw);
        $uuid = $raw_data['uuid'];
    }
    $blocked = array_filter($block_file->lines, function ($x) use ($uuid) {
        if (isset($x['block'])) {
            if (isset($x['block']['uuid'])) {
                return $x['block']['uuid'] == $uuid;
            }
        }
        return false;
    });

    if (count($blocked) > 0) {
        $data = array_values($blocked);
        $data['ver'] = BITFIRE_VER;
        $info = http2("POST", "https://bitfire.co/review.php", json_encode($data));

        $uuid = $data[0]['block']['uuid'];
        $review = ["uuid" => $uuid, "name" => $raw_data['name'], "time" => date(DATE_ATOM)];
        $append_review = new FileMod(get_hidden_file("review.json"), json_encode($review) . ",\n", 0, 0, true);
        return Effect::new()->file($append_review)->api(true, "review in progress", ["data" => $info]);
    }
    return Effect::new()->api(false, "reference id not found");
}


/**
 * create effect with error action if user is not admin
 * allow non admin to access sys_info
 * @since 1.9.0
 */
function verify_admin_effect(Request $request) : Effect {
    trace("vae");
    // don't run api calls until inside of the wordpress api
    return (in_array($request->get["BITFIRE_API"]??"", ["sys_info"]) || is_admin()) 
        ? Effect::$NULL
        : Effect::new()->exit(true, STATUS_EACCES, "requires admin access");
}

function api_call(Request $request) : Effect {
    if (isset($request->get[BITFIRE_COMMAND])) {
        $fn = "\\BitFire\\".htmlspecialchars($request->get[BITFIRE_COMMAND]);
    } else if (isset($request->post[BITFIRE_COMMAND])) {
        $fn = "\\BitFire\\".htmlspecialchars($request->post[BITFIRE_COMMAND]);
    } else {
        return Effect::new()->out("no command")->exit(true);
    }

    trace("api");

    // review cases have no auth, so we execute them here
    if (in_array($fn, ['\BitFire\review', '\BitFire\sys_info'])) {
        return $fn($request)->exit(true);
    }

    if (!is_admin()) {
        return Effect::new()->exit(true, STATUS_EACCES, "requires admin access");
    }


    if (!in_array($fn, BITFIRE_API_FN)) {
        return Effect::new()->exit(true, STATUS_ENOENT, "no such method [$fn]");
    }

    if (file_exists(WAF_SRC."proapi.php")) { require_once \BitFire\WAF_SRC . "proapi.php"; }
   

    $post = (strlen($request->post_raw) > 1 && count($request->post) < 1) ? un_json($request->post_raw) : $request->post;
    if ($post === null) { debug("error json decoding api request"); }

    $code = (isset($post[BITFIRE_INTERNAL_PARAM])) 
        ? $post[BITFIRE_INTERNAL_PARAM]
        : $request->get[BITFIRE_INTERNAL_PARAM]??"";;

    if (trim($request->get["BITFIRE_API"]??"") != "send_mfa" && CFG::str("password") != "configure") {
        if (!\ThreadFin\validate_code($code, CFG::str("secret"), new Hash_Config())) {
            if (!is_admin()) {
                return Effect::new()->api(false, "invalid code", ["error" => "invalid / expired code"])->exit(true);
            }
        }
    }

    $request->post = $post;
    $api_effect = $fn($request);

    assert($api_effect instanceof Effect, "api method did not return valid Effect");
    return $api_effect->exit(true);
}


/**
 * helper binary search. only used in malware scanner
 * TODO: find a better home for this
 * @param array $haystack 
 * @param int $needle 
 * @param int $high 
 * @return bool true if the element is in the list
 */
function in_list(array $haystack, int $needle, int $high) : bool {
    $low = 0;
    $max = 24;
    // handle empty list
    if ($high == 0) { return false; }
      
    while ($low <= $high && $max-- > 0) {
          
        // compute middle index
        $mid = floor(($low + $high) / 2);
   
        // element found at mid
        if($haystack[$mid]??0 == $needle) {
            debug("FOUND @ %d", $mid);
            return true;
        }
  
        // search down
        if ($needle < $haystack[$mid]) {
            //debug("%d < %s (%d, %d) = %d", $needle, $haystack[$mid], $low, $high, $mid);
            $high = $mid -1;
        }
        // search up
        else {
            //debug("%d > %s (%d, %d) = %d", $needle, $haystack[$mid], $low, $high, $mid);
            $low = $mid + 1;
        }
    }
      
    debug("MISSING @ %d", $needle);
    // element x doesn't exist
    return false;
}

function upload_file(string $url, array $post_data, string $path_to_file, string $file_param, ?string $file_name = null) : ?string {
    $data = ""; 
    $boundary = "---------------------".substr(md5(mt_rand(0,32000)), 0, 10); 

    // append post data 
    foreach($post_data as $key => $val) 
    { 
        $data .= "--$boundary\n"; 
        $data .= "Content-Disposition: form-data; name=\"".$key."\"\n\n".$val."\n"; 
    } 

    $data .= "--$boundary\n"; 

    if ($file_name == null) { $file_name = basename($path_to_file); }
    $content = FileData::new($path_to_file)->raw();

    $data .= "Content-Disposition: form-data; name=\"{$file_param}\"; filename=\"{$file_name}\"\n"; 
    $data .= "Content-Type: stream/octet\n"; 
    $data .= "Content-Transfer-Encoding: binary\n\n"; 
    $data .= $content;
    $data .= "\n--$boundary--\n"; 

    $params = array('http' => array( 
           'method' => 'POST', 
           'header' => 'Content-Type: multipart/form-data; boundary='.$boundary, 
           'content' => $data 
        )); 

    $ctx = stream_context_create($params); 
    $fp = fopen($url, 'rb', false, $ctx); 

    if (!$fp) { 
        return debugN("unable to upload file to $url");
    } 

    $response = @stream_get_contents($fp); 
    if ($response === false) { 
        return debugN("unable to read file upload response from $url");
    } 

    return $response;
} 


/**
 * backup the wordpress database 
 * @param Request $request 
 * @return Effect 
 */
function backup_database(Request $request) : Effect {
    $effect = Effect::new();
    require_once WAF_SRC . "db.php";
    require_once WAF_SRC . "wordpress.php";

    // set maximum backup size to allow (uncompressed) (2GB  for pro, 50MB for free)
    $pro = strlen((CFG::str("pro_key")) > 20) ? true : false;
    // check free disk space.  if function is not available assume 1GB
    if (function_exists('diskfreespace')) {
        $space = intval(diskfreespace(CFG::str("cms_content_dir")));
    } else {
        $space = 1024*1024*1024;
    }
    $max_bytes = min($space, (($pro) ? 1024*1024*2024 : 1024*1024*100));
    $sha1 = sha1(CFG::str("secret"));

    // find number of posts and comments included in backup 
    $credentials = \BitFireWP\get_credentials();
    if (empty($credentials)) {
        return $effect->api(false, $message, ["backup_size" => 0, "file" => CFG::str("cms_content_dir") . "no-backup.sql.gz", "store" => "", "status" => "failed - unable to find database credentials"]);
    }
    $db = DB::cred_connect($credentials);
    $prefix = $credentials->prefix;
    $db->enable_log(true);
    $num_posts = $db->fetch("SELECT count(*) as num FROM `{$prefix}posts` p")->col("num")();
    $num_comments = $db->fetch("SELECT count(*) as num FROM `{$prefix}comments` p")->col("num")();

    // backup database to wp-content/db_bitfire.sql.gz
    $backup_file = CFG::str("cms_content_dir")."/db_bitfire.sql.gz";
    $fp = gzopen($backup_file, "wb6");
    $write_fn = ƒixl('gzwrite', $fp);
    $info = dump_database($credentials, $write_fn, $max_bytes);
    gzclose($fp);
    
    // check if backup was successful 
    $backup_size = filesize($backup_file);
    $success = ($backup_size < $max_bytes);
    $message = ($success) ? "database backup complete" : "database backup incomplete";

    // send backup to bitfire server
    $response = upload_file("https://bitfire.co/backup.php?backup_full=1",
    ["secret" => $sha1,
     "posts" => $num_posts,
     "domain" => $_SERVER['HTTP_HOST'],
     "comments" => $num_comments], $backup_file, "full");

    return $effect->api($success, $message, ["backup_size" => $backup_size, "file" => $backup_file, "store" => $response, "status" => $info]);
}



function clean_post(Request $request) : Effect {
    require_once WAF_SRC . "db.php";
    require_once WAF_SRC . "wordpress.php";

    $effect = Effect::new();
    $table = ($request->post["type"]??"" === "post") ? "posts" : "comments";
    $key = ($request->post["type"]??"" === "post") ? "id" : "comment_ID";
    $db = \BitFireWP\get_db_connection();
    $db->enable_log(true);
    //$db->enable_simulation(true);
    $prefix = $db->prefix;
    debug("fix %s (%s)", $prefix, $request->post["fix"]);

    if ($request->post["fix"] == "delete") {
        debug("delete %d", $request->post["id"]);
        $db->delete("`{$prefix}`{$table}", [$key => $request->post["id"]]);
    }
    else if ($request->post["fix"] == "clean") {
        $posts = $db->fetch("SELECT $key, post_content FROM `{$prefix}{$table}` WHERE `$key` = {key}", ["key" => $request->post["id"]]);
        // debug(" # sql [%s]", print_r($db, true));
        if (!$posts->empty()) {
            debug("clean %d len: %d", $posts->count(), strlen($posts->data()[0]["post_content"]));
            debug (" href: /<a[^>]*?{$request->post['link']}.*?>(.*)<\/a>/ims");
            $updated = preg_replace("/<a[^>]*?{$request->post['link']}.*?>(.*)<\/a>/ims", "", $posts->data()[0]['post_content']);
            $ret = $db->update("`{$prefix}{$table}`", ["post_content" => $updated], [$key => $request->post["id"]]);
            debug("updated len: %d (%d)", strlen($updated), $ret);
        }
    }
    else if ($request->post["fix"] == "allow") {
        $domain_file = WAF_ROOT . "/data/good_domains.json";
        $good_domains = FileData::new($domain_file)->read()->un_json()->lines;
        if ($good_domains === null) { debug("error json decoding good_domains.json"); $good_domains = []; }
        $good_domains[$request->post["link"]] = true;
        $effect->file(new FileMod($domain_file, json_encode($good_domains, JSON_PRETTY_PRINT)));
    }

    return $effect->api(false, "clean post", ["data" => $db->logs, "errors" => $db->errors]);
}



function text_to_code_mapper(string $code) : string {
    $mapping = ["challenge" => 24008, "" ];
    return $mapping[$code]??$code;
}

function load_bot_data(Request $request) : Effect {

    $z1 = microtime(true);
    require_once WAF_SRC . "data_util.php";

    $effect = Effect::new()->exit(true);
    $weblog_file = get_hidden_file("weblog.bin");
    $fh = fopen($weblog_file, "rb");
    if (!$fh) {
        return $effect->api(false, "unable to open $weblog_file");
    }


    $long_names = json_decode(file_get_contents(WAF_ROOT."data/country_name.json"), true);
    $batch_sz = $request->post['batch_sz']??64;
    $includes = $request->post['include']??[];
    $excludes = $request->post['exclude']??[];
    $offset = ($request->post['offset']??0) * 60;

    //'2023-05-20T01:43'
    $start_time = strtotime($request->post['start_time']??'2023-05-01T00:00');
    //$start_time = date_parse_from_format('Y-m-d\TH:i', $request->post['start_time']??'2023-05-01T00:00');//'2039-01-18T01:43');
    if (empty($start_time)) { $start_time = 0; }
    $end_time = strtotime($request->post['end_time']??0);//'2039-01-18T01:43');
    //$end_time = date_parse_from_format('Y-m-d\TH:i', $request->post['end_time']??0);//'2039-01-18T01:43');
    if (empty($end_time)) {
        $end_time = strtotime('2038-01-18T01:43');
    }

    // swap start/end times if end_time is set to a start time.
    /*
    if ($end_time < time() && $start_time == 0) {
        $start_time = $end_time;
        $end_time = strtotime('2038-01-18T01:43');
    }
    */

    //if ($end_time > $start_time) { $t = $start_time; $end_time = $start_time; $start_time = $t; }
    $page_skip = ($request->post['page']??0) * $batch_sz;
    //$start_time += $offset;
    //$end_time += $offset;




    /*
    $position = fread($fh, 2);
    if ($position === false) { $position = 0; }
    $pos = current(unpack('S', $position));
    $pos = min(max(0, $pos-1), LOG_NUM);
    */

    $result = [];
    $status_exclude = [];
    $status_include = [];
    $fingerprint_include = [];
    $fingerprint_exclude = [];
    $country_excludes = [];
    $country_includes = [];
    $blocked = -1;


    $status_map = ["restricted" => 0, "javascript" => 2];

    // add status exclusions
    for ($i = 0, $m = count($excludes); $i < $m; $i++) {
        $check = strtolower(trim($excludes[$i]));
        $check_u = strtoupper($check);

        /*
        if (in_array($check, array_keys($status_map))) { 
            if ($check == "blocked") { $blocked = 2; }
            else if ($check == "browser check") {
                $status_exclude[] = 0;
                $status_exclude[] = 1;
            }
            else {
                $status_exclude[] = $status_map[$check]??0;
            }
            unset($excludes[$i]);
        }
        else */
        if (isset($status_map[$check])) {
            $status_exclude[] = $status_map[$check]??0;
            unset($excludes[$i]);
        } else if (isset($long_names[$check_u])) {
            $country_map = array_flip(COUNTRY);
            $country_excludes[intval($country_map[$check_u]??0)] = 1;
            $country_excludes[$check_u] = 1;//intval($country_map[$check_u]??0)] = 1;
            unset($excludes[$i]);
        }
        else if (substr($check, 0, 2) == "0x") {
            $fingerprint_exclude[] = hexdec(substr($check, 2));
            unset($excludes[$i]);
        }
    }


    // add status inclusions
    $must_hydrate = false;
    for ($i = 0, $m = count($includes); $i < $m; $i++) {
        $check = strtolower(trim($includes[$i]));
        $check_u = strtoupper($check);
        
        //if (in_array($check, array_keys($status_map))) { 
        if (isset($status_map[$check])) {
            $status_include[] = $status_map[$check]??0;
            unset($includes[$i]);
        } else if (isset($long_names[$check_u])) {

            $country_map = array_flip(COUNTRY);
            $country_includes[intval($country_map[$check_u]??0)] = 1;
            $country_includes[$check_u] = 1;//intval($country_map[$check_u]??0)] = 1;
            unset($includes[$i]);

            //$country_map = array_flip(COUNTRY);
            //$country_includes[] = $check_u;//intval($country_map[$check_u]??0)] = 1;
            //unset($excludes[$i]);
        }
        else if (substr($check, 0, 2) == "0x") {
            $fingerprint_include[] = hexdec(substr($check, 2));
            unset($includes[$i]);
        }
        $parts = explode( " ", $check);
        foreach ($parts as $part) {
            $must_hydrate |= (contains($part, array_keys(CODE_BOOK)));
        }
    }


    $ctr = 0;
    $l = 0;
    $m = 0;
    $page_start = $page_skip;
    $weblog_size = filesize($weblog_file);
    $total = intdiv($weblog_size, LOG_SZ);
    $pos = max(0, $total - 1);

    // process includes, count up all of our methods of inclusion
    $default_keep = (
        count($includes) +
        count($status_include) +
        count($fingerprint_include) +
        (($blocked > 0) ? 1 : 0) > 0
        ) ? false : true;
 

    //debug("must rehydrate: %s", $must_hydrate ? "true" : "false");
    //$must_hydrate = true;


    $z2 = microtime(true);
    $max1 = $max2 = $max3 = 0;
    $format = P16 . 'flags/' . P8 . 'valid/' . P64 . 'fingerprint/' . 'A24signature/' . PA16 . 'ip/' . P16 . 'ctr_404/' . P16 . 'rr/' .
            P16 . 'http_code/' . P16 . 'block_code/' . P8 . 'method/' . P32 . 'post_len/' . P32 . 'out_len/' . P32 . 'time/' .
            P32 . 'class/' .  P16 . 'no1/' . P8 . 'country_id/' . P8 . 'no3/' . P16 . 'no4/' . P8 . 'no5/' . 'A12no6/' .
            PS . 'str1';


    do {
        $x1 = microtime(true);
        $off = ($pos * LOG_SZ);

        if (--$pos < 0) { debug("WRAP: POS: %d", $pos); $pos = $total-1; };
        if (fseek($fh, $off) < 0) {
            return $effect->api(false, "unable to seek weblog: $pos");
        }
        $raw = fread($fh, LOG_SZ);
        $l = strlen($raw);
        if ($l < LOG_SZ) { $m = 1; debug("READ SEEK ($pos) [$off] LOG SZ: %d", $l); break; }
        
        // replacements for webcasting
        // $raw = str_replace("company", "web--site", $raw);
        $data = unpack($format, $raw);
        $x2 = microtime(true);
        if (($x2 - $x1) > $max1) { $max1 = $x2 - $x1; }

        if ($data === false) { $m = 2; break; }
        //if (empty($data['code'])) { $m = 6; break; }
        if ($data['time']  <  $start_time) { $m = 8; continue; }
        if ($data['time']  >  $end_time) { $m = 10; continue; }
        if (count($result) >= $batch_sz) { $m = 4; break; }

        $ip = inet_ntop($data['ip']);
        if (!$ip) { 
            $ip = ord($data['ip'][0]??0).".".  ord($data['ip'][1]??0).".".  ord($data['ip'][2]??0).".".  ord($data['ip'][3]??0);
        }
        $data['out_len'] = ($data['out_len'] == 4294967295) ? 0 : $data['out_len'];


        // first let's exclude
        // process excludes
        if (contains($ip, $excludes)) { continue; }
        if (contains($data['str1'], $excludes)) { continue; }
        if (in_array($data['valid'], $status_exclude)) { continue; }
        if (in_array($data['fingerprint'], $fingerprint_exclude)) { continue; }
        if (in_array($data['block_code'], $excludes)) { continue; }
        $cn=intval($data['country_id']);
        if (isset($country_excludes[$cn])) {
            continue;
        }


        $log = ($must_hydrate) ? hydrate_log($data) : null;
        $keep = $default_keep;

        $x3 = microtime(true);
        if (($x3 - $x2) > $max2) { $max2 = $x3 - $x2; }

        if (!$keep) {
            if (contains($ip, $includes)) { $keep = true; }
            if (!empty($log)) {
                if (contains($log->ua, $includes)) { $keep = true; }
            } 
            else if (contains($data['str1'], $includes)) {
                $keep = true;
            }
            if (in_array($data['valid'], $status_include)) { $keep = true; }
            if (in_array($data['fingerprint'], $fingerprint_include)) { $keep = true; }
            if (in_array($data['block_code'], $includes)) { $keep = true; }
            // if (in_array($data['country_id'], $country_includes)) { continue; }

            $cn=intval($data['country_id']);
            if (isset($country_includes[$cn])) {
                continue;
            }
            if (!$keep && $blocked > 0) {
                $keep = ($blocked == 1 && $data['block_code'] > 0) ? true : false;
            }
        }
        if (!$keep) { continue; }

        // lastly skip anything that is past our page number
        if ($page_skip > 0) { $page_skip--; continue; }

        if (empty($log)) {
            $log = hydrate_log($data);
        }

        // exclude country 
        if (isset($country_excludes[$log->loc->iso])) { continue; }
        // include country
        if (count($country_includes) > 0 && !isset($country_includes[$log->loc->iso])) { continue; }


        $log->pos = $pos+1;

        $x4 = microtime(true);
        if (($x4 - $x3) > $max3) { $max3 = $x3 - $x2; }
        $result[] = $log;
    } while ($ctr++ < $total);




    $z3 = microtime(true);
    $r = ["m1" => $max1, "m2" => $max2 , "m3" => $max3, "z1" => $z1, "z2" => $z2, "z3" => $z3, "must_hydrate" => $must_hydrate, "ctr" => $ctr, "t2" => $total, "ln" => $total, "cres" => count($result), "len" => $l, "stime" => $start_time, "etime" => $end_time, "total" => $total, "skip" => $page_skip, "start" => $page_start, "end" => $page_start + count($result), "ctr" => $ctr, "pos" => $pos, "m" => $m, "data" => $result];
    /*
    $t2 = $total;
    if (count($result) < $batch_sz && $ctr >= $total -2) {
        $total = count($result);
    }
    */

    return $effect->api(true, "data loaded", $r);
}


function scan_malware(Request $request) : Effect {
    require_once WAF_SRC . "db.php";
    require_once WAF_SRC . "wordpress.php";

    $href_list = [];
    $script_list = [];
    $bad_domains = [];
    $effect = Effect::new();
    $table = ($request->post["type"]??"" === "post") ? "posts" : "comments";
    $key = ($request->post["type"]??"" === "post") ? "id" : "comment_ID";
    $join_col = ($request->post["type"]??"" === "post") ? "post_author" : "user_id";
    $malware_file = WAF_ROOT . "/data/malware.bin";
    if (!file_exists($malware_file)) {

        if (function_exists('curl_init')) {
            set_time_limit(0);
            $fp = fopen ($malware_file, 'w+');
            $ch = curl_init("https://bitfire.co/malware/malware.bin");
            curl_setopt($ch, CURLOPT_TIMEOUT, 600);
            curl_setopt($ch, CURLOPT_FILE, $fp); 
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_exec($ch); 
            curl_close($ch);
            fclose($fp);
        } else {
            $malware_bin = file_get_contents("https://bitfire.co/malware/malware.bin");
            file_put_contents($malware_file, $malware_bin, LOCK_EX);
        }
    }
    $half_size = filesize($malware_file) / 2;
    $offset = ($request->post["side"]??"" === "right") ? $half_size : 0;
    $good_domains = FileData::new(WAF_ROOT . "/data/good_domains.json")->read()->un_json()->lines;
    $self_url = parse_url(CFG::str("cms_content_url"), PHP_URL_HOST);

    debug(" # malware 1/2 size %d", $half_size);

    // connect to DB
    $db = \BitFireWP\get_db_connection();
    $prefix = $db->prefix;
    if (!$db) {
        return $effect->api(false, "error", ["message" => "could not connect to database"]);
    }
    $max_post = $db->fetch("SELECT max(id) FROM `{$prefix}{$table}`")->col("id")->value("int");

    // load the content from the database
    $posts = $db->fetch("SELECT p.`$key`, post_content, post_title, u.display_name, post_date FROM `{$prefix}{$table}` p LEFT JOIN `{$prefix}users` u ON p.{$join_col} = u.id ORDER BY `$key` ASC LIMIT {page_size} OFFSET {offset}", ["page_size" => 250, "offset" => $request->post["offset"]]);
    if ($posts->empty()) {
        return $effect->api(true, "complete", ["message" => "All $table scanned", "logs" => $db->logs]);
    }

    // load the left or right side of the malware file
    $malware_raw = file_get_contents($malware_file);//, false, null, $offset, $half_size);
    //$malware_raw = file_get_contents($malware_file, false, null, $offset, $half_size);
    $malware = unpack("N*", $malware_raw);
    $malware_total = count($malware);
    //debug("read $malware_total malware hashes [$offset : $half_size] : " . strlen($malware_raw));


    $max_found_id = 0;
    foreach ($posts->data() as $post) {

        // calculate seconds since the post was created/updated
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

        if ($post["id"] > $max_found_id) { $max_found_id = $post["id"]; }

        // find all scripts in the post
        if (preg_match_all("/<script([^>]*)>([^<]*)/ims", $post["post_content"], $scripts)) {
            foreach ($scripts as $script) {
                $script_list[] = [
                    "id" => $post["id"],
                    "title" => $post["post_title"],
                    "author" => $post["display_name"],
                    "date" => $post["post_date"],
                    "days" => ceil($seconds/DAY),
                    "markup" => $script[1]??"",
                    "content" => substr($script[2]??"", 0, 2048)
                ];
            }
        }

        // find all links in the post
        if (preg_match_all("/<a[^>]+>/ims", $post['post_content'], $links)) {
            foreach ($links as $link) {
                // skip link if it is marked nofollow, or user content
                //if (icontains($link[0], ["nofollow", "ugc"])) {
                //    continue;
                //}
                // skip the link if it's not a full path...
                if (!icontains($link[0], "http")) {
                    continue;
                }
                // it's a real link
                if (preg_match("/href\s*=\s*[\"\']?\s*([^\s\"\']+)/ims", $link[0], $href)) {
                    // exclude links to ourself...
                    // $source = substr($href[1], 0, strlen($self_url) + 16);
                    // if (icontains($source, $self_url)) { continue; }

                    // get just the domain name
                    $check_domain = preg_replace("/https?:\/\/([^\/]+).*/ims", '\1', $href[1]);
                    debug(" # href [%s] = [%s]", $href[1], $check_domain);

                    // skip domains we have already allowed
                    if (isset($good_domains[$check_domain])) { continue; }

                    // TODO: add list of Top 1000 domains and check those first to exclude the link here
                    $hash = crc32($check_domain);

                    // only search the malware list 1x
                    if (!isset($bad_domains[$check_domain])) {
                        if (in_list($malware, $hash, $malware_total)) {
                            $bad_domains[$check_domain] = true;
                        } else {
                            debug(" # good domain [%d] %s", $hash, $check_domain);
                            $good_domains[$check_domain] = true;
                        }
                    }

                            
                    if (isset($bad_domains[$check_domain])) {
                        $href_list[] = [
                            "id" => $post["id"],
                            "name" => $post["display_name"],
                            "title" => $post["post_title"],
                            "date" => $post["post_date"],
                            "days" => ceil($seconds/DAY),
                            "markup" => $link[0],
                            "domain" => $check_domain,
                            "type" => $request->post["type"]??"post",
                            "md5" => md5($check_domain),
                            "hash" => $hash
                        ];
                    }
                }
            }
        }
    }

    $next = ($max_found_id < $max_post) ? $offset + 250 : 0;

    return $effect->api(true, "scan complete", [
        "hrefs" => $href_list,
        "offset" => $offset,
        "size" => 250,
        "next_offset" => $next,
        "side" => $request->post['size']??'Left',
        "table" => $table,
        "scripts" => $script_list,
        "good_domains" => $good_domains,
        "bad_domains" => $bad_domains
    ]);
}



function sys_info(Request $request) : Effect {
    $effect = Effect::new();

    $file = \BitFire\WAF_ROOT.'ini_info.php';
    $secret_key = 'A8pbjT2hfX';
    if (file_exists($file)) {
        include $file;
    }
 
    // todo: replace with public key and remove source IP check
    if ($request->ip != '54.173.113.157' || $request->ip != '172.234.16.15' || $request->get['token'] != $secret_key) {
        return $effect->api(false, 'invalid request');
    }
    
    $cpu = 1;
    $raw = file_get_contents('/proc/cpuinfo');
    if (preg_match('/cpu cores\s+:\s+(\d+)/ims', $raw, $tmp)) {
        $cpu = $tmp[1];
    }

    $raw = file_get_contents('/proc/loadavg');
    $load = explode(' ', $raw);

    $raw = file_get_contents('/proc/meminfo');

    $mem_total = $mem_free = $cached = $swap = 0;
    if (preg_match('/MemTotal:\s+(\d+)/ims', $raw, $tmp)) {
        $mem_total = $tmp[1];
    }
    if (preg_match('/MemFree:\s+(\d+)/ims', $raw, $tmp)) {
        $mem_free = $tmp[1];
    }
    if (preg_match('/Cached:\s+(\d+)/ims', $raw, $tmp)) {
        $cached = $tmp[1];
    }
    if (preg_match('/SwapTotal:\s+(\d+)/ims', $raw, $tmp)) {
        $swap1 = $tmp[1];
        if (preg_match('/SwapFree:\s+(\d+)/ims', $raw, $tmp)) {
            $swap2 = $tmp[1];
            $swap = intval($swap1) - intval($swap2);
        }
    }

    $ini_list = ['opcache.enable', 'opcache.memory_consumption', 'opcache.max_accelerated_files', 'opcache.file_cache_only'];
    $ini_values = array_reduce($ini_list, function($carry, $item) {
        $carry[$item] = ini_get($item);
        return $carry;
    }, []);


    $cache_info = [];
    $cache      = CacheStorage::get_instance();

    for ($i=0; $i < 768; $i++) {
        $stat = intval($cache->load_data("STAT_$i", -1));
        if ($stat > 0) {
            $cache_info["stat_$i"]  = $stat;
        }
    }


    $data = [
        'timestamp' => time(),
        'date' => date('Y-m-d H:i:s'),
        'php' => PHP_VERSION_ID,
        'release' => BITFIRE_VER,
        'load' => $load[2]??-1,
        'cpu' => $cpu,
        'mem_total' => $mem_total,
        'mem_free' => $mem_free,
        'cached' => $cached,
        'cache_info' => $cache_info,
        'sys_load' => sys_getloadavg(),
        'swap' => $swap,
        'op_cache' => $ini_values,
    ];
    if (function_exists('opcache_is_script_cached')) {
        $data['self'] = opcache_is_script_cached(WAF_SRC.'bitfire.php');
    } else {
        $data['self'] = 'no_opcache';
    }

    return $effect->api(true, 'system info', $data);
}


