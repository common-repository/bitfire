<?php

namespace BitFirePlugin;

use BitFire\Config AS CFG;
use ThreadFin\FileData;

use function BitFireSvr\trim_off;
use function BitFireSvr\update_ini_value;
use function ThreadFin\get_sub_dirs;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\file_recurse;
use function ThreadFin\find_const_arr;
use function ThreadFin\find_fn;
use function ThreadFin\HTTP\http2;
use function ThreadFin\trace;

define("BitFire\\CMS_INCLUDED", true);

const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["/plugins/", "/themes/"];
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "style.css", "package.json"];

/**
 * get the wordpress version from a word press root directory
 */
function get_cms_version(string $root_dir): string
{
    $full_path = "$root_dir/wp-includes/version.php";
    $wp_version = "1.0";
    if (file_exists($full_path)) {
        include $full_path;
    }
    return trim_off($wp_version, "-");
}


/**
 * return the hash file type
 * @param string $path 
 * @return string 
 */
function file_type(string $path) : string {
    if (strpos($path, "/plugins/") > 0) { return "wp_plugin"; }
    if (strpos($path, "/themes/") > 0) { return "wp_themes"; }
    if (strpos($path, "/wp-content/") > 0) { return "wp_plugin"; }
    return "wp_core";
}

/**
 * convert a path to a source url
 * @param string $name 
 * @param string $path 
 * @param string $ver 
 * @return string 
 */
function path_to_source(string $rel_path, string $type, string $ver, ?string $name=null, bool $final = false) : string {

    static $core_ver = null;
    if ($core_ver == null) {
        global $wp_version;
        $core_ver = (isset($wp_version)) ? $wp_version : $core_ver = CFG::str("wp_version");
    }

    switch($type) {
        case "wp_plugin":
            $source = "plugins.svn.wordpress.org/{$name}/tags/{$ver}/{$rel_path}";
            $alt = "plugins.svn.wordpress.org/{$name}/tags/";
            break;
        case "wp_themes":
            $source = "themes.svn.wordpress.org/{$name}/{$ver}/{$rel_path}";
            $alt = "themes.svn.wordpress.org/{$name}/tags/";
            break;
        case "wp_core":
        default:
            $source = "core.svn.wordpress.org/tags/{$core_ver}/{$rel_path}?type={$type}";
            $alt = "core.svn.wordpress.org/tags/{$core_ver}/";
            break;
    }
    $source = "https://" . str_replace("//", "/", $source);
    $x = http2("HEAD", $source);

    // compute numeric version number
    $parts = explode(".", $ver);
    $check_num = (intval($parts[0]??1) * 10000) + (intval($parts[1]??0) * 100) + intval($parts[2]??0);

    if (! $x['success'] && !$final) {
        $html_list = http2("GET", $alt);
        $links = take_links($html_list->content);
        $min_dist = 99999999;
        $new_ver = "trunk";
        // compare each tag version against the check version and find the nearest version number
        foreach(array_keys($links) as $link) {
            $ver = str_replace("/", "", $link);
            $parts = explode(".", $ver);
            $num = (intval($parts[0]??1) * 10000) + (intval($parts[1]??0) * 100) + intval($parts[2]??0);
            $diff = abs($num - $check_num);
            if ($diff < $min_dist) {
                $min_dist = $diff;
                $new_ver = $ver;
            }
        }

        return path_to_source($rel_path, $type, $new_ver, $name, true);
    }

    return $source;
}


/**
 * return the version number for a package.json or readme.txt file
 * @param mixed $path 
 * @return string 
 */
function package_to_ver(string $carry, string $line) : string {
    if (!empty($carry)) { return $carry; }
    if (preg_match("/stable\s+tag\s*[\'\":]+\s*([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    if (preg_match("/version\s*[\'\":]+\s*([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    return $carry;
}

function malware_scan_dirs(string $root) : array {
    debug("malware_scan (%s)", $root);
    $r1 = realpath(CFG::str("cms_root"))."/";
    $r2 = realpath(CFG::str("cms_content_dir"))."/";

    if (!ends_with($root, "/")) { $root .= "/"; }
    $d1 = CFG::str("cms_content_dir")."/plugins";
    $d2 = CFG::str("cms_content_dir")."/themes";
    $d3 = CFG::str("cms_content_dir")."/uploads";
    $t4 = get_sub_dirs(CFG::str("cms_root"));
    $d4 = array_diff($t4, ["{$r1}wp-content", "{$r1}wp-includes", "{$r1}wp-admin"]);
    $t5 = get_sub_dirs(CFG::str("cms_content_dir"));
    $d5 = array_diff($t5, ["{$r2}plugins", "{$r2}themes"]);

    $result = array_merge(get_sub_dirs($d1), get_sub_dirs($d2), get_sub_dirs($d3), $d4, $d5);
    $q1 = array_unique($result);
    return $q1;
}



// find a plugin / theme version number located in $path
function version_from_path(string $path, string $default_ver = "") {
    static $versions = [];

    $reg = "(.*?\\".DIRECTORY_SEPARATOR."(plugins|themes))\\".DIRECTORY_SEPARATOR."([^\\".DIRECTORY_SEPARATOR."]+)";
    if (preg_match("/$reg/", $path, $matches)) {
        $root = $matches[0];
        if (isset($versions[$root])) {
            return $versions[$root];
        }
    }
    // not a plugin, use default version
    else {
        return $default_ver;
    }


    $package_fn = find_fn("package_to_ver");
    $package_files = find_const_arr("PACKAGE_FILES");
    $php_files = array_map('basename', glob(dirname($root)."/*.php"));
    $all_files = array_merge($package_files, $php_files);

    foreach($all_files as $file) {
        $file_path = "{$root}/{$file}";
        if (file_exists($file_path)) {
            $version = FileData::new($file_path)->read()->reduce($package_fn, "");
            if ($version) {
                $versions[$root] = $version;
                return $version;
            }
        }
    }
    return $default_ver;
}

function take_links(string $input): array
{
    preg_match_all("/href=['\"]([^'\"]+)['\"].*?>([^<]+)/", $input, $matches);
    $result = array();
    for ($i = 0, $m = count($matches[1]); $i < $m; $i++) {
        $result[$matches[1][$i]] = $matches[2][$i];
    }
    return array_filter($result, function ($x) {
        return $x != '..' && $x != '../' && strpos($x, 'subversion') === false;
    }, ARRAY_FILTER_USE_KEY);
}



/**
 * @OVERRIDE for cms_root() function
 * @since 1.9.1
 */
function find_cms_root() : ?string {
    $cfg_path = CFG::str("cms_root");

    // prefer to use WordPress code
    if (function_exists('get_home_path')) {
        $root = \get_home_path();
        if ($root !== $cfg_path) {
            update_ini_value("cms_root", $root)->run();

        }
        return $root;
    }

    // if the cms_root in config is set to a valid WordPress dir, use that
    if (contains($cfg_path, $_SERVER["DOCUMENT_ROOT"]) && file_exists("$cfg_path/wp-config.php")) {
        return $cfg_path;
    }

    // go a searching...
    $files = file_recurse($_SERVER["DOCUMENT_ROOT"], function($path) {
        if (file_exists($path)) {
            return dirname($path);
        }
    }, "/wp-config.php/", [], 1);
    debug("files [%s]", print_r($files, true));

    // order all found wp-config files by directory length.
    // this can happen when a user backups a old wordpress install INSIDE
    // the current wordpress install.  We want to find the most recent
    usort($files, function($a, $b) { return strlen($a) <=> strlen($b); });

    if (isset($files[0]) && file_exists($files[0])) {
        trace("UPDATE_CMS_ROOT");
        update_ini_value("cms_root", $files[0])->run();
        return $files[0];
    }

    // didn't find anything. we use document root instead...
    debug("cms_root not found. using document root");
    return $_SERVER['DOCUMENT_ROOT']??"/";
}


