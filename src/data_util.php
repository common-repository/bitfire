<?php
namespace BitFire\Data;

use BitFire\Request;
use BitFire\UserAgent;
use BitFireSvr\Whois_Info;

use function BitFire\on_err;
use function BitFireBot\validate_header;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\get_hidden_file;
use function ThreadFin\len;
use function ThreadFin\at;

use const BitFire\COUNTRY;
use const BitFire\METHODS;
use const BitFire\REQ_USER_LIST;
use const BitFire\WAF_ROOT;
use const BitFire\WAF_SRC;

require_once WAF_SRC . "browser_data.php";
require_once WAF_SRC . "botfilter.php";

const CODE_BOOK = [
    'like' => 128,
    'mozilla' => 129,
    'gecko' => 130,
    'applewebkit' => 131,
    'khtml' => 132,
    'mobile' => 133,
    'iphone' => 134,
    'android' => 135,
    'safari' => 136,
    'linux' => 137,
    'chrome' => 138,
    'build' => 139,
    'version' => 140,
    'fbav' => 141,
    'mac' => 142,
    'net' => 143,
    'cpu' => 144,
    'clr' => 145,
    'ios' => 146,
    'fbios' => 147,
    'iab' => 148,
    'phone' => 149,
    'fbrv' => 150,
    'ipad' => 151,
    'instagram' => 152,
    'windows' => 153,
    'dpi' => 154,
    'compatible' => 155,
    'msie' => 156,
    'trident' => 157,
    'nrd' => 158,
    'samsung' => 159,
    'lmy' => 160,
    'mmb' => 161,
    'ppr' => 162,
    'mra' => 163,
    'bytespider' => 164,
    'opr' => 165,
    'opera' => 166,
    'ucbrowser' => 167,
    'huawei' => 168,
    'sdk' => 169,
    'afma' => 170,
    'wow' => 171,
    'slcc' => 172,
    'media' => 173,
    'center' => 174,
    'yaapp' => 175,
    'yasearchbrowser' => 176,
    'infopath' => 177,
    'qcom' => 178,
    'moto' => 179,
    'redmi' => 180,
    'yabrowser' => 181,
    'kot' => 182,
    'arm' => 183,
    'mini' => 184,
    'lenovo' => 185,
    'pixel' => 186,
    'pkq' => 187,
    'opm' => 188,
    'presto' => 189,
    'orca' => 190,
    'gtb' => 191,
    'nmf' => 192,
    'com' => 193,
    'yandexsearch' => 194,
    'messengerforios' => 195,
    'samsungexynos' => 196,
    'nexus' => 197,
    'app' => 198,
    'plus' => 199,
    'midp' => 200,
    'xiaomi' => 201,
    'htc' => 202,
    'verizon' => 203,
    'zen' => 204,
    'bri' => 205,
    'note' => 206,
    'asus' => 207,
    'nettype' => 208,
    'bonprix' => 209,
    'ucweb' => 210,
    'api' => 211,
    'pro' => 212,
    'win' => 213,
    'zenkit' => 214,
    'lte' => 215,
    'jdq' => 216,
    'internalnewdesign' => 217,
    'pinterest' => 218,
    'opd' => 219,
    'oneplus' => 220,
    'yandexsearchbrowser' => 221,
    'zte' => 222,
    'nokia' => 223,
    'gamut' => 224,
    'lge' => 225,
    'ajq' => 226,
    'outlook' => 227,
    'jssdk' => 228,
    'kirin' => 229,
    'microsoft' => 230,
    'wifi' => 231,
    'lite' => 232,
    'gzip' => 233,
    'osmeta' => 234,
    'vivo' => 235,
    'ktu' => 236,
    'play' => 237,
    'one' => 238,
    'google' => 239
];

const HEADER_BOOK = [
  'q=0.9' => 'A',
  'gzip' => 'B',
  'deflate' => 'C',
  'br' => 'D',
  'compress' => 'E',
  'document' => 'F',
  '?1' => 'G',
  'navigate' => 'H',
  'none' => 'I',
  'text/html' => 'J',
  'application/xhtml+xml' => 'K',
  'application/xml' => 'L',
  'image/avif' => 'M',
  'image/webp' => 'N',
  'image/apng' => 'O',
  '*/*' => 'P',
  'q=0.8' => 'Q',
  'application/signed-exchange' => 'R',
  'q=0.7' => 'S',
  '?0' => 'T',
  'no-cache' => 'U',
  'keep-alive' => 'V',
  'text/plain' => 'W',
  'application/javascript' => 'X',
  'application/rss+xml' => 'Y',
  'application/atom+xml' => 'Z',
  'application/x-www-form-urlencoded' => 'a',
  'application/json' => 'b',
  'multipart/form-data' => 'c',
  'image/png' => 'd',
  'image/gif' => 'e',
  'image/jpeg' => 'f',
  'image/svg+xml' => 'g',
  'multipart/form' => 'h',
  'upgrade' => 'i',
  'sdch' => 'j',
  'application/xhtml' => 'k',
  '*' => 'l',
  'max-age' => 'm',
  'public' => 'n',
  'private' => 'o',
  'cors' => 'p',
  'no-cors' => 'q',
  'same-origin' => 'r',
  'no-store' => 's',
  'q=1.0' => 't',
  'q=0.1' => 'u',
  'text/css' => 'v',
  'text/javascript' => 'w',
  'text/xml' => 'x',
  'application/x' => 'y',
  'application/octet' => 'z',
  '"Linux"' => '0',
  '"Windows"' => '1',
  '"macOS"' => '2',
  '__' => '3',
  '___' => '4',
  'application/zip' => '5',
  'application/octet-stream' => '6',
  'audio/mpeg' => '7',
  'audio/wav' => '8',
  'audio/ogg' => '9',
  'video/mp4' => ':',
  'video/webm' => ';',
  'video' => '<',
  'identity' => '=',
  'x-gzip' => '>',
  'x-compress' => '?',
  'close' => '@',
  'exi' => '!',
  'no-transform' => '#',
  'must-revalidate' => '$',
  'nested-navigate' => '%',
  'embed' => '^',
  'empty' => '&',
  'iframe' => '*',
  'worker' => '(',
  'style' => ')',
  'script' => '_',
  'report' => '+',
  'object' => '~',
  'manifest' => '`',
  'image' => '[',
  'font' => ']',
  'audio' => '{',
  'q=0.6' => '}',
  'q=0.5' => '|',
  'q=0.4' => '-',
  'q=0.2' => '"',
  's-maxage' => '\'',
  'immutable' => '~',
  'reload' => '`',
  'force-cache' => ' '];



const ALPHA = [
    'a' => 1, 'b' => 1, 'c' => 1, 'd' => 1, 'e' => 1, 'f' => 1,
    'g' => 1, 'h' => 1, 'i' => 1, 'j' => 1, 'k' => 1, 'l' => 1,
    'm' => 1, 'n' => 1, 'o' => 1, 'p' => 1, 'q' => 1, 'r' => 1,
    's' => 1, 't' => 1, 'u' => 1, 'v' => 1, 'w' => 1, 'x' => 1,
    'y' => 1, 'z' => 1];



/**
 * compress a user agent string by replacing items in CODE_BOOK with a single byte
 * @param string $input 
 * @return string 
 */
function ua_compress(string $input) : string {
    
    $m = len($input);
    $output = $test = "";

    for ($i=0; $i<$m; $i++) {
        $j = $input[$i];
        if (isset(ALPHA[$j])) {
            $test .= $input[$i];
        } else {
            if (isset(CODE_BOOK[$test])) {
                $output .= chr(CODE_BOOK[$test]) . $j;
            } else {
                $output .= $test . $j;
            }
            $test = "";
        }
    }

    return $output . (isset(CODE_BOOK[$test]) ? chr(CODE_BOOK[$test]) : $test);
}

/**
 * de-compress a user agent string
 * @param string $input 
 * @return string 
 */
function ua_decompress(string $input) : string {
    static $book = null;
    if ($book === null) { $book = array_flip(CODE_BOOK); }

    $output2 = '';
    $m = len($input);

    for ($i=0; $i<$m; $i++) {
        $x = ord($input[$i]);
        $output2 .= ($x > 127)
            ? $book[$x]??'?'
            : $input[$i];
    }

    return $output2;
}





/**
 * binary search for needle in file
 * @param mixed $fh file handle for the binary IP data
 * @param int $needle ip to search for
 * @param int $file_sz size of the file
 * @param int $block_sz block size for each entry
 * @return int pointer to city data
 */
function ip4_in_list($fh, int $needle, int $file_sz, int $block_sz) : int {
    $low = 0;
    $max = 24;
    $high = floor($file_sz / $block_sz);

    // handle empty list
    if ($high == 0) { return -1; }
      
    while ($low <= $high && $max-- > 0) {
          
        // compute middle index
        $mid = floor(($low + $high) / 2);
        // compute offset
        $pos = max(0, ($mid * $block_sz) - $block_sz);

        // read 2 blocks(previous end is our start)
        fseek($fh, $pos);
        $block = fread($fh, $block_sz * 2);
        $data = unpack("Vstart/VuniB/Vend/VuniA", $block);

        // is our needle in the range?
        if ($data['start'] <= $needle && $data['end'] >= $needle) {
            return $data['uniA'];
        }
  
        // search down
        if ($needle < $data['start']) {
            $high = $mid -1;
        }
        // search up
        else {
            $low = $mid + 1;
        }
    }
      
    // element x doesn't exist
    return -2;
}

/**
 * uni to country code
 * @param int $uni - 
 * @return int 
 */
function ip4_uni_to_country_code(int $uni) : int  {
    $cn = ($uni&0x000000FF);
    return $cn;
}

/**
 * uni to city file position
 * @param int $uni - uni from ip4_to_uni or ip6_to_uni
 * @return int - city.bin position
 */
function ip4_uni_to_pos(int $uni) : int {
    $pos = ($uni>>8);
    return $pos;
}

/**
 * 
 * @param string $ip - ipv4 address
 * @param string $file - the ip database file
 * @return int 
 */
function ip4_to_uni(string $ip) : int {
    static $fh = null;
    static $sz = 0;
    $ip_num = ip2long($ip);
    if ($fh === null) {
        $file = get_hidden_file("ip.bin");
        if (!file_exists($file)) {
            return -4;
        }
        $fh = fopen($file, "rb");
        $sz = filesize($file);
        if ($sz != 25094960) { on_err(103, "invalid ip.bin size $sz", __FILE__, __LINE__); return -3;}
    }

    if (!$fh) {
        on_err(102, "unable to open $file", __FILE__, __LINE__);
        return -3;
    }

    $uni = ip4_in_list($fh, $ip_num, $sz, 8);
    // don't close $fh, PHP will do it for us on teardown
    return $uni;
}

/**
 * convert a city position from a ip4_to_uni -> uni_to_pos
 * @param int $pos the position offset in city database
 * @param array $short_names - mapping of codes to 2 char country names
 * @param array $long_names  - map of 2 char country codes to names
 * @return Loc_Info 
 */
function ip4_pos_to_loc(int $pos, array $long_names = [], string $file = "data/city.bin") : Loc_Info {
    static $fh = null;

    $loc = new Loc_Info();
    if ($pos < 0) {
        $loc->region = "n/a";
        $loc->city = "n/a";
        $loc->lat = 0.0;
        $loc->lng = 0.0;
        $loc->country = "n/a";
        $loc->iso = "NA";
        return $loc;
    }
    // open and jump to city record
    if ($fh == null) {
        $fh = fopen(WAF_ROOT . $file, "rb");
    }
    if (!$fh) { on_err(102, "unable to open $file", __FILE__, __LINE__); return -3; }

    fseek($fh, $pos);
    // read a block
    $data = fread($fh, 64);
    if (empty($data)) {
        $loc->region = "n/a";
        $loc->city = "n/a";
        $loc->lat = 0.0;
        $loc->lng = 0.0;
        $loc->country = "n/a";
        $loc->iso = "NA";
        return $loc;
    }
    $r = unpack("Ciso/vlat/vlng/a*citystate", $data);
    // split on null byte
    list($region, $city) = explode(',', at ($r['citystate'], chr(0), 0, 'na,na')); // split again on ,
    // map to location class
    $loc->region = $region;
    $loc->city = $city;
    $loc->lat = ($r['lat']-32768)/180;
    $loc->lng = ($r['lng']-32768)/180;
    $loc->iso = COUNTRY[$r['iso']];
    if (!empty($long_names)) {
        $loc->country = $long_names[$loc->iso]??"-";
    } else {
        $loc->country = $loc->iso;
    }

    return $loc;
}



class Request_Display {
    public bool $bot;
    public int $valid;
    public int $pos;
    public string $fingerprint;
    public string $signature;
    public string $ver;
    public string $ip;
    public string $param;
    public string $ref;
    public string $url;
    public string $ua;
    public string $os;
    public string $reason;
    public string $browser;
    public string $favicon;
    public Loc_Info $loc;
    public Whois_Info $whois;
    public string $method;
    public int $ctr404;
    public int $rr;
    public int $http_code;
    public int $block_code;
    public int $post_sz;
    public int $resp_sz;
    public int $time;
    public int $manual_mode;
    public int $classification;
    // public bool $fingerprint_ok;
    public string $human_time;
}


class Loc_Info {
    public string $country;
    public string $iso;
    public string $city;
    public string $region;
    public float $lat;
    public float $lng;
}


/**
 * hydrate unpacked log data into object data
 * @param array $data 
 * @return Request_Display 
 */
function hydrate_log(array $data) : Request_Display {

    static $short_names = [];
    static $long_names = [];

    if (empty($long_names)) {
        $long_names = json_decode(file_get_contents(WAF_ROOT."data/country_name.json"), true);
    }


    return hydrate_log_full($data, $short_names, $long_names);
}




function fix_enc(string $input) : string {

    if (function_exists('mb_detect_encoding')) {
        $encoding = mb_detect_encoding($input);
        if (!$encoding || $encoding == "1") { $encoding = null; }
        return mb_convert_encoding($input, "ASCII", $encoding);
    }
    // write a function to convert input to ascii if mb_detect_encoding doesn't exist
    $output = '';
    for ($i = 0, $m = strlen($input); $i < $m; $i++) {
        if (ord($input[$i]) < 128) {
            $output .= $input[$i];
        }
    }
    return $output;
}



function hydrate_log_full(array $data, array $long_names) : Request_Display {

    static $ip_loc_cache = [];
    static $agent_cache = [];
    static $methods = null;
    static $browser_list = null;

    if ($methods === null) {
        $methods = array_flip(METHODS);
    }
    if ($browser_list === null) {
        $browser_list = file(WAF_ROOT."data/browsers.txt", FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
    }
 
    $t = intval($data['time']);
    $h = "";
	if ($t > 1) {
		$diff = time() - $t;
        if ($diff < 60) {
            $h = "$diff sec ago";
        } else if ($diff < 3600) {
            $r = floor($diff / 60);
            $h = "$r min ago";
        } else if ($diff < 86400) {
            $r = floor($diff / 3600);
            $h = "$r hours ago";
        } else {
            $r = floor($diff / 86400);
            $h = "$r days ago";
        }
	}


    $display = new Request_Display();

    $display->classification = $data['class']??0;
    $display->bot = $data['flags'];
    $display->valid = $data['valid'];
    $ip = inet_ntop($data['ip']);
    if (!$ip) { $ip = 
        ord($data['ip'][0]??0).".".
        ord($data['ip'][1]??0).".".
        ord($data['ip'][2]??0).".".
        ord($data['ip'][3]??0); }
    $display->ip = $ip;
    if (!isset($ip_loc_cache[$ip])) {
        $uni = ip4_to_uni($ip);
        $ip_loc_cache[$ip] = ip4_pos_to_loc(ip4_uni_to_pos($uni), $long_names);
    }
    $display->loc = $ip_loc_cache[$ip];


    $parts = explode(chr(0), $data['str1']);
    $display->ua = fix_enc(ua_decompress($parts[0]??"none"));
    $display->url = fix_enc($parts[1]??"none");
    $display->reason = fix_enc($parts[3]??"none");
    $display->ref = fix_enc($parts[2]??"none");

    if (empty($display->ua)) {
        $display->ua = $parts[0];
    }
    $display->method = $methods[$data['method']]??'none';
    $display->ctr404 = $data['ctr_404'];
    $display->rr = $data['rr'];

    if (!isset($agent_cache[$display->ua])) {
        $agent_cache[$display->ua] = $agent = \BitFire\parse_agent($display->ua);
    } else {
        $agent = $agent_cache[$display->ua];
    }

    // UGLY AF, this needs to be in a function
    // skip bots that look like browsers...
    $crc32 = crc32($agent->trim);
    if (!in_array($crc32, [137575271])) {
        $bot_dir = get_hidden_file("bots");
        $info_file = "{$bot_dir}/{$crc32}.js";
        $bot_data = false;
        if (file_exists($info_file)) {
            $bot_data = json_decode(file_get_contents($info_file));
        }
        if (!empty($bot_data) && !empty($bot_data->name)) {
            $parts = preg_split("/[0-9\/\(]/", $bot_data->name);
            $display->favicon = $bot_data->icon;
            $agent->browser_name = trim($parts[0]);
            if (!empty($bot_data->domain)) {
                $display->reason .= ", Network auth: " . $bot_data->domain;
            }
            $display->manual_mode = $bot_data->manual_mode;
        }
    }

    $display->fingerprint = $data['fingerprint'];//base64_encode(pack("V", $data['fingerprint']>>32));
    //$display->signature = substr($data['signature'], 0, 10) . ' ' . substr($data['signature'], 10);//base64_encode(pack("V", $data['fingerprint']>>32));
    $display->signature = $data['signature'];
    // $display->fingerprint_ok = validate_header($agent->browser_name, $agent->fingerprint, FINGERPRINT_MAP2);
    $display->browser = (empty($agent->browser_name)) ? "unknown_bot" : $agent->browser_name;
    $display->ver = $agent->ver;
    $display->os = $agent->os;
    /*
    $matched = FINGERPRINT_IDENT[$data['fingerprint']]??null;
    if (!empty($matched)) {
        $display->browser = $matched;
        $display->ver = "ID";
        $display->os = "Linux";
    }
    */

    if (empty($display->favicon)) {
        if (!empty($display->browser) && in_array($display->browser, $browser_list)) {
            $display->favicon = "/wp-content/plugins/bitfire/public/browsers/" . $display->browser . ".webp";
        } else {
            $display->favicon = "/wp-content/plugins/bitfire/public/browsers/unknown_bot.webp";
        }
    }

    $display->http_code  = $data['http_code'];
    $display->block_code = $data['block_code'];
    $display->post_sz    = $data['post_len'];
    $display->resp_sz    = $data['out_len'];
    $display->human_time = $h;
    $display->time    = $data['time'];
    $display->reason .= classify($display);

    return $display;
}


const CLASSIFICATION = [
    "solr" => "Solr Hack Attempt",
    "autodiscover." => "MS Exchange Discovery",
    ".git/config" => "Git Secrets Download",
    "login" => "login attempt",
    "404" => "404 response check",
    "xdebug" => "developer hack attempt",
    "gateway/routes" => "Oracle Java Spring web scan",
    "sitemap.xml" => "Web Scanning",
    "hellothinkphp" => "Think PHP Exploitation attempt",
    "/owa" => "OutLook Web Access Scan",
    "/myadmin" => "phpMyAdmin Scan",
    "/pma" => "phpMyAdmin Scan",
    "/comsole" => "Console login",
    "/boaform" => "Router Exploit",
    "/hnap" => "Home Network Auth Protocol Router Bypass",
    "/geoserver/web" => "Java GeoWebCache Remote Code Auth",
    "wp-load.php?" => "WordPress Malware infection check",
    "wp-config.php" => "WordPress security config download attempt",
    "java.lang.runtime" => "log4j exploit attempt",
    "die(" => "PHP Injection exploit attempt",
    "action=register" => "User registration attempt",
    "wp-json/wp" => "WordPress JSON API access",
    "/.aws" => "AWS Credential Access",
    "/.ssh" => "SSH Key Access",
    "/id_rsa_" => "SSH Key Access",
    "/.env" => "Password Access",
    "xmlrpc.php" => "XMLRPC Login Attempt",
    "user.php?act=login" => "ECShop 3.x SQLi / RCE",
    ".pem" => "SSH Private Key Searching",
    "/.ssh/" => "SSH Private Key Searching",
];

const BAD_AGENTS = [
    "hello world" => "https://en.wikipedia.org/wiki/Mirai_(malware)",
    "hello, world" => "https://en.wikipedia.org/wiki/Mirai_(malware)",
    "googlebot" => "https://bitfire.co/malware/googlebot"
];


function classify(Request_Display $req) {

    $mapping = [
        10 => "Cross Site Scripting",
        11 => "XML Entity Attack",
        12 => "Windows File Injection",
        13 => "Known Vulnerable Script",
        14 => "SQL Injection",
        15 => "Linux File Injection",
        16 => "PHP Object Injection",
        17 => "Directory Traversal Attack",
        18 => "WebShell Access Attempt",
        21 => "PHP File Upload",
        22 => "Blocked IP/Agent",
        23 => "Trusted Bot Impersonation",
        24 => "Network Authentication Failed",
        25 => "Hacking Tool Detected",
        26 => "Rate Limited",
        27 => "Fake Browser Accessing Restricted Content",
        29 => "Attempt to Write PHP File Blocked",
        31 => "WordPress Restricted Function",
        32 => "DataBase Injection Attempt",
        33 => "Evil Nginx MITM Detected",
        34 => "WordPress Authentication Bypass",
        41 => "Plugin Enumeration Blocked",
        42 => "SSL Upgrade",
        43 => "Browser Verification Incorrect Answer",
        44 => "Browser Verification Failed"
    ];

    $scrape_libs = ["go-http", "python-", "pycurl", "curl", "wget", "guzzlehttp", "okhttp", "libwww-"];

    
    $info = "";
    if ($req->block_code > 0) {
        $map = floor($req->block_code / 1000);
        if (isset($mapping[$map])) {
            $info = ", " . $mapping[$map];
        }
    }

    if (empty($req->ua) || $req->ua == "none") {
        $info .= ", Empty User-Agent blocked";
    }

    if ($req->bot && strlen($req->url) < 3) {
        if (contains($req->browser, $scrape_libs) || $req->classification & 1) {
            $info .= ", common web-scrape";
        }
    }

    // handle invalid search engines
    if ($req->valid == 0) {
        foreach (BAD_AGENTS as $key => $link) {
            if (strstr($req->ua, $key)) {
                return "$info, $link";
            }
        }
    }

    $url = strtolower($req->url);
    if (preg_match("/[0-0a-f]{6}=\d{5}/", $url)) { return ", botnet infection searching"; }
    foreach (CLASSIFICATION as $signature => $sig) {
        if (is_string($signature) && stripos($url, $signature) !== false) { return "$info, $sig"; }
    }

    if ($req->classification & REQ_USER_LIST) {
        $info .= ", User Account Discovery";
    }


    return $info;
}

