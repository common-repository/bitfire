<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * 
 * to block:
 * bytespider AI image crawler - block!
 * mozilla/5.0 (compatible; bytespider; spider-feedback@bytedance.com) applewebkit/537.36 (khtml, like gecko) chrome/70.0.0.0 safari/537.36
 * - attack bot
 * bidtellect/0.0.1349.0
 * 
 * x-middleton:
 * amazonaws
 * 
 * review bots in the bot_info3 and add them to the DB...
 * add whois and host lookup to bot actions
 */

namespace BitFire;

use BitFire\BrowserState;
use ThreadFin\CacheItem;

use function BitFire\Data\ip4_pos_to_loc;
use function BitFire\Data\ip4_to_uni;
use function BitFire\Data\ip4_uni_to_pos;
use function BitFireBot\bot_authenticate;
use function BitFireBot\is_automattic;
use function BitFireBot\is_bing;
use function BitFireBot\is_cloud_flair;
use function BitFireBot\is_google_ip;
use function BitFireBot\validate_header;
use function BitFireSvr\update_common_params;
use function BitFire\Pure\ip_in_cidr_list;
use function BitFireSvr\update_ini_value;
use function ThreadFin\cidr_match;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\at;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\get_hidden_file;
use function ThreadFin\http\http2;
use function ThreadFin\icontains;
use function ThreadFin\ƒ_id;
use function ThreadFin\ƒ_inc;
use function ThreadFin\partial as ƒixl;
use function ThreadFin\random_str;
use function ThreadFin\starts_with;
use function ThreadFin\un_json;
use function ThreadFin\validate_raw;
use const ThreadFin\ENCODE_RAW;

use BitFire\Config as CFG;
use Random\RandomException;
use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\Entity;
use ThreadFin\FileData;
use ThreadFin\Hash_Config;
use ThreadFin\packable;

use const BitFire\Data\APPS;
use const BitFire\Data\BOT_WORDS;
use const BitFire\Data\BROWSER_LIST;
use const BitFire\Data\browser_list;
use const BitFire\Data\BROWSER_MAP;
use const BitFire\Data\BROWSER_WORDS;
use const BitFire\Data\COMMON_WORDS;
use const BitFire\Data\FINGERPRINT_MAP;
use const BitFire\Data\LIB_LIST;
use const BitFire\Data\OS_MAP;
use const ThreadFin\DAY;
use const ThreadFin\HOUR;
use const BitFire\IP_GOOG_MS_AUTO;
use const BitFire\IP_GOOGLE;
use const BitFire\IP_MICROSOFT;
use const BitFire\IP_AUTOMATTIC;

const MAX_HOST_HEADER_LEN = 80;
const UA_NO_MATCH = -1;
const UA_NET_FAIL = 0;
const UA_NET_MATCH = 1;

const BOT_ALLOW_ANY = 2;
const BOT_ALLOW_NONE = 1;
const BOT_ALLOW_NET = 8;
const BOT_ALLOW_AUTH = 16;
const BOT_ALLOW_OPEN = 32;
const BOT_ALLOW_DOMAIN = 64;
const BOT_ALLOW_RESTRICT = 256;
const BOT_VERIFY = 128;

const BOT_VALID_RESTRICTED = -2;
const BOT_VALID_INVALID = -1; // restricted bot
const BOT_VALID_SEND = 0;
const BOT_VALID_JS = 2;
const BOT_VALID_FINGERPRINT = 3;
const BOT_VALID_NET = 4; // net == ip?
const BOT_VALID_OPEN = 5;
const BOT_VALID_IP = 6;
const BOT_VALID_AGENT = 7; // agent == open?




class Abuse {
    public int $number = 0;
    public int $score = -1;
    public int $isp_id = 0;
    public string $isp = '';
    public bool $tor = false;
    public bool $proxy = false;
    public string $domain = "";
    public $reporters = 0;

    // convert the abuse value to a 32bit int (exclude domain strings)
    public function to_int() : int {
        $value = ($this->score & 0xFF);
        $value += ($this->tor & 0x1) << 8;
        $value += ($this->proxy & 0x1) << 9;
        $value += ($this->isp_id & 0xFFFF) << 16;

        return $value;
    } 

    // convert a 32bit int to an abuse object (exclude domain strings)
    public static function from_int(int $value) : Abuse {
        $abuse = new Abuse();
        $abuse->score = $value & 0xFF;
        $abuse->tor = ($value >> 8) & 0x1;
        $abuse->proxy = ($value >> 9) & 0x1;
        $abuse->isp_id = ($value >> 16) & 0xFFFF;

        return $abuse;
    }
}

class IP_Info {
    // the ip classification
    public int $cls;
    // the ip domain
    public string $dom;
    // the city
    public string $cty;
    // the country
    public string $cou;
    // the ISP Id
    public int $isp;
    // the abuse score
    public int $abu;
    // the ip class
    public int $ipc;
}



class UserAgent
{
    public string $os = "bot";
    public string $agent_text = "";
    public string $browser_name = "";
    public string $ver = "0";
    public bool $bot = false;
    public string $trim = "";
    public int $crc32 = 0;
    public int $browser_id = 0;
    public int $valid = 0;
    public bool $matched = false;
    public bool $inspect = false;
    public int $fingerprint = 0;
    public string $signature = '';

    public function __construct(string $os, string $agent_text, string $ver, bool $bot)
    {
        $this->os = $os;
        $this->agent_text = $agent_text;
        $this->ver = $ver;
        $this->bot = $bot;
    }

    function os_as_int() : int {
        return OS_MAP[$this->os]??0;
    }

    // convert the string representation of the version number to a sortable int
    function version_as_int(): int {
        $parts = explode('.', $this->ver); // split the string into an array of version parts
        $major = intval($parts[0]??"0");
        $minor = intval($parts[1]??"0");
        return (int) ($major * 1000) + (int) $minor;
   }

    public static function int_as_version(int $ver) : string  {
        $major = (int) ($ver / 1000);
        $minor = $ver % 1000;
        return "$major.$minor";
    }
}


/**
 * @param string $haystack 
 * @param array $needles 
 * @return string - the first needle found in the haystack (case sensitive)
 */
function which(string $haystack, array $needles) : string {
    foreach ($needles as $n) {
        $p = strpos($haystack, $n);
        if ($p !== false) {
            return $n;
        }
    }
    return '';
}
        

/**
 * this function takes a useragent and turns it into an array with os, browser, bot and ver
 * return array('os', 'browser', 'ver', 'bot':bool)
 * return UserAgent
 * @test test_bot.php test_parse_agent
 * test: mozilla/4.5 (compatible; httrack 3.0x; windows 98)
 * test: mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36,gzip(gfe)
 * 
 * should return browser:
 * test: mozilla/5.0 (x11; cros aarch64 14989.107.0) applewebkit/537.36 (khtml, like gecko) chrome/105.0.0.0 safari/537.36
 * 
 * 
 * TODO: make sure bots cant be common words...
 * PURE!
 */
function parse_agent(string $user_agent, string $encoding = "gzip, deflate, br", bool $check_blacklist = false): UserAgent {
    $user_agent = strtolower($user_agent);
    $backup_bot = (bool)strpos($user_agent, "mozilla/5.0") === false;
    // maintain a list of name to version strings so after we figure out
    // which agent this is, we can lookup the agent version
    $link = $email = $backup_name = "";

    // google appends this string to the end of the user agent, remove it
    $user_agent = str_replace(",gzip(gfe)", "", $user_agent);

    // remove anything that is not alpha
    $agent = new UserAgent('bot', $user_agent, "", $backup_bot);
    $agent_min1 = preg_replace("/[^a-z\s]/", " ", strtolower(trim($user_agent)));

    // remove short words, this will also remove language and locale info 
    $agent_min2 = preg_replace("/\s+/", " ", preg_replace("/\s[a-z]{1,3}\s([a-z]{1-3}\s)?/", " ", $agent_min1));
    $agent->trim = substr($agent_min2, 0, 250);
    $agent->crc32 = crc32($agent_min2);

    $user_agent = trim($user_agent, "; ");
    // remove country and locale
    $user_agent = preg_replace("/[ ;][a-z][a-z]\-[a-z][a-z][; )]/i", " ", $user_agent);

    // find the OS type, and possibly the bot type (some bot names are stored in the OS info)
    if (preg_match_all("/[\(,;]([^\(,;\)]+)\)/", $user_agent, $matches, PREG_PATTERN_ORDER)) {
        /** @var array $list */
        $list = $matches[1];

        /** @var string $info */
        $tail = array_shift($list);
        $agent->os = which($agent->trim, array_keys(OS_MAP));

        // android has lots of junk here so, don't pull the UA from here
        if ($agent->os != "android") {
            while (!empty($tail)) {

                $text = trim(preg_replace("/[^a-zA-Z\s_-]/", "", $tail));
                $tail = array_pop($list);

                if (!isset(COMMON_WORDS[$text]) && strpos($text, "like mac") == false) {
                    if (strpos($text, 'os x') !== false) {
                        continue;
                    }
                    $backup_name = trim($text, " ();");//"$text ";
                    $backup_bot = true;
                }
            }
        }
    }

    // we found the bot in the OS info!
    if (!empty($backup_name) && isset(LIB_LIST[$backup_name])) {
        $agent->bot = true;
        $agent->matched = true;
        $agent->browser_name = $backup_name;
    }


    $browser_id = 0;
    if (preg_match_all("/([^\/\s\)\(]+)\/([^\s;,]+)/", $user_agent, $matches, PREG_PATTERN_ORDER)) {
        for($i=0,$m=count($matches[0]);$i<$m;$i++) {

            $name = $matches[1][$i];
            $ver = $matches[2][$i];


            // some browsers are of the type: mozilla/unique_name/version, or: unique_name/mozilla/version
            // we inspect all combinations of the key/values looking for a hit and build up the fingerprint
            if (strpos($ver, '/') !== false) {
                if (strpos($name, 'http') !== false) {
                    $agent->bot = $backup_bot = true;
                    continue;
                }
                // mozilla is in name, so the name is the version
                if (strpos($name, 'mozilla') !== false) {
                    $name = at($ver, '/', 0);
                }
                // mozilla is in version, get version from the end of the string
                else if (strpos($ver, 'mozilla') !== false) {
                    $ver = at($ver, '/', 1);
                }
            }

            $browser_id = 0;

            if (isset(BROWSER_LIST[$name])) {
                $browser_id = BROWSER_LIST[$name];
                $backup_bot = false;
            }
            // check if it is a bot that we know
            else if (isset(LIB_LIST[$name])) {
                $browser_id = LIB_LIST[$name];
                $backup_bot = true;
            }
            // no match, need to leave this here so we can BROWSER_LIST match a few common words
            // maybe break common words up into common1 and 2?
            else if (! isset(COMMON_WORDS[$name])) {
                // handle special case for mac that has lots of OS info here....
                $backup_name = $name;
                $agent->ver = $ver;
            }

            // exact match...
            if ($browser_id > 0 && $browser_id < 254) {
                $agent->browser_name = $name;
                $agent->ver = $ver;
                $agent->bot = $backup_bot;
                $agent->browser_id = $browser_id;
                $agent->matched = true;
                break;
            }

            $agent->browser_id += $browser_id;
        }
    }


    // if we don't have an EXACT match, check the blacklist. a little expensive so don't do it for the most common cases
    if ($check_blacklist && !$agent->matched) {
        if (Config::enabled('blacklist_enable')) {
            $agent->inspect = true;
        }
    }

    // special case for weird "app clients" that look like bots...
    if ($agent->bot) {
        $app = which($agent->agent_text, APPS);
        if (!empty($app)) {
            $agent->bot = false;
            $agent->browser_name = $app;
            $agent->matched = true;
        }
    }

    if (!$agent->matched) {
        // an actual browser found somewhere in the agent
        if (isset(BROWSER_LIST[$agent->browser_name])) {
            $agent->bot = false;
        }
        else if (empty($agent->browser_name) && empty($backup_name) && isset(BROWSER_MAP[$agent->browser_id])) {
            $agent->browser_name = BROWSER_MAP[$agent->browser_id];
            $test = ($agent->browser_name == "edge") ? "edg" : $agent->browser_name;
            if (preg_match("/{$test}\/(\d+\.?\d*)/", $user_agent, $matches)) {
                $agent->ver = $matches[1];
            }
            $agent->matched = true;
            $agent->bot = false;
        }
    }
    
    // early bail out if we already matched the user agent
    if ($agent->matched) {
        return $agent;
    }

    // we still don't know the name, grab the backup name (url)...
    $agent->browser_name = (empty($agent->browser_name)) ? $backup_name : $agent->browser_name;

    // search for bots, if we don't think we have a bot...
    if (!$agent->bot) {
        $bot_type = which($agent->agent_text, BOT_WORDS);
        // fb and instagram mess up the UA, so hard code a fix here...
        if ($agent->os == "iphone" || $agent->os == "android") {
            $agent->bot = !empty($bot_type);
            $agent->matched = true;
        }
    }

    // facebook and instagram user agents
    if (contains($user_agent, ["instagram", "fbsn", "fbav"]) && !contains($user_agent, "facebookexternalhit")) {
        $agent->browser_name = contains($user_agent, "instagram") ? "instagram" : "facebook";
        $agent->bot = false;
        $agent->matched = true;
        return $agent;
    }

    // special case for ios text messages reporting they are facebook and twitter bots SMH
    else if ($agent->browser_name == "facebookexternalhit" && contains($agent->agent_text, "twitterbot")) {
        $agent->browser_id = 194;
        $agent->browser_name = "ios_text_message";
        $agent->bot = false;
        $agent->matched = true;
    }

 
    if (!$agent->matched && empty($agent->browser_name)) {
        
        // look for a url
        if (preg_match("/\+?(https?:\/\/[^\s;,:]+)/", $user_agent, $matches)) {
            $agent->browser_name = $matches[1];
            $agent->bot = true;
            if (contains($user_agent, 'wordpress.com')) {
                $agent->browser_name = 'wordpress.com';
            }
        }
        // or an email addresses
        else if (preg_match("/([\w\._-]+\@[a-z0-9-_\.]+)/", $user_agent, $matches)) {
            $agent->browser_name = $matches[1];
            $agent->bot = true;
        }
        // last ditch effort
        else {
            if (!empty($bot_type)) {
                $agent->bot = true;
                if (empty($agent->browser_name)) {
                    $agent->browser_name = $bot_type;
                }
            } else {
                $type = which($agent->agent_text, BROWSER_WORDS);
                if (!empty($type)) {
                    $agent->bot = false;
                    if (empty($agent->browser_name)) {
                        $agent->browser_name = $type;
                    }
                }
            }
        }
    }

    // handle SHORT android agents
    if (!$agent->matched && $agent->browser_id == 0 && strlen($agent->agent_text) < 32 && strstr($agent->agent_text, "android") !== false) {
        $agent->browser_name = "android";
        $agent->bot = false;
    }

    $agent->browser_name = trim($agent->browser_name, " +()");

    // if the browser does not accept gzip, it is a bot, interestingly we hit this case for JavaScript verified browsers on CB.
    // requires further investigation
    /*
    if (in_array($agent->browser_name, ["chrome", "firefox", "safari", "opera", "edge", "brave"]) && !contains($encoding, "gzip")) {
        $agent->bot = true;
        $agent->browser_name = "Fake " . $agent->browser_name;
    }
    */

    return $agent;
}



class JS_Fn
{
    public $js_code;
    public $fn_name;
    public function __construct($code, $name)
    {
        $this->js_code = $code;
        $this->fn_name = $name;
    }
}


/**
 * server side data about an IP
 * @package BitFire
 */
class IPData implements packable
{

    public $rr;
    public $rr_time;
    public $ctr_403 = 0;
    public $ctr_404 = 0;
    public $ctr_500 = 0;
    public $browser_state = 0;
    public $browser_id = 0;
    public $browser_name = '';
    // the ip4_to_uni location value (4 quick lookup of geo data in city.bin)
    public $loc_pos = 0;
    public $iso = '';
    public $ip = 0;
    public $valid = 0;
    public $update_time = 0;
    public $crc32 = 0;

    public $domain = '';
    /** @var int $ip_classification - IP_constants, not request classification */
    public $ip_classification = 0;
    public $request_class = 0;

    // each time an IP uses a new bot user-agent, we add it to the list.
    // if the list grows beyond 3, we block the IP.
    public $bot_file_list = [];

    // pack is 115 bytes - 128byte compatible
    const pack_str = P16 . P32 . P16 . P16 . P16
        . P16 . P32 . PA32 . P8 
        . P32 . PA32 . P16 . P16 . P32 . P32
        . P32 . P32 . P32 . P32 . P32;

    const unpack_str = P16 . 'rr/' . P32 . 'rr_time/' . P16 . 'ctr_404/' . P16 . 'ctr_500/'
        . P16 . 'ctr_403/' . P16 . 'browser_state/' . P32 . 'browser_id/' . 'A32browser_name/'
        . P8 . 'valid/' . P32 . 'loc_pos/' . 'A2iso/' . PA32 . 'domain/' . P16 . 'ip_classification/'
        . P16 . 'request_class/' . P32 . 'update_time/' . P32 . 'crc32/'
        . P32 . 'agent1/' . P32 . 'agent2/' . P32 . 'agent3/' . P32 . 'agent4/' . P32 . 'agent5';

    public function __construct()
    {
    }

    public static function __set_state(array $properties) : IPData
    {
        $ip = new IPData();
        for ($i = 0; $i < 5; $i++) {
            $key = 'agent' . ($i + 1);
            if (isset($properties[$key])) {
                $ip->bot_file_list[] = $properties[$key]??'';
                unset($properties[$key]);
            }
        }
        foreach ($properties as $key => $value) {
            $ip->$key = $value;
        }
        return $ip;
    }

    public function pack(int $request_class = 0) : string {
        $p = pack(self::pack_str, $this->rr, $this->rr_time, $this->ctr_404, $this->ctr_500, $this->ctr_403,
            $this->browser_state, $this->browser_id, $this->browser_name, $this->valid,
            $this->loc_pos, $this->domain, $this->ip_classification, $this->request_class, time(), crc32($this->ip),
            $this->bot_file_list[0]??0, $this->bot_file_list[1]??0,
            $this->bot_file_list[2]??0, $this->bot_file_list[3]??0,
            $this->bot_file_list[4]??0);
        return $p;
    }

    public static function unpack(string $data)  {
        //$len = strlen($data);
        //debug("unpack ipdata len [$len]");
        $properties = unpack(self::unpack_str, $data);
        return self::__set_state($properties);
    }

    // verify this IP is the same as the one passed in
    public function verify(string $ip, string $browser_name) : bool {
        $crc = crc32($ip);
        if ($this->crc32 == $crc && $this->browser_name == substr($browser_name, 32)) {
            return true;
        }
        return false;
    }

}

 


class BotSimpleInfo extends Entity
{
    public bool $valid = false;
    public string $agent_trim = "";
    public string $net = "";
    public string $domain = "";
    public string $home_page;
    public string $agent;
    public string $category;
    public string $icon = "";
    public string $favicon = "";
    public string $vendor = "";
    public string $class_id;
    public string $name = "";
    public $abuse;
    public $configured = false;
    public $id = '';

    // manual bot editing mode
    public int $manual_mode = BOT_ALLOW_RESTRICT;
    // TRIM user agent hash
    public int $crc32 = 0;
    // counter bot auth pass
    public int $hit = 0;
    // counter bot auth miss
    public int $miss = 0;
    // counter for 404 pages
    public int $not_found = 0;
    // creation time
    public int $mtime = 0;
    public int $ctime = 0;
    // creation time
    public int $classification = 0;
    // list of last bot ips 
    public array $ips = [];
    // classification string
    public string $class;
    public $ip;

    public function __construct($agent = "")
    {
        $this->agent = $agent;
    }

    public function path() : string {
        return get_hidden_file('bots/' . $this->id . 'js');
    }
}


/**
 * update the IPData counters (rr, 404, 500)
 * @param IPData $ip_data 
 * @param int $http_code 
 * @return IPData 
 */
function update_ip_data(IPData $ip_data, int $http_code, int $agent_crc32, int $block_code, int $req_class) : IPData {

    $t = time();
    if ($t > $ip_data->rr_time) {
        trace("IP_CTR_RST");
        $ip_data->rr = $ip_data->ctr_404 = $ip_data->ctr_500 = 0;
        $ip_data->rr_time = $t + (60 * 5);
    }
    $ip_data->rr += 1;

    // update counters...
    $http_class = floor($http_code / 100) * 100;
    if ($block_code > 0) {
        $ip_data->ctr_403 += 1;
    } else if ($http_code == 404) {
        $ip_data->ctr_404 += 1;
    } else if ($http_class == 500) {
        $ip_data->ctr_500 += 1;
    }

    // add the agent to the list of agents
    if (!in_array($agent_crc32, $ip_data->bot_file_list)) {
        trace("ADD_AGENT");
        $ip_data->bot_file_list[] = $agent_crc32;
    }
    // update request class
    $ip_data->request_class = $req_class;
    $ip_data->update_time = $t;

    return $ip_data;
}



/**
 * create a new ip_data local cache entry
 * @param string $remote_addr - ip address 
 * @param UserAgent $agent - the parsed useragent info
 * @param int $state - browser state bit-mask, | of BrowserState:: options
 * @return IPData 
 */
function new_ip_data(string $remote_addr, UserAgent $agent, int $state = 0): IPData
{
    $s1 = hrtime(true);

    $ip_data                = new IPData();
    $ip_data->domain        = '';
    $ip_data->ip            = $remote_addr;
    $ip_data->browser_id    = $agent->browser_id;
    $ip_data->browser_name  = $agent->browser_name;
    $ip_data->browser_state = $state;
    $ip_data->rr            = 0;
    $ip_data->rr_time       = time() + (60 * 5); // 5 minutes
    $ip_data->bot_file_list[] = $agent->crc32;

    // lets get some IP info (but we wont do this if the cache is disabled)
    $ip_data->ip_classification |= is_google_ip($remote_addr) ? IP_GOOGLE : 0;
    $ip_data->ip_classification |= is_bing($remote_addr) ? IP_MICROSOFT : 0;
    $ip_data->ip_classification |= is_automattic($remote_addr) ? IP_AUTOMATTIC : 0;

    if (ip_in_cidr_list($remote_addr, ['10.0.0.0' => 8, '172.16.0.0' => 12, '192.168.0.0' => 16])) {
        $ip_data->ip_classification |= IP_INTERNAL;
    }

    $ip_data->ip_classification |= is_cloud_flair($remote_addr) ? IP_CLOUD_FLAIR : 0;

    if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) || 
        isset($_SERVER['HTTP_VIA']) || 
        isset($_SERVER['HTTP_FORWARDED']) || 
        isset($_SERVER['HTTP_X_PROXY_CONNECTION']) || 
        isset($_SERVER['HTTP_X_REAL_IP'])) {
        $ip_data->ip_classification |= IP_PROXY;
    }

    $ip_data->ip_classification |= IP_INSPECTED;
 
    // location lookup
    if (! ($ip_data->ip_classification & IP_INTERNAL)) {
        $off = ip4_to_uni($remote_addr);
        $loc = ip4_pos_to_loc(ip4_uni_to_pos($off));
    
        $ip_data->loc_pos = $off;
        $ip_data->iso = $loc->iso;
    }

    $s2 = (hrtime(true) - $s1) / 1e+6;
    trace("new_ip[$s2]");

    return $ip_data;
}



/**
 * return true if $addr is valid ipv6 address
 */
function is_ipv6(string $addr): bool
{
    return !empty(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));
}




/**
 */
class BotFilter
{

    public function __construct() { }


    /**
     * inspect the UA, determine human or bot
     * perform human validation, bot white/black listing
     */
    public function inspect(\BitFire\Request $request, UserAgent $agent) : UserAgent
    {
        $ins = BitFire::get_instance();

        // handle wp-cron and other self requested pages
        if (\BitFireBot\is_local_request($request)) {
            $agent->valid = BOT_VALID_IP;
            return $agent;
        }


        // ignore urls that receive consistent bot access that may be difficult to identify
        $ignored = CFG::arr("ignore_bot_urls");
        if ($request->method == "POST" && \ThreadFin\starts_with($request->path, "/ws/")) { return $agent; }
        if (!empty($ignored) && in_array($request->path, $ignored)) {
            return $agent;
        }

        // store the fingerprint status if it is updated
        // TODO: add fingerprint and signature maps
        // $cookie->valid_print = $cookie->valid_print ?: validate_header($agent->browser_name, $agent->fingerprint, FINGERPRINT_MAP);
        $ip_data = $ins->ip_data;

        // rewrite wordpress and jetpack user-agents.
        // TODO: get list of the actual uas and update default list
        if (contains($agent->browser_name, ["wordpress.com", "wordpress"])) {
            $agent->trim = "mozilla compatible wordpress https wordpress ";
        } else if (contains($agent->browser_name, "jetpack")) {
            $agent->trim = "mozilla compatible jetpack https jetpack ";
        }



        // this case can happen when a valid browser comes in on url that looks restricted to the classifier
        // this will update server side IP_Data and set a verified cookie.
        // TODO: sync this code with verify.php
        if (isset($request->get['_bfa']) || isset($request->post['_bfa'])) {
            $answer = $request->get['_bfa']??$request->post['_bfa']??'';
            $effect = verify_browser_effect($answer, $agent, $request->ip);
            unset($_GET['_cache_break']);

            if ($effect->read_status() == STATUS_OK) {
                // set cookie
                $effect->cookie('1', 'verified_state');

                $learning = (CFG::int('dynamic_exceptions') > time());
                unset($_GET['_bfa']);
                require_once WAF_ROOT . 'src/server.php';
                update_common_params($_GET, $request->ip, $learning);

                if (!empty($request->post_raw)) {
                    $post = @json_decode($request->post_raw);
                    if ($post !== false) {
                        $_GET = un_json($request->post['_bfg']??"");
                        $_POST = un_json($request->post['_bfp']??"");
                        $_SERVER['REQUEST_METHOD'] = $request->post['_bfm']??"GET";
                    }
                }
            }
            $effect->run();

            return $agent;
        }




        // if we are not going to BLOCK this request, AND the server side ip data is valid, don't do any actual tests
        $effect = Effect::new()->status($ip_data->valid);

        // handle un-validated bots
        if ($agent->bot) {
            $effect = (CFG::enabled("whitelist_enable"))
                ? bot_authenticate($agent, $request, $ip_data)
                : Effect::new()->status(BOT_VALID_OPEN);
        }
        // handle un-validated users
        else {
            if (CFG::enabled(CONFIG_REQUIRE_BROWSER) && $request->classification & REQ_RESTRICTED) {
                $effect = block_now(FAIL_RESTRICTED, "user_agent", $request->agent, $request->path, 0);
            }
        }

        // update the sever validation status, 99 is blocked, < 0 is auth fail, or bot blocked
        $status = $effect->read_status();
        // if status is block or restricted, then we set valid to 0
        $ip_data->valid = ($status == 99 || $status < 1) ? 0 : $ip_data->valid;

        // update the latest ip_data
        $ins->ip_data = $ip_data;

        // there is a race-condition here between when the data was loaded and now updated, it might have changed
        // hesitant to lock here, but it might be necessary
        //CacheStorage::get_instance()->save_data("IP_" . $request->ip, $ins->ip_data, HOUR);

        // execute the effect!
        $effect->run();

        return $agent;
    }
}



/**
 * verifies the response matches the expected bot verification code
 * updates server cache for IP_Data and updates the cookie in returned effect
 * @test test_verify_browser
 * PURE! 
 */
function verify_browser_effect(string $bfa, UserAgent $agent, string $ip): Effect
{
    $effect = Effect::new();

    // server side answer

    // browser submitted answer
    $parts = explode('.', $bfa);
    if (count($parts) != 3) {
        trace("VR/FY/MAL");
        return $effect;
    }
    $config = new Hash_Config('sha256', 86400 * 7, 24);
    $pass = validate_raw($parts[0]??'', $parts[1]??'', $parts[2]??'', CFG::str("secret"), $config);
    trace("VR/FY/$pass");

    // increase metric counter for verify success/ failure
    $key_id = 256 + ((($pass) ? FAIL_ANSWER_VERIFY : FAIL_ANSWER_MISS) / 1000);
    $effect->status(($pass) ? STATUS_OK : STATUS_FAIL)
        // update the ip_data valid state for 60 minutes, TODO: make this real func, not anon-func
        ->update(new CacheItem(
            'IP_' . $ip,
            function (IPData $ip_data) use ($pass) {
                $ip_data->valid |= ($pass) ? BOT_VALID_JS : 0;
                $ip_data->browser_state |= ($pass) ? BrowserState::JS | BrowserState::VERIFIED : 0;
                return $ip_data;
            },
            ƒixl('\BitFire\new_ip_data', $ip, $agent, ($pass) ? BrowserState::JS | BrowserState::VERIFIED : 0),
            HOUR, CACHE_LOW | CACHE_STALE_OK
        ))
        ->update(new CacheItem("STAT_$key_id", ƒ_inc(1), ƒ_id(0), DAY * 7, CACHE_HIGH));

    return $effect;
}

namespace BitFireBot;

use BitFire\Abuse;
use BitFire\BitFire;
use BitFire\BotSimpleInfo;
use BitFire\BrowserState;
use BitFire\Config;
use BitFire\Config as CFG;
use BitFire\IPData;
use BitFire\JS_Fn;
use BitFire\Request;
use BitFire\UserAgent;
use Random\RandomException;
use ThreadFin\CacheItem;
use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\Hash_Config;

use function BitFire\block_now;
use function BitFire\is_ipv6;
use function BitFire\new_ip_data;
use function BitFire\Pure\ip_in_cidr_list;
use function ThreadFin\array_shuffle;
use function ThreadFin\cache_prevent;
use function ThreadFin\cidr_match;
use function ThreadFin\contains;
use function ThreadFin\cookie;
use function ThreadFin\dbg;
use function ThreadFin\ends_with;
use function ThreadFin\debug;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\icontains;
use function ThreadFin\ƒ_id;
use function ThreadFin\ƒ_inc;
use function ThreadFin\map_map_value;
use function ThreadFin\map_to_object;
use function ThreadFin\random_str;
use function ThreadFin\starts_with;
use function ThreadFin\trace;

use const BitFire\BITFIRE_VER;
use const BitFire\BOT_ALLOW_ANY;
use const BitFire\BOT_ALLOW_AUTH;
use const BitFire\BOT_ALLOW_DOMAIN;
use const BitFire\BOT_ALLOW_NET;
use const BitFire\BOT_ALLOW_NONE;
use const BitFire\BOT_ALLOW_OPEN;
use const BitFire\BOT_ALLOW_RESTRICT;
use const BitFire\BOT_VALID_AGENT;
use const BitFire\BOT_VALID_INVALID;
use const BitFire\BOT_VALID_IP;
use const BitFire\BOT_VALID_NET;
use const BitFire\BOT_VALID_OPEN;
use const BitFire\BOT_VALID_RESTRICTED;
use const BitFire\BOTS;
use const BitFire\CACHE_HIGH;
use const BitFire\Data\FAST_BOTS;
use const BitFire\FAIL_BLOCKED_AGENT;
use const BitFire\FAIL_BLOCKED_IP;
use const BitFire\FAIL_MISS_WHITELIST;
use const BitFire\REQ_BLOCKED;
use const BitFire\REQ_EVIL;
use const BitFire\REQ_RESTRICTED;
use const BitFire\WAF_ROOT;
use const ThreadFin\DAY;


/**
 * return true if the request is from the local server
 * @pure
 */
function is_local_request(Request $request): bool {

    if (ends_with($request->path, 'wp-cron.php')) {
        return true;
    }
    if (cidr_match($request->ip, $_SERVER['SERVER_ADDR']??'0.0.0.0', 24)) {
        return true;
    }
    if (php_sapi_name() == "cli") {
        return true;
    }
    // private IP? must be local request
    if (!filter_var($request->ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return true;
    }

    return false;
}



/**
 * create obfuscated JavaScript for $number
 * @test test_bot.php test_js_int_obfuscate
 */
function js_map_obfuscate(string $orig): JS_Fn
{
    // convert ascii printable character range (32-126) to actual char values, shuffle the result array and turn into string
    $z = join('', array_shuffle(array_map(function ($x) {
        return chr($x);
    }, range(32, 126))));

    // integer to string, set dictionary name, function name, 
    $dict_name = 'z' . random_str(3);
    $fn_name = 'x' . random_str(3);

    $data = str_split($orig);

    $mapped = array_map(function ($x) use ($dict_name, $z) {
        $idx = strpos($z, $x);
        return "$dict_name\[$idx\]";
    }, $data);
    $code = join(' + ', $mapped);

    // the actual js function
    //$js_code = sprintf("function %s(){let %s='%s';return %s;}", $fn_name, $dict_name, addslashes($z), $code);
    $js_code = sprintf("function %s(){let %s='%s';return %s;}", $fn_name, $dict_name, addslashes($orig), $dict_name);
    return new JS_Fn($js_code, $fn_name);
}


/**
 * make the html javascript challenge
 * PURE!
 */
function make_js_script(Request $request, string $path_to_verify, bool $use_xhr = false): string
{
    $config = new Hash_Config('sha256', 86400 * 7, 24);
    // use the same timestamp for up to 2 hours.  this will allow server caches to cache the js for 2 hours
    $time = floor(time() / 7200) * 7200;
    $code = \ThreadFin\make_code(CFG::str('secret'), $config, $time);
    $fn   = js_map_obfuscate($code);
    $js   = $fn->js_code . "\n";

    if ($use_xhr == true && $request->method == "GET") {
        $js .= "if (! document.cookie.includes('_bitf')) {\n";
        $js .= "    console.log('b3');\n";
        $js .= '    let zzz = {"_fn":"xhr","_bfa":' . $fn->fn_name . '(),"_bfg":\'' . json_encode($_GET) . '\',"_bfp":\'' . json_encode($_POST) . '\',"_bfm":"' . urlencode($request->method) . '","_bfx":"n","_bfxa":"on","_gen":"' . date('H:i:s') . "\"};\n";
        $js .= '    let params = {"method":"POST","mode":"same-origin","credentials":"same-origin","redirect":"follow","body":JSON.stringify(zzz)};' . "\n";
        $js .= '    console.log("BFF"); fetch("'.rtrim($path_to_verify, '/').'", params); }';
    }
    else {
        $js .= "if (true) {\n";
        $js .= "\tconsole.log('b2');\n";
        $js .= "\tvar url = new URL(window.location.href);\n";
        $js .= "\turl.searchParams.delete('_cache_break');\n";
        $js .= "\turl.searchParams.set('_bfa', ".$fn->fn_name."());\n";
        $js .= "\twindow.setTimeout(function() { window.location.href = url }, 150); }\nelse { console.log('bfv2'); }\n";
    }

    return $js;
}


/**
 * send the browser verification challenge
 * @test test_bot.php send_test_browser_verification
 * PURE-ish, required Config! 
 * @param bool $document_wrap - if true, wrap the challenge in an HTML document
 * NOTE: be sure to keep the effect up to date with bitfire-plugin
 */
function send_browser_verification(Request $request, UserAgent $agent, bool $document_wrap = true, bool $use_xhr = true): Effect
{
    if (!defined("\BitFire\DOCUMENT_WRAP")) {
        $document_wrap = false;
        $use_xhr = true;
    }

    // create an effect to send JS challenge
    $effect = Effect::new()->status(1);


    // allow/block browsers by IP or user-agent
    $allowed = FileData::new(get_hidden_file("browser_allow.json"))->read()->un_json();
    $action = $allowed->lines['ip'][$request->ip]??-1;
    // if the ip is blocked, block it
    if ($action >= 0) {
        debug("browser ip match %d", $action);
        return ($action == 0) ? block_now(FAIL_BLOCKED_IP, "IP Address", (string)$request->ip, "IP Address is blocked") : $effect->status(BOT_VALID_IP);
    }
    $action = $allowed->lines['agent'][$request->agent]??-1;
    // if the agent is blocked, block it
    if ($action >= 0) {
        debug("browser agent match %d", $action);
        return ($action == 0) ? block_now(FAIL_BLOCKED_AGENT, "User Agent", (string)$request->agent, "User Agent is blocked") : $effect->status(BOT_VALID_AGENT);
    }


    $content_url = rtrim(CFG::str('cms_content_url', '/wp-content'), '/');
    $script      = make_js_script($request, $content_url . '/plugins/bitfire/verify.php', $use_xhr);
    $html        = "";
    // build the page to block bots
    if ($document_wrap) {
        BitFire::get_instance()->reason = "browser verification forced";
        // build the challenge
        // find the correct html file to use
        $html_src = (file_exists(WAF_ROOT . "views/".CFG::str("verify_css", "blank").".html")) ? CFG::str("verify_css", "blank") : "cloudflair_light";
        // read the html source
        $document = FileData::new(WAF_ROOT . "views/".$html_src.".html")->raw();

        cookie('_bitf', '0', -DAY * 30);

        $html = str_replace("__JS__", $script, $document);
        $html = str_replace("__FINGERPRINT__", $agent->fingerprint, $html);
        $html = str_replace("__SIGNATURE__", $agent->signature, $html);
        $html = str_replace("__TITLE__", CFG::str("title_tag", "Verifying Your Browser"), $html);
        $html = str_replace("__BROWSER__", $agent->browser_name, $html);
        $html = str_replace("__UUID__", strtoupper(random_str(10)), $html);
        $html = str_replace("__DOMAIN__", $_SERVER['SERVER_NAME']??'UNKNOWN_SERVER', $html);
        $html = str_replace("__VER__", BITFIRE_VER, $html);
        // log_it will increment the verification counter for FAIL_RESTRICTED in log_it()
        \BitFire\log_it(\BitFire\FAIL_RESTRICTED);
        $effect->response_code(CFG::int("verify_http_code", 303))->exit(true);

    }
    // build the page to send back xml-http-request
    else {
        $html = $script;
        $effect->exit(false);
    }

    $effect->out($html);
    return $effect;
}



function json_to_bot(string $json, string $path = "") : ?BotSimpleInfo {
    $data = json_decode($json, true);
    if (!empty($data)) {
        $bot_data = new BotSimpleInfo("");
        $abuse = new Abuse();
        if (empty($bot_data['favicon'])) { $bot_data['favicon'] = ''; } // old bot conversion code here
        if (empty($bot_data['mtime'])) { $bot_data['mtime'] = time(); } // old bot conversion code here
        $bot_data = map_to_object($data, $bot_data);
        $bot_data->abuse = map_to_object($data['abuse']??[], $abuse);
        return $bot_data;
    }
    if (!empty($path)) {
        rename($path, "{$path}.malformed");
    }
    return null;
}

function hydrate_any_bot_file(string $file_path) : ?BotSimpleInfo {

    $file = FileData::new($file_path);
    if (!$file->exists) {
        return null;
    }

    if (ends_with($file_path, ".json")) {
        return unserialize($file->raw());
    }
    // map the json data to a real object
    else if (ends_with($file_path, ".js")) {
        return json_to_bot($file->raw(), $file_path);
    }

    return null;
}


/**
 * ensure that bot access times are correct
 * @param BotSimpleInfo 
 * @return BotSimpleInfo 
 */
function set_bot_access_time(BotSimpleInfo $bot_data) : BotSimpleInfo {
    if (empty($bot_data->mtime)) {
        $bot_data->mtime = time();
    }
    if (empty($bot_data->ctime)) {
        $bot_data->ctime = time();
    }
    return $bot_data;
}

/**
 * update the manual mode for the bot if it is not configured and not google and being evil...
 * @param BotSimpleInfo $bot_data 
 * @param null|Request $request 
 * @return BotSimpleInfo 
 */
function set_bot_manual_mode(BotSimpleInfo $bot_data, ?Request $request = null) : BotSimpleInfo {
    // fix for old bot data
    $bot_data->manual_mode = ($bot_data->manual_mode == 0) ? BOT_ALLOW_RESTRICT : $bot_data->manual_mode;

    // flip the bot to allow none if it is unknown and evil
    if (($request->classification & REQ_EVIL) && !$bot_data->valid && !$bot_data->configured && !is_google_or_bing($request->ip)) {
        $bot_data->manual_mode = BOT_ALLOW_NONE;
    }

    return $bot_data;
}


/**
 * load bot data, if request is null, will not attempt to add the ip to the bot data
 * @param UserAgent $agent 
 * @param null|Request $request 
 * @return BotSimpleInfo 
 * @throws RandomException 
 */
function load_bot_data2(UserAgent $agent, ?Request $request = null): BotSimpleInfo {
    $base_name = get_hidden_file('bots/'.crc32($agent->trim));

    // load the local bot configuration...
    $bot_data = hydrate_any_bot_file($base_name . '.js');

    // request bot info from the remote server if we don't have it locally
    if (empty($bot_data) && !empty($request)) {

        $data = ['ip2' => $request->ip, 'trim' => $agent->trim, 'agent'=>$agent->agent_text, 'fingerprint'=>$agent->fingerprint, 'url' => $request->path];
        $response = http2('GET', BOTS . 'bot_info4.php', $data);

        if (!empty($response->content)) {
            $bot_data = json_to_bot($response->content);
            if ($bot_data != false) {
                $bot_data->ctime = time();
            }
        }
    }


    // create a new bot if we could not load one from the remote server (bitfire.co down?)
    if (!empty($request) && empty($bot_data)) {
        trace('BOT_NEW');
        $bot_data = new BotSimpleInfo($agent->trim);
        $bot_data->agent_trim = $agent->trim;
        $bot_data->ips = [$request->ip => $request->classification];
        $bot_data->category = 'Auto Learn';
        $bot_data->name = '';
        $bot_data->home_page = '';
        $bot_data->icon = 'unknown_bot.webp';
        $bot_data->valid = 0;
        $bot_data->manual_mode = BOT_ALLOW_RESTRICT;
        $bot_data->ctime = time();
    }

    // WE ALWAYS NEED ABUSE OBJECT
    if (empty($bot_data->abuse)) {
        $bot_data->abuse = new Abuse();
    }

    // bot_data will now have known bots and unknown bots, manual mode will be set
    $bot_data->agent = $agent->agent_text;


    if (!empty($request)) {
        // update ips for valid bots IF they are NOT evil...
        $bot_data = add_net_to_bot($bot_data, $request->ip, $request->classification);
        // always update manual mode 
        $bot_data = set_bot_manual_mode($bot_data, $request);
    }
    // always make sure access time is set
    $bot_data = set_bot_access_time($bot_data);

    return $bot_data;
}


/**
 * add the network to the bot data
 * @param BotSimpleInfo $bot_data 
 * @param string $ip 
 * @return BotSimpleInfo 
 */
function add_net_to_bot(BotSimpleInfo $bot_data, string $ip, int $classification): BotSimpleInfo {
    // we have seen this ip before
    $have_ip = isset($bot_data->ips[$ip]);

    // if the bot is authenticated, we can add the domain IF its not evil and not abusive
    $ensure_auth = $bot_data->abuse->score < 25 && (in_array($bot_data->manual_mode, [BOT_ALLOW_AUTH]) && !($classification & REQ_EVIL));

    if (!$have_ip && count($bot_data->ips) >= 40) {
        if ( (!($classification & REQ_EVIL) && ($bot_data->abuse->score < 20)) ) {
            array_shift($bot_data->ips);
            $bot_data->ips[$ip] = ($bot_data->ips[$ip]??0) | $classification;
        }
    }
    else {
        $bot_data->ips[$ip] = ($bot_data->ips[$ip]??0) | $classification;
    }

    // IMPORTANT! do not add domain verification for unknown bots or scanners...
    $restricted_cats = ["vulnerability scanner", "uncategorized", "unknown"];
    // don't add new ips for restricted categories
    if (in_array(strtolower($bot_data->category), $restricted_cats)) {
        return $bot_data;
    }

    // only keep the last 40 ips, this will remove the first ip if we have more than 40
    // add the ip domain if we don't already have it
    if (!$have_ip && $ensure_auth) {
        $domain = ip_to_domain($ip);
        // add abuse domain name if we don't have it already
        if (!empty($bot_data->abuse->domain) && !icontains($bot_data->domain, $bot_data->abuse->domain)) {
            $bot_data->domain .= trim("," . $bot_data->abuse->domain, ", ");   
        }

        if (!empty($domain) && !icontains($bot_data->domain, $domain)) {
            $bot_data->domain .= ",{$domain}";
        }
    }

    return $bot_data;
}


/**
 * take a FQDN and return the domain name
 * @param string $fqdn 
 * @return string 
 */
function host_to_domain(string $fqdn) : string {
    if (preg_match("/([a-zA-Z0-9_-]+\.(?:[a-zA-Z0-9-]+|xn-\w+))\.?$/", $fqdn, $matches)) {
        // if the domain is NOT an ip address, return it
        if (!preg_match('/^[0-9\.:]+$/', $matches[1])) {
            return $matches[1];
        }
    }
    return "";
}



/**
 * see return value for details
 * @param UserAgent $agent 
 * @param Request $request 
 * @return Effect - with status set to correct BOT_VALID_XXX status 
 */
function bot_authenticate(UserAgent $agent, Request $request, IPData $ip_data): Effect {
    $fail = FAIL_MISS_WHITELIST;
    $message = "bot blocked by administrator";
    $action = 0;

    // handle special case where we have no user agent...
    if (empty($agent->trim)) {
        $agent->trim = $agent->agent_text = $agent->browser_name = "none";
        $action = ($request->path == '/manifest.json') ? BOT_VALID_OPEN : 0;  // weird case
    }


    // load the bot data
    $bot_data = load_bot_data2($agent, $request);
    
    // quickly validate our most popular search engines, store reverse IP in memory cache
    if (isset(FAST_BOTS[$agent->browser_name])) {
        $action = BOT_VALID_AGENT;
        if (empty($ip_data->domain)) {
            $ip_data->domain = ip_to_domain($request->ip);
        }
        $host = $ip_data->domain;
        foreach (FAST_BOTS[$agent->browser_name] as $domain) {
            if (!empty($host) && ends_with(strtolower($host), $domain)) {
                return Effect::new()->status(BOT_VALID_NET);
            }
        }
        // if the bot is not authenticated, and requesting restricted action, block it
        if ($request->classification & (REQ_EVIL | REQ_RESTRICTED)) {
            $action = BOT_VALID_INVALID;
            $fail = 23002;
            $message = "Fake {$agent->browser_name} bot";
        }
    }

    // validate the bot (if not yet validated)
    if ($action == 0) {
        $action = bot_action_logic($bot_data, $request);
    }
    $blocked = ($action == BOT_VALID_INVALID);

    // update hit counters
    $bot_data->hit  += $blocked ? 0 : 1;
    $bot_data->miss += $blocked ? 1 : 0;

    // update the bot file
    register_shutdown_function(function () use ($bot_data) {
        $bot_file = get_hidden_file("bots/" . crc32($bot_data->agent_trim) . ".js");
        file_put_contents($bot_file, json_encode($bot_data, JSON_PRETTY_PRINT), LOCK_EX);
    });

    // handle too many UA from 1 IP here...
    // immediate block if 5 or more BOT uas from this ip
    if (!$ip_data->ip_classification & \BitFire\IP_GOOG_MS_AUTO) {
        if ($agent->bot && $action != BOT_ALLOW_RESTRICT && count($ip_data->bot_file_list) > 4) {
            block_now(24010, "user_agent", $request->agent, $request->agent, 0)->run();
        }
    }

    // return a block or the status (which is the allowed reason - from create_bot_effect)
    return ($blocked) ?
        block_now($fail, "user-agent", $request->agent, "match", 600, $request, $message) :
        Effect::new()->status($action);
}

/**
 * take BotSimpleInfo configuration, and the request, validate it and return an effect to allow or block the request
 * @param BotSimpleInfo $bot_data 
 * @param Request $request 
 * @return int - BOT_VALID_XXX status. if status is < 0, should be blocked
 */
function bot_action_logic(BotSimpleInfo $bot_data, Request $request) : int {

    $logic = [
        BOT_ALLOW_NONE => BOT_VALID_INVALID,
        BOT_ALLOW_RESTRICT => BOT_VALID_RESTRICTED,
        BOT_ALLOW_AUTH => BOT_VALID_IP,
        BOT_ALLOW_DOMAIN => BOT_VALID_NET,
        BOT_ALLOW_NET => BOT_VALID_NET,
        BOT_ALLOW_OPEN => BOT_VALID_OPEN,
        BOT_ALLOW_ANY => BOT_VALID_OPEN
    ];

    $result = BOT_VALID_INVALID;

    // admin has blocked this bot!
    if ($bot_data->manual_mode == BOT_ALLOW_NONE) {
        return BOT_VALID_INVALID;
    }

    // is this one ip blocked?
    if (isset($bot_data->ips[$request->ip])) {
        if (($bot_data->ips[$request->ip] & REQ_BLOCKED)) {
            return BOT_VALID_INVALID;
        }
    }

    // the bot is open, just allow it...
    if ($bot_data->manual_mode == BOT_ALLOW_ANY || $bot_data->manual_mode == BOT_ALLOW_OPEN) {
        return BOT_VALID_OPEN;
    }

    // bot's NOT requesting a restricted action, exit here...
    if (! ($request->classification & REQ_RESTRICTED)) {
        return BOT_VALID_RESTRICTED;
    }


    // bot is authenticated, allow it if we have seen the IP...
    if ($bot_data->manual_mode == BOT_ALLOW_AUTH) {
        // a restricted action is being requested...
        // only match the ip if the bot ip is not evil
        $cidrs = map_map_value($bot_data->ips, function ($classification) {
            return ($classification & REQ_EVIL) ? NULL : 20;
        });


        // first check for matching cidr (faster), then matching domain if that fails (reverse dns lookup)
        if (ip_in_cidr_list($request->ip, $cidrs)) {
            return BOT_VALID_IP;
        }
        // fall back to domain verification
        else if (domain_match($bot_data->domain, $request->ip)) {
            return BOT_VALID_NET;
        }
    }

    // no matching ip or network for restricted action, block it...
    return BOT_VALID_INVALID;
}

/**
 * test if an ip/user agent is bing or google by ip
 * TODO: add more crawlers and ip address, update ip addresses weekly...
 * NOTE: when crawling bing and google ip range xml files, whois lookup the ip and
 * add the full range, then remove duplicates, this will reduce the number of cidr
 * ranges tyo check.
 * @param string $ip 
 * @param string $agent 
 * @return bool 
 */
function is_google_or_bing(string $ip, bool $use_cache = true) : bool {
   
    if (is_google_ip($ip, $use_cache)) {
        return true;
    }

    if (is_bing($ip, $use_cache)) {
        return true;
    }
    
    if (is_automattic($ip, $use_cache)) {
        return true;
    }

    return false;
}

function is_cloud_flair(string $ip, bool $use_cache = true) : bool {
    static $match = null;
    if ($match === null && $use_cache) {
        $flair_ips = [ '103.21.244.0' => '22', '103.22.200.0' => '22', '103.31.4.0' => '22', '104.16.0.0' => '13',
        '104.24.0.0' => '14', '108.162.192.0' => '18', '131.0.72.0' => '22', '141.101.64.0' => '18', '162.158.0.0' => '15', 
        '172.64.0.0' => '13', '173.245.48.0' => '20', '188.114.96.0' => '20', '190.93.240.0' => '20', 
        '197.234.240.0' => '22', '198.41.128.0' => '17' ];
        $match = ip_in_cidr_list($ip, $flair_ips);
    }
    return $match;
}


function is_bing(string $ip, bool $use_cache = true) : bool {
    static $match = null;
    if ($match === null || $use_cache == false) {
        $msn = ['157.55.39.0' => '24' ,'207.46.13.0' => '24' ,'40.77.167.0' => '24' ,'13.66.139.0' => '24' ,'13.66.144.0' => '24'
        ,'52.167.144.0' => '24' ,'13.67.10.16' => '28' ,'13.69.66.240' => '28' ,'13.71.172.224' => '28' ,'139.217.52.0' => '28'
        ,'191.233.204.224' => '28' ,'20.36.108.32' => '28' ,'20.43.120.16' => '28' ,'40.79.131.208' => '28' ,'40.79.186.176' => '28'
        ,'52.231.148.0' => '28' ,'20.79.107.240' => '28' ,'51.105.67.0' => '28' ,'20.125.163.80' => '28' ,'40.77.188.0' => '22'
        ,'65.55.210.0' => '24' ,'199.30.24.0' => '23' ,'40.77.202.0' => '24' ,'40.77.139.0' => '25' ,'20.74.197.0' => '28',
        '20.15.133.160' => '27'];
        $match = ip_in_cidr_list($ip, $msn);
    }
    return $match;
}

function is_google_ip(string $ip, bool $use_cache = true) : bool {
    static $match = null;
    if ($match === null || $use_cache == false) {
        // google ipv6 or ipv4
        if (is_ipv6($ip)) {
            $match = starts_with($ip, "2001:4860:4801");
        } else {
            $match = ip_in_cidr_list($ip, ['66.249.64.1' => '19', '35.247.243.240' => '28',
                '34.64.0.0' => '10', '34.128.0.0' => '10', '74.125.0.1' => '16', '209.85.128.0' => '17',
                '72.14.192.0' => '18', '74.125.0.0' => '16']);
        }
   }
    return $match;
}

// check for automattic ip
function is_automattic(string $ip, bool $use_cache = true) : bool {
    static $match = null;
    if ($match === null || $use_cache == false) {
        $match = cidr_match($ip, '192.0.64.0', 18);
    }
    return $match;
}

/**
 * forward and reverse domain lookup
 * @param string $domain_list_comma 
 * @param string $ip
 * @return bool - true if $domain is in $ip's reverse lookup
 */
function domain_match(string $domain_list_comma, string $ip) {
    $ins = BitFire::get_instance();
    if ($ins) {
        if (empty($ins->ip_data->domain)) {
            $ins->ip_data->domain = ip_to_domain($ip);
        }
        $domain = $ins->ip_data->domain;
    }
    if (empty($domain)) {
        $domain = ip_to_domain($ip);
    }
    // make sure to save this ip lookup in the ip_data object
    
    $domain_list = explode(",", $domain_list_comma);
    return in_array($domain, $domain_list);
}



/**
 * @param string $browser_name 
 * @param int $fingerprint 
 * @param array $fingerprint_map 
 * @return bool - true if $fingerprint_map[$browser_name] contains $fingerprint
 */
function validate_header(string $browser_name, int $fingerprint, array $fingerprint_map) : bool {
    if (php_sapi_name() == "cli") { return true; }

    return (in_array($fingerprint, $fingerprint_map[$browser_name]??[]));
}



/**
 * uses forward and reverse ip lookups to verify the domain name
 * TODO: wire up IP_Data and ip_to_domain somehow ... think about this one
 * @param string $ip - an IPv4 or IPv6 address and convert to a domain name.
 * @return string domain name, or empty string
 */
function ip_to_domain(string $ip) : string {
    $host = gethostbyaddr($ip);
    trace("IP2H[$ip . $host]");
    // ip has no dns host
    if ($ip == $host) {
        return "";
    }
    $check_domain = host_to_domain($host);
    // dns query failed
    if (empty($check_domain)) {
        return "";
    }
    $ips = gethostbynamel($host);
    // reverse query failed
    if (empty($ips) || !in_array($ip, $ips)) {
        return "";
    }
    return $check_domain;
}
