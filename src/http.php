<?php

namespace ThreadFin\HTTP;

use ArrayAccess;

use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\trace;
use function ThreadFin\debug;

use const BitFire\BITFIRE_VER;

function map_reduce(array $map, callable $fn, $carry = "") {
    foreach($map as $key => $value) { $carry = $fn($key, $value, $carry); }
    return $carry;
}

class Basic_Array implements ArrayAccess {
    public function offsetExists($offset) : bool {
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
        unset($this->$offset);
    }
}


/**
 * portable * HTTP functions
 */
class HttpResponse extends Basic_Array {
    /** @var string $content */
    public $content;
    /** @var string $url */
    public $url;
    /** @var array $headers */
    public $headers;
    /** @var int $len */
    public $len;
    /** @var bool $success */
    public $success;
    /** @var int $http_code */
    public $http_code;
    public $info;

    public function __construct(string $content, string $url, array $headers, int $len, bool $success)
    {
        $this->content = $content;
        $this->url = $url;
        $this->headers = $headers;
        $this->len = $len;
        $this->success = $success;
    }
}

function http_response(string $content, string $url, array $headers, int $len, bool $success) : HttpResponse {
    return new HttpResponse($content, $url, $headers, $len, $success);
}

function new_headers(array $optional_headers = [], string $url = "") : array {
       // set user-agent
    if (!isset($optional_headers['User-Agent'])) {
        if (contains($url, "bitfire.co")) {
		    $optional_headers['User-Agent'] = "BitFire/1.1 RASP https://bitfire.co/user_agent/".BITFIRE_VER;
        } else {
		    $optional_headers['User-Agent'] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36";
            $optional_headers['Upgrade-Insecure-Requests'] = "1";
            $optional_headers['Sec-Fetch-User'] = "?1";
            $optional_headers['Sec-Fetch-Site'] = "none";
            $optional_headers['Sec-Fetch-Mode'] = "navigate";
            $optional_headers['Sec-Fetch-Dest'] = "document";
            $optional_headers['Sec-Ch-Ua-Platform'] = "Linux";
            $optional_headers['Sec-Ch-Ua-Mobile'] = "?0";
            $optional_headers['Sec-Ch-Ua'] = 'Chromium";v="115", "Not/A)Brand";v="99"';
            $optional_headers['Pragma'] = 'no-cache';
            $optional_headers['Cache-Control'] = 'no-cache';
            $optional_headers['Accept-Language'] = 'en-US,en;q=0.9';
            $optional_headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
        }
    }

    return $optional_headers;
}

/**
 * http request via curl, return [$content, $response_headers]
 */
function http2(string $method, string $url, $data = "", array $optional_headers = ['redirect' => 3]) : HttpResponse {
    $m0 = microtime(true);

    $optional_headers = new_headers($optional_headers, $url);

    // fall back to non curl...
    if (!function_exists('curl_init')) {
        $c = http($method, $url, $data, $optional_headers);
        $len = strlen($c->content);
        return http_response($c->content, $url, ["http/1.1 200"], $len, ($len > 0));
    }

    // startup curl library
    $ch = \curl_init();
    // fall back to non-curl if library fails
    if (!$ch) {
        $c = http($method, $url, $data, $optional_headers);
        $len = strlen($c->content);
        return http_response($c->content, $url, ["http/1.1 200"], $len, ($len > 0));
    }

    //trace("http2 $url");

    // build the post content
    $content = (is_array($data)) ? http_build_query($data) : $data;
    if ($method == "POST") {
        \curl_setopt($ch, CURLOPT_POST, 1);
        \curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
    } else {
        $prefix = contains($url, '?') ? "&" : "?";
        $url .= $prefix . $content;
        if ($method == "HEAD") {
            \curl_setopt($ch, CURLOPT_NOBODY, 1);
        }
    }

    // set the url
    \curl_setopt($ch, CURLOPT_URL, $url);

    // map the headers
    if ($optional_headers != NULL) {
        $headers = map_reduce($optional_headers, function($key, $value, $carry) { $carry[] = "$key: $value"; return $carry; }, []);
        \curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    
    // Receive server response ...
    \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    \curl_setopt($ch, CURLINFO_HEADER_OUT, true);

    // store response headers
    $resp_headers = [];
    // this function is called by curl for each header received
    \curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $header) use (&$resp_headers) {
        $hdr = explode(':', $header, 2);
        $name = $hdr[0]??'empty';
        $value = $hdr[1]??'empty';
        $resp_headers[strtolower(trim($name))] = trim($value);
        return strlen($header);
    });

    curl_setopt($ch, CURLOPT_TIMEOUT, 1500);


    $server_output = \curl_exec($ch);
    $m1 = microtime(true);
    $ms = round(($m1 - $m0) * 1000, 2);
    if (!empty($server_output)) {
        if ($resp_headers['content-encoding']??"" == 'gzip') {
            $server_output = gzdecode($server_output);
        }
    }

    // follow redirects...
    if (isset($resp_headers['location'])) {
        echo "$url -> redirect {$resp_headers['location']}\n";
        if (intval($optional_headers['redirect']??0) > 0) {
            $optional_headers['redirect'] = intval($optional_headers['redirect']??0) - 1;
            echo " => " . intval($optional_headers['redirect']) . "({$resp_headers['location']}) ";
            return http2($method, $resp_headers['location'], $data, $optional_headers);
        }
    }

    $info = @\curl_getinfo($ch);
    $info['error_no'] = curl_errno($ch);
    $info['error_str'] = curl_error($ch);
    /*
    if ($ssl) {
        $info['x-cert'] = curl_getinfo($ch, CURLINFO_CERTINFO);
        fclose($fh);
        $info['x-log'] = file_get_contents($tmp);
        @unlink($tmp);
    }
    */
    \curl_close($ch);



    $response = http_response($server_output, $url, $resp_headers, strlen($server_output), (empty($info)) ? false : true);
    // if ($proxy) { print_r($response); }
    $response->http_code = $info["http_code"];
    $response->info = $info;
    return $response;



    
    $server_output = \curl_exec($ch);
    $m1 = microtime(true);
    $ms = round(($m1 - $m0) * 1000, 2);
    if (!empty($server_output)) {
        debug("curl [%s] [%d] bytes (%fms)", $url, strlen($server_output), $ms);
    } else {
        debug("curl [%s] failed (%fms)", $url, $ms);
        return http_response("", $url, ["http/1.1 200"], 0, false);
    }

    $info = @\curl_getinfo($ch);
    \curl_close($ch);

    $response = http_response($server_output, $url, $resp_headers, strlen($server_output), (empty($info)) ? false : true);
    $response->http_code = $info["http_code"];
    return $response;
}


function httpg(string $path, $data, array $opts = [])  { return http("GET", $path, $data, $opts); }
function httpp(string $path, $data, array $opts = [])  { return http("POST", $path, $data, $opts); }


/**
 * post data to a web page and return the result
 * refactor to use http2
 * @param string $method the HTTP verb
 * @param string $url the url to post to
 * @param array $data the data to post, key value pairs in the content head
 *   parameter of the HTTP request
 * @param string $optional_headers optional stuff to stick in the header, not
 *   required
 * @param integer $timeout the HTTP read timeout in seconds, default is 5 seconds
 * @throws \RuntimeException if a connection could not be established OR if data
 *  could not be read.
 * @throws HttpTimeoutException if the connection times out
 * @return HttpResponse the server response.
 */
function http(string $method, string $path, $data, ?array $optional_headers = []) : HttpResponse {
    $m0 = microtime(true);
    $path1 = $path;

    $optional_headers = new_headers($optional_headers, $path);

    // build the post content parameter
    $content = (is_array($data)) ? http_build_query($data) : $data;
    $params = http_ctx($method, 5);
    if ($method === "POST") {
        $params['http']['content'] = $content;
        $optional_headers['Content-Length'] = strlen($content);
    } else { $path .= "?" . $content; }
    $path = trim($path, "?&");

    if (!$optional_headers) { $optional_headers = []; }

    if (!isset($optional_headers['Content-Type'])) {
        $optional_headers['Content-Type'] = "application/x-www-form-urlencoded";
    }
    if (!isset($optional_headers['User-Agent'])) {
		$optional_headers['User-Agent'] = "BitFire/1.1 RASP https://bitfire.co/user_agent/".BITFIRE_VER;
    }

    
    if ($optional_headers && count($optional_headers) > 0) {
        $params['http']['header'] = map_reduce($optional_headers, function($key, $value, $carry) { return "$carry$key: $value\r\n"; }, "" );
    }

    $ctx = stream_context_create($params);
    $response = @file_get_contents($path, false, $ctx);
    // log failed requests, but not failed requests to wordpress source code

    $m1 = microtime(true);
    $ms = round(($m1 - $m0) * 1000, 2);
    trace("http $path1 ({$ms}ms)");
    if ($response === false && !contains($path, "wordpress.org")) {
        debug("http_resp [%s] fail", $path);
        return http_response($response, $path, ["http/1.1 200"], 0, false);
    }

    return http_response($response, $path, ["http/1.1 200"], strlen($response), true);
}

/**
 * create HTTP context for HTTP request
 * PURE
 */
function http_ctx(string $method, int $timeout) : array {
    return array('http' => array(
        'method' => $method,
        'timeout' => $timeout,
        'max_redirects' => 5,
        'header' => ''
        ),
        'ssl' => array(
            'verify_peer' => true,
            'allow_self_signed' => false,
        )
    );
}

function http3(string $method, string $url, $data = "", array $optional_headers = []) {

    $optional_headers = new_headers($optional_headers, $url);

    $ch = \curl_init();
    if (!$ch) {
        $c = http($method, $url, $data, $optional_headers);
        $len = strlen($c->content);
        return ["content" => $c->content, "path" => $url, "headers" => ["http/1.1 200"], "length" => $len, "success" => ($len > 0)];
    }

    $content = (is_array($data)) ? http_build_query($data) : $data;
    if ($method == "POST") {
        \curl_setopt($ch, CURLOPT_POST, 1);
        \curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
    } else {
        $prefix = contains($url, '?') ? "&" : "?";
        $url .= $prefix . $content;
    }

    \curl_setopt($ch, CURLOPT_URL, $url);
    \curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);

    if ($optional_headers != NULL) {
        $headers = map_reduce($optional_headers, function($key, $value, $carry) { $carry[] = "$key: $value"; return $carry; }, array());
        \curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    
    // Receive server response ...
    \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    \curl_setopt($ch, CURLINFO_HEADER_OUT, false);
    \curl_setopt($ch, CURLOPT_HEADER, false);

    return $ch;
}

function http_wait($mh) {

    if (!empty($mh)) {
        $active = null;
        debug("http wait...");
        //execute the handles
        do {
            $mrc = curl_multi_exec($mh, $active);
        }
        while ($mrc == CURLM_CALL_MULTI_PERFORM);

        while ($active && $mrc == CURLM_OK) {
            if (curl_multi_select($mh) != -1) {
                do {
                    $mrc = curl_multi_exec($mh, $active);
                    usleep(10000);
                } while ($mrc == CURLM_CALL_MULTI_PERFORM);
            }
        }
    }
}

