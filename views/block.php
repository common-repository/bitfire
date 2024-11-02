<?php

    use const BitFire\BITFIRE_VER;
    // ensure start_time is set
    if (!isset($GLOBALS['bf_s1'])) {
        $GLOBALS['bf_s1'] = hrtime(true) - 1000000;
    }

    $resp_code = intval(\BitFire\Config::int("response_code", 200));
    $error_css = \Threadfin\get_public("error.css");
    $error_css = isset($error_css) ? htmlentities($error_css) : "";
    $st = (hrtime(true) - $GLOBALS['bf_s1']) / 1e+6;
    \BitFire\BitFire::get_instance()->blocked($st, $resp_code, $custom_err);
    \ThreadFin\trace("BL CODE $resp_code");
    $agent = \BitFire\BitFire::get_instance()->agent; 
    $fingerprint = 0;
    if ($agent && isset($agent->fingerprint)) { $fingerprint = $agent->fingerprint; $browser = $agent->browser_name; }
    http_response_code($resp_code);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Request blocked by BitFire</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, follow">
    <link type="text/css" rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.1/css/fontawesome.min.css">
    <link type="text/css" rel="stylesheet" href="<?php echo $error_css; ?>">
    <style>
    </style>
</head>
<body>
<div id="block"> <div class="block-bg"></div> <div class="block"> <div class="block-err"> <h1>Halt!</h1> </div>
<h2>Something Happened</h2>
<p class="nor"><?php echo $custom_err?></p>
<p class="nor">If this is an error, please click the request review button below. Reference ID <i><?php echo $uuid; ?></i></p>
<a href="#" id="review"> <button type="button" id="review">Request Review</button> </a>
<a href="/"> <button type="button" id="home">Back To Homepage</button> </a>
</div> </div>
<div id="attribute"><p>
    <span> Powered by: <a href="https://bitfire.co" target="_blank" style="color: #fff;">BitFire</a></span>
    <span> Photo by: <a href="https://www.pexels.com/@pok-rie-33563/" rel="nofollow ugc" target="_blank" style="color: #fff;">@pok-rie</a> </span>
</p></div>
<script>

if (navigator.sendBeacon) {
    let data = new FormData();
    data.append('fingerprint', '<?php echo $agent->fingerprint;?>');
    data.append('browser', '<?php echo $browser;?>');
    data.append('type', '<?php echo $custom_err;?>');
    data.append('code', '<?php echo $resp_code;?>');
    data.append('ver', '<?php echo BITFIRE_VER;?>');
    navigator.sendBeacon("https://bitfire.co/ray.php", data);
}


document.getElementById("review").addEventListener("click", function () {
    let e=window.event; let data={"uuid":'<?php echo $uuid;?>',"x":e.clientX,"y":e.clientY};
    console.log(data);
    let name = prompt("short message for the administrator to review your request", "");
    data["name"] = name;
    if (navigator.sendBeacon) {
        let data2 = new FormData();
        data2.append('fingerprint', '<?php echo $fingerprint; ?>');
        data2.append('type', 'verify');
        data2.append('name', data["name"]);
        data2.append('uuid', data["uuid"]);
        data2.append('x', data["x"]);
        data2.append('y', data["y"]);
        navigator.sendBeacon("https://bitfire.co/ray.php", data2);
    }

    if (name != null) {
        const response = fetch("/?BITFIRE_API=review", {
        method:'POST',mode:'no-cors',cache:'no-cache',credentials:'omit',headers:{'Content-Type': 'application/json'},redirect:'follow',referrerPolicy:'unsafe-url',body:JSON.stringify(data)
        }).then((response) => response.json()).then((data) => alert(data.note));
    }
});
</script>
</body>
</html>
<!--
detailed block reason: 

<?php echo "$code\n"; if (\BitFire\Config::enabled('debug')) { echo(json_encode($block, JSON_PRETTY_PRINT)); } echo $st; ?>
-->
