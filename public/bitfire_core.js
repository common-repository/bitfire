var BitFire = (function() {

    var version = 5000;

function bf_time_stamp() {
    return Math.floor(Date.now() / 1000);
}

function bf_new_page() {
    return {"page": window.location.href, "t": bf_time_stamp(), "n": "page"};
}

function bf_new_click(x) {
    let v = "";
    let type = "";
    if (x.target && x.target.nodeName) {
        type = x.target.nodeName;
        if (x.target.nodeName == "INPUT") {
            v = (x.target.type == "checkbox") ? x.target.checked : x.target.value;
        } else if (x.target.nodeName == "SELECT") {
            v = x.target.value;
        } else if (x.target.nodeName == "A") {
            v = x.target.href;
        } else if (x.target.nodeName == "BUTTON") {
            v = x.target.innerText;
        }
    }
    return ({"n":"click", "t": bf_time_stamp(), "scroll": window.scrollY, "type": type, "x": window.pageXOffset + x.pageX, "y": window.pageYOffset + x.pageY, "v": v});
}

function bf_key_time() {
    if (!bf_key_time.last_time) {
        bf_key_time.last_time = Date.now();
        bf_key_time.rates = [];
        bf_key_time.ctr = 0
        return;
    } else {
        bf_key_time.this_time = Date.now();
        if (bf_key_time.this_time - bf_key_time.last_time < 2000) {
            bf_key_time.ctr++;
        } else {
            bf_key_time.rates.push(bf_key_time.ctr);
            bf_key_time.ctr = 0;
            bf_key_time.last_time = bf_key_time.this_time;
        }
    }
}
function getPosition(el) {
    var xPosition = 0;
    var yPosition = 0;
   
    while (el) {
      if (el.tagName == "BODY") {
        // deal with browser quirks with body/window/document and page scroll
        var xScrollPos = el.scrollLeft || document.documentElement.scrollLeft;
        var yScrollPos = el.scrollTop || document.documentElement.scrollTop;
   
        xPosition += (el.offsetLeft - xScrollPos + el.clientLeft);
        yPosition += (el.offsetTop - yScrollPos + el.clientTop);
      } else {
        xPosition += (el.offsetLeft - el.scrollLeft + el.clientLeft);
        yPosition += (el.offsetTop - el.scrollTop + el.clientTop);
      }
   
      el = el.offsetParent;
    }
    return {
      x: xPosition,
      y: yPosition
    };
}

function bf_clicks(event) {
    //console.log(event);
    if (!bf_clicks.clicks) {
        bf_clicks.clicks = [];
    }
    let r = event.target.getBoundingClientRect();
    let w = event.target.innerWidth;
    let h = event.target.innerHeight;

    let pos = getPosition(event.target);
    /*
    bf_clicks.clicks.push({
        "absx":pos.x,
        "absy":pos.y,
        "x": event.clientX,
        "y": event.clientY,
        "w": event.target.innerWidth,
        "h": event.target.innerHeight,
        "t": Date.now(),
        "n": event.target.tagName,
        "i": event.target.id,
    });
    */
    bf_clicks.clicks.push([
        pos.x,
        pos.y,
        event.clientX,
        event.clientY,
        event.target.innerWidth,
        event.target.innerHeight,
        Date.now(),
        event.target.tagName,
       event.target.id,
    ]);

    //bf_clicks.clicks.push({event.clientX + pos.x, event.clientY + pos.y, , Date.now()]);
}

function bf_scroll() {
    if (!bf_scroll.last_time) {
        bf_scroll.last_time = Date.now();
        bf_scroll.positions = [];
        bf_scroll.position = 0
        return;
    } else {
        bf_scroll.this_time = Date.now();
        if (bf_scroll.this_time - bf_scroll.last_time < 2000) {
            bf_scroll.position = window.scrollY;
        } else {
            bf_scroll.positions.push(bf_scroll.position);
            bf_scroll.position = 0;
            bf_scroll.last_time = bf_scroll.this_time;
        }
    }
}

function vector_to_byte(velocity_x, velocity_y) {
    let x = Math.min(velocity_x * 0.092, 46);
    let y = Math.min(velocity_y * 0.092, 46);

    let xc = Math.min(Math.max(79+x, 33), 126);
    let yc = Math.min(Math.max(79+y, 33), 126);

    return String.fromCharCode(xc) + String.fromCharCode(yc);
}

function bf_mouse(event) {
   if (!bf_mouse.last_time) {
        bf_mouse.moves = "";
        bf_mouse.pos = []
        bf_mouse.last_pos = [event.screenX, event.screenY];
        //console.log("first", bf_mouse.last_pos);
        bf_mouse.last_time = Date.now();
    } else {
        var from = event.relatedTarget || event.toElement;
        //console.log(event, from);
        if (event.relatedTarget) { console.log("TARGET: ", event.relatedTarget); }
        if (Date.now() - bf_mouse.last_time > 100) {
            window.clearTimeout(window.BF_LAST);
            let vector = [event.movementX, event.movementY];
            let velocity = Math.abs(vector[0]) + Math.abs(vector[1]);
            if (velocity > 10) {
                bf_mouse.moves += vector_to_byte(vector[0], vector[1]);
                bf_mouse.pos.push([(vector[0] - bf_mouse.last_pos[0]) + (vector[1] - bf_mouse.last_pos[1])])
                if (bf_mouse.moves.length > 256) {
                    bf_mouse.moves = bf_mouse.moves.slice(-250);
                    bf_mouse.pos = bf_mouse.pos.slice(-250);
                }
                bf_mouse.last_pos = vector;
            }
            bf_mouse.last_time = Date.now();
            window.BF_LAST = window.setTimeout(function() {
            }, 250)
        }
    }
}



//window.addEventListener('DOMContentLoaded', (event) => {
window.addEventListener('never_execute', (event) => {
    /*
    var t = sessionStorage.getItem("bitfire_page");
    if (!t) { p = 0;}
    else { p = (parseInt(t) + 1) % 10; }
    console.log("page p", p);
    //sessionStorage.setItem("bitfire_page", p);
    //sessionStorage.setItem("bitfire"+p, JSON.stringify([bf_new_page()]));
    */

    document.addEventListener("keydown", bf_key_time);
    document.addEventListener("click", bf_clicks);
    document.addEventListener("scroll", bf_scroll);
    document.addEventListener("mousemove", bf_mouse);
    document.addEventListener("mouseleave", function() { 
        bf_mouse.moves += " M";
        bf_mouse.pos.push("0");
    });

    //console.log("event listeners 1");
    /*
    document.addEventListener("scroll", function() {
        if (!window.BF_EVT) {
            window.BF_EVT = window.setTimeout(function() {
                if (window.BF_SCROLL == window.scrollY) {
                    events.push({"n":"scr", "t": bf_time_stamp(), "scroll": window.scrollY});
                }
            }, 1500);
            window.BF_SCROLL = window.screenY;
        }
    });

    /*
    function(x) {
        let raw = sessionStorage.getItem("bitfire"+p);
        let events = JSON.parse(raw);
        events.push(bf_new_click(x));
        sessionStorage.setItem("bitfire"+p, JSON.stringify(events));
    });
    */
    document.addEventListener("visibilitychange", function(event) {
        //console.log(event.target);
        //let raw = sessionStorage.getItem("bitfire"+p);
        //let events = JSON.parse(raw);
        //events.push({"n":"vis", "t": bf_time_stamp(), "scroll": window.scrollY, "type": document.visibilityState});
        //sessionStorage.setItem("bitfire"+p, JSON.stringify(events));
        let type = document.visibilityState.substring(0,1);
        bf_mouse.moves += " " + type;
        
        if (document.visibilityState == "hidden") {
            //console.log("VIS!");
            const data = new FormData();
            data.append("clicks", bf_clicks.clicks);
            data.append("scrolls", bf_scroll.positions);
            data.append("keys", bf_key_time.rates);
            data.append("mouse", bf_mouse.moves);
            data.append("width", window.innerWidth); 
            data.append("height", window.innerHeight); 
            navigator.sendBeacon("/bitfire-beacon.php", data);
        }
    });
    //console.log("event listeners");
});

function bt_fnt() {
    let { fnts } = document;
    const it = fnts.entries();
  
    let arr = [];
    let done = false;
  
    while (!done) {
      const font = it.next();
      if (!font.done) {
        arr.push(font.value[0]);
      } else {
        done = font.done;
      }
    }
  
    return arr;
}

function bf_web_gl() {
    var canvas = document.createElement("canvas");
    var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    return gl ? gl.getParameter(gl.VENDOR) : "Deprecated Browser";
}

function bf_head() {
    navigator.permissions.query({name:'notifications'}).then(function(permissionStatus) {
        if(Notification.permission === 'denied' && permissionStatus.state === 'prompt') {
            return true;
        }
        return false;
    });
}

// calculate a 32bit fletcher sum on a string
function bf_fletcher32(str) {
    let sum1 = 0xffff, sum2 = 0xffff;
    for (let i = 0, l = str.length; i < l; i++) {
        let c = str.charCodeAt(i);
        sum1 += c;
        sum2 += sum1;
    }
    sum1 = (sum1 & 0xffff) + (sum1 >>> 16);
    sum2 = (sum2 & 0xffff) + (sum2 >>> 16);
    return sum2 << 16 | sum1;
}


function bf_info() {
    let a = navigator.webdriver ? 1 : 0;
    let d = document.$cdc_asdjflasutopfhvcZLmcfl_ ? 1 : 0;
    let p = navigator.userAgent.includes(navigator.platform) ? 1 : 0;
    let o = new Date().getTimezoneOffset();
    let f = bt_fnt();
    let u = navigator.plugins;
    let g = bf_web_gl();
    let j = eval.toString().length;
    let sum = bf_fletcher32(navigator.userAgent + a + d + p + o + f + u + g + j);
    return {a, d, p, o, f, u, g, j, sum};
}

return {
    xhr: function (data) {
        /*
        const form = document.createElement('form'); form.method = "POST"; form.action = window.location.href;
        for (const key in params) {
            if (params.hasOwnProperty(key)) {
                const field = document.createElement('input');
                field.type = 'hidden'; field.name = key;
                field.value = params[key]; form.appendChild(field);
            }
        }

        document.body.appendChild(form);
        form.submit(); 
        */
        console.log(window.BitFire);
        if (window.fetch) {
            let params = {};
            params.method = "POST";
            params.mode = "same-origin";
            params.credentials = "same-origin";
            params.redirect = "follow";
            params.body = JSON.stringify(data);
            fetch(window.BitFire['U'], params);
        }

        /*
        if (navigator.sendBeacon && window.BitFire) {
            let data = new FormData();
            data.append('fingerprint', window.BitFire['F1']);
            data.append('fingerprint2', window.BitFire['F2']);
            data.append('browser', window.BitFire['B']);
            data.append('type', 'verify');
            data.append('style', 'bitfire');
            data.append('ver', window.BitFire['V']);
            navigator.sendBeacon("https://bitfire.co/ray.php", data);
        }
        */
    }
};

})();