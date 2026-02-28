let DoH = 'cloudflare-dns.com';
let dohPath = 'dns-query';

export default {
  async fetch(request, env) {
    if (env.DOH) {
      DoH = env.DOH;
      const match = DoH.match(/:\/\/([^/]+)/);
      if (match) DoH = match[1];
    }
    dohPath = env.PATH || env.TOKEN || dohPath;
    if (dohPath.includes('/')) dohPath = dohPath.split('/')[1];

    const url = new URL(request.url);
    const path = url.pathname;

    // OPTIONS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    const isBrowserDirect = request.method === 'GET' && !url.search && (request.headers.get('Accept') || '').includes('text/html');

    // DoH endpoint
    if (path === `/${dohPath}` && !isBrowserDirect) {
      return handleDohRequest(request, DoH);
    }

    // Custom DoH via path: /1.1.1.1/dns-query or /dns.google/dns-query
    const pathParts = path.split('/').filter(Boolean);
    if (!isBrowserDirect && pathParts.length > 1 && pathParts[pathParts.length - 1] === dohPath) {
      let customDoh = path.substring(1, path.lastIndexOf(`/${dohPath}`));
      if (customDoh.includes(':/') && !customDoh.includes('://')) {
        customDoh = customDoh.replace(':/', '://');
      }
      return handleDohRequest(request, customDoh);
    }

    // IP geolocation proxy
    if (path === '/ip-info') {
      return handleIpInfo(request, env, url);
    }

    // DNS query via query params (web UI)
    if (url.searchParams.has('doh')) {
      return handleWebDnsQuery(url, DoH, dohPath);
    }

    if (env.URL302) return Response.redirect(env.URL302, 302);
    if (env.URL) {
      if (env.URL.toString().toLowerCase() === 'nginx') {
        return new Response(NGINX_HTML, { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
      }
      return proxyUrl(env.URL, url);
    }
    return new Response(renderHtml(), { headers: { 'content-type': 'text/html;charset=UTF-8' } });
  }
};

// ─── IP Info Handler ───────────────────────────────────────────────
function handleIpInfo(request, env, url) {
  const CORS_JSON = { 'content-type': 'application/json;charset=UTF-8', 'Access-Control-Allow-Origin': '*' };

  if (env.TOKEN) {
    const token = url.searchParams.get('token');
    if (token !== env.TOKEN) {
      return new Response(JSON.stringify({ status: 'error', message: 'Token不正确', code: 'AUTH_FAILED' }), { status: 403, headers: CORS_JSON });
    }
  }

  const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
  if (!ip) {
    return new Response(JSON.stringify({ status: 'error', message: 'IP参数未提供', code: 'MISSING_PARAMETER' }), { status: 400, headers: CORS_JSON });
  }

  return fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`)
    .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then(data => new Response(JSON.stringify(data), { headers: CORS_JSON }))
    .catch(err => new Response(JSON.stringify({ status: 'error', message: `IP查询失败: ${err.message}`, code: 'API_REQUEST_FAILED' }), { status: 500, headers: CORS_JSON }));
}

// ─── DNS Query (single type, JSON format) ──────────────────────────
async function queryDns(dohServer, domain, type) {
  let endpoint = dohServer;
  if (endpoint.endsWith('/dns-query')) {
    endpoint = endpoint.slice(0, -10) + '/resolve';
  } else if (!endpoint.endsWith('/resolve') && !endpoint.includes('?')) {
    endpoint += endpoint.endsWith('/') ? 'resolve' : '/resolve';
  }

  const response = await fetch(`${endpoint}?name=${encodeURIComponent(domain)}&type=${type}`, {
    headers: { 'Accept': 'application/dns-json' }
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`DoH error (${response.status}): ${errText.substring(0, 200)}`);
  }

  const ct = response.headers.get('content-type') || '';
  if (ct.includes('json') || ct.includes('dns-json')) {
    return response.json();
  }
  const text = await response.text();
  try { return JSON.parse(text); }
  catch { throw new Error(`Cannot parse response as JSON: ${text.substring(0, 100)}`); }
}

// ─── Combine A/AAAA/NS Results ────────────────────────────────────
function combineDnsResults(ipv4Result, ipv6Result, nsResult) {
  const nsRecords = [];
  if (nsResult.Answer) nsRecords.push(...nsResult.Answer.filter(r => r.type === 2));
  if (nsResult.Authority) {
    const authNs = nsResult.Authority.filter(r => r.type === 2 || r.type === 6);
    nsRecords.push(...authNs);
  }

  const questions = [ipv4Result.Question, ipv6Result.Question, nsResult.Question]
    .filter(Boolean).flat();

  return {
    Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
    TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
    RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
    RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
    AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
    CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
    Question: questions,
    Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || []), ...nsRecords],
    ipv4: { records: ipv4Result.Answer || [] },
    ipv6: { records: ipv6Result.Answer || [] },
    ns: { records: nsRecords }
  };
}

// ─── Web UI DNS Query Handler ─────────────────────────────────────
async function handleWebDnsQuery(url, defaultDoH, defaultPath) {
  const domain = url.searchParams.get('domain') || url.searchParams.get('name') || 'www.google.com';
  const doh = url.searchParams.get('doh') || `https://${defaultDoH}/dns-query`;
  const type = url.searchParams.get('type') || 'all';
  const JSON_HDR = { 'content-type': 'application/json;charset=UTF-8', 'Access-Control-Allow-Origin': '*' };

  // Determine upstream DoH
  let upstream = doh;
  if (doh.includes(url.host)) {
    upstream = `https://${defaultDoH}/dns-query`;
    try {
      const dohUrl = new URL(doh);
      const parts = dohUrl.pathname.split('/').filter(Boolean);
      if (parts.length > 1 && parts[parts.length - 1] === defaultPath) {
        let custom = dohUrl.pathname.substring(1, dohUrl.pathname.lastIndexOf(`/${defaultPath}`));
        if (custom.includes(':/') && !custom.includes('://')) custom = custom.replace(':/', '://');
        if (!custom.startsWith('http')) custom = `https://${custom}`;
        upstream = custom.endsWith('/dns-query') ? custom : custom + '/dns-query';
      }
    } catch { }
  }

  try {
    if (type === 'all') {
      const [a, aaaa, ns] = await Promise.all([
        queryDns(upstream, domain, 'A'),
        queryDns(upstream, domain, 'AAAA'),
        queryDns(upstream, domain, 'NS')
      ]);
      return new Response(JSON.stringify(combineDnsResults(a, aaaa, ns)), { headers: JSON_HDR });
    }
    const result = await queryDns(upstream, domain, type);
    return new Response(JSON.stringify(result), { headers: JSON_HDR });
  } catch (err) {
    return new Response(JSON.stringify({ error: `DNS查询失败: ${err.message}`, doh, domain }), { status: 500, headers: JSON_HDR });
  }
}

// ─── DoH Request Proxy ────────────────────────────────────────────
async function handleDohRequest(request, targetDoh) {
  const { method, headers, body } = request;
  const UA = headers.get('User-Agent') || 'DoH Client';
  const url = new URL(request.url);
  const { searchParams } = url;

  if (!targetDoh) targetDoh = DoH;
  // Normalize target DoH URL
  let baseDoh;
  if (targetDoh.startsWith('http://') || targetDoh.startsWith('https://')) {
    baseDoh = targetDoh.replace(/\/+$/, '');
  } else {
    baseDoh = `https://${targetDoh}`;
  }
  const currentDnsDoH = baseDoh.endsWith('/dns-query') ? baseDoh : baseDoh + '/dns-query';
  const currentJsonDoH = baseDoh.endsWith('/dns-query') ? baseDoh.replace('/dns-query', '/resolve') : baseDoh + '/resolve';

  try {
    if (method === 'GET' && !url.search) {
      return new Response('Bad Request', { status: 400, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
    }

    let response;
    if (method === 'GET' && searchParams.has('name')) {
      const search = searchParams.has('type') ? url.search : url.search + '&type=A';
      response = await fetch(currentDnsDoH + search, { headers: { 'Accept': 'application/dns-json', 'User-Agent': UA } });
      if (!response.ok) {
        response = await fetch(currentJsonDoH + search, { headers: { 'Accept': 'application/dns-json', 'User-Agent': UA } });
      }
    } else if (method === 'GET') {
      response = await fetch(currentDnsDoH + url.search, { headers: { 'Accept': 'application/dns-message', 'User-Agent': UA } });
    } else if (method === 'POST') {
      response = await fetch(currentDnsDoH, {
        method: 'POST',
        headers: { 'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message', 'User-Agent': UA },
        body
      });
    } else {
      return new Response('Unsupported request format', { status: 400, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
    }

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`DoH error (${response.status}): ${errText.substring(0, 200)}`);
    }

    const rHeaders = new Headers(response.headers);
    rHeaders.set('Access-Control-Allow-Origin', '*');
    if (method === 'GET' && searchParams.has('name')) {
      rHeaders.set('Content-Type', 'application/json');
    }

    return new Response(response.body, { status: response.status, headers: rHeaders });
  } catch (error) {
    return new Response(JSON.stringify({ error: `DoH error: ${error.message}` }), {
      status: 500, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

// ─── HTML Page ─────────────────────────────────────────────────────
function renderHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DNS-over-HTTPS Resolver</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
<link rel="icon" href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg" type="image/x-icon">
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;min-height:100vh;padding:0;margin:0;line-height:1.6;background:url('https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5B5shLB8bSKIyB9NJ6R1jz/87e7617be2c61603d46003cb3f1bd382/Hero-globe-bg-takeover-xxl.png'),linear-gradient(135deg,rgba(253,101,60,.85) 0%,rgba(251,152,30,.85) 100%);background-size:cover;background-position:center;background-repeat:no-repeat;background-attachment:fixed;padding:30px 20px;box-sizing:border-box}
.container{width:100%;max-width:800px;margin:20px auto;background-color:rgba(255,255,255,.65);border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.15);padding:30px;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,.4)}
h1{background-image:linear-gradient(to right,rgb(249,171,76),rgb(252,103,60));color:rgb(252,103,60);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;font-weight:600;text-shadow:none}
.card{margin-bottom:20px;border:none;box-shadow:0 2px 10px rgba(0,0,0,.05);background-color:rgba(255,255,255,.8);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}
.card-header{background-color:rgba(255,242,235,.9);font-weight:600;padding:12px 20px;border-bottom:none}
.form-label{font-weight:500;margin-bottom:8px;color:rgb(70,50,40)}
.form-select,.form-control{border-radius:6px;padding:10px;border:1px solid rgba(253,101,60,.3);background-color:rgba(255,255,255,.9)}
.btn-primary{background-color:rgb(253,101,60);border:none;border-radius:6px;padding:10px 20px;font-weight:500;transition:all .2s ease}
.btn-primary:hover{background-color:rgb(230,90,50);transform:translateY(-1px)}
pre{background-color:rgba(255,245,240,.9);padding:15px;border-radius:6px;border:1px solid rgba(253,101,60,.2);white-space:pre-wrap;word-break:break-all;font-family:Consolas,Monaco,'Andale Mono',monospace;font-size:14px;max-height:400px;overflow:auto}
.loading{display:none;text-align:center;padding:20px 0}
.loading-spinner{border:4px solid rgba(0,0,0,.1);border-left:4px solid rgb(253,101,60);border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:0 auto 10px}
.badge{margin-left:5px;font-size:11px;vertical-align:middle}
@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
.footer{margin-top:30px;text-align:center;color:rgba(255,255,255,.9);font-size:14px}
.beian-info{text-align:center;font-size:13px}
.beian-info a{color:rgb(253,101,60);text-decoration:none;border-bottom:1px dashed rgb(253,101,60);padding-bottom:2px}
.beian-info a:hover{border-bottom-style:solid}
.error-message{color:#e63e00;margin-top:10px}
.success-message{color:#e67e22}
.nav-tabs .nav-link{border-top-left-radius:6px;border-top-right-radius:6px;padding:8px 16px;font-weight:500;color:rgb(150,80,50)}
.nav-tabs .nav-link.active{background-color:rgba(255,245,240,.8);border-bottom-color:rgba(255,245,240,.8);color:rgb(253,101,60)}
.tab-content{background-color:rgba(255,245,240,.8);border-radius:0 0 6px 6px;padding:15px;border:1px solid rgba(253,101,60,.2);border-top:none}
.ip-record{padding:5px 10px;margin-bottom:5px;border-radius:4px;background-color:rgba(255,255,255,.9);border:1px solid rgba(253,101,60,.15)}
.ip-record:hover{background-color:rgba(255,235,225,.9)}
.ip-address{font-family:monospace;font-weight:600;min-width:130px;color:rgb(80,60,50);cursor:pointer;position:relative;transition:color .2s ease;display:inline-block}
.ip-address:hover{color:rgb(253,101,60)}
.ip-address:after{content:'';position:absolute;left:100%;top:0;opacity:0;white-space:nowrap;font-size:12px;color:rgb(253,101,60);transition:opacity .3s ease;font-family:'Segoe UI',sans-serif;font-weight:normal}
.ip-address.copied:after{content:'✓ 已复制';opacity:1}
.result-summary{margin-bottom:15px;padding:10px;background-color:rgba(255,235,225,.8);border-radius:6px}
.result-tabs{margin-bottom:20px}
.geo-info{margin:0 10px;font-size:.85em;flex-grow:1;text-align:center}
.geo-country{color:rgb(230,90,50);font-weight:500;padding:2px 6px;background-color:rgba(255,245,240,.8);border-radius:4px;display:inline-block}
.geo-as{color:rgb(253,101,60);padding:2px 6px;background-color:rgba(255,245,240,.8);border-radius:4px;margin-left:5px;display:inline-block}
.geo-blocked{color:#fff;background-color:#dc3545;padding:2px 8px;border-radius:4px;font-weight:600;display:inline-block;animation:pulse-red 2s infinite}
@keyframes pulse-red{0%{box-shadow:0 0 0 0 rgba(220,53,69,.7)}70%{box-shadow:0 0 0 10px rgba(220,53,69,0)}100%{box-shadow:0 0 0 0 rgba(220,53,69,0)}}
.geo-loading{color:rgb(150,100,80);font-style:italic}
.ttl-info{min-width:80px;text-align:right;color:rgb(180,90,60)}
.copy-link{color:rgb(253,101,60);text-decoration:none;border-bottom:1px dashed rgb(253,101,60);padding-bottom:2px;cursor:pointer;position:relative}
.copy-link:hover{border-bottom-style:solid}
.copy-link:after{content:'';position:absolute;top:0;right:-65px;opacity:0;white-space:nowrap;color:rgb(253,101,60);font-size:12px;transition:opacity .3s ease}
.copy-link.copied:after{content:'✓ 已复制';opacity:1}
.github-corner svg{fill:#fff;color:rgb(251,152,30);position:absolute;top:0;right:0;border:0;width:80px;height:80px}
.github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}
@keyframes octocat-wave{0%,100%{transform:rotate(0)}20%,60%{transform:rotate(-25deg)}40%,80%{transform:rotate(10deg)}}
@media(max-width:576px){.container{padding:20px}.github-corner:hover .octo-arm{animation:none}.github-corner .octo-arm{animation:octocat-wave 560ms ease-in-out}}
</style>
</head>
<body>
<a href="https://github.com/cmliu/CF-Workers-DoH" target="_blank" class="github-corner" aria-label="View source on Github">
<svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin:130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
</a>
<div class="container">
<h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
<div class="card">
<div class="card-header">DNS 查询设置</div>
<div class="card-body">
<form id="resolveForm">
<div id="customDohContainer" class="mb-3">
<label for="customDoh" class="form-label">当前使用的 DoH 地址:</label>
<input type="text" id="customDoh" class="form-control" readonly>
</div>
<div class="mb-3">
<label for="domain" class="form-label">待解析域名:</label>
<div class="input-group">
<input type="text" id="domain" class="form-control" value="www.google.com" placeholder="输入域名，如 example.com">
<button type="button" class="btn btn-outline-secondary" id="clearBtn">清除</button>
</div>
</div>
<div class="d-flex gap-2">
<button type="submit" class="btn btn-primary flex-grow-1">解析</button>
<button type="button" class="btn btn-outline-primary" id="getJsonBtn">Get Json</button>
</div>
</form>
</div>
</div>
<div class="card">
<div class="card-header d-flex justify-content-between align-items-center">
<span>解析结果</span>
<button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display:none;">复制结果</button>
</div>
<div class="card-body">
<div id="loading" class="loading"><div class="loading-spinner"></div><p>正在查询中，请稍候...</p></div>
<div id="resultContainer" style="display:none;">
<ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
<li class="nav-item" role="presentation"><button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button" role="tab">IPv4 地址</button></li>
<li class="nav-item" role="presentation"><button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button" role="tab">IPv6 地址</button></li>
<li class="nav-item" role="presentation"><button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button" role="tab">NS 记录</button></li>
<li class="nav-item" role="presentation"><button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button" role="tab">原始数据</button></li>
</ul>
<div class="tab-content" id="resultTabContent">
<div class="tab-pane fade show active" id="ipv4" role="tabpanel"><div class="result-summary" id="ipv4Summary"></div><div id="ipv4Records"></div></div>
<div class="tab-pane fade" id="ipv6" role="tabpanel"><div class="result-summary" id="ipv6Summary"></div><div id="ipv6Records"></div></div>
<div class="tab-pane fade" id="ns" role="tabpanel"><div class="result-summary" id="nsSummary"></div><div id="nsRecords"></div></div>
<div class="tab-pane fade" id="raw" role="tabpanel"><pre id="result">等待查询...</pre></div>
</div>
</div>
<div id="errorContainer" style="display:none;"><pre id="errorMessage" class="error-message"></pre></div>
</div>
</div>
<div class="beian-info">
<p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">https://<span id="currentDomain">...</span>/${dohPath}</span></strong><br>基于 Cloudflare Workers 上游 <span id="upstreamDomainDisplay">${DoH}</span> 的 DoH (DNS over HTTPS) 解析服务</p>
</div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
const currentHost=location.host,currentProtocol=location.protocol,currentDohPath='${dohPath}',currentDohUrl=currentProtocol+'//'+currentHost+'/'+currentDohPath,defaultDnsDoh='https://${DoH}/${dohPath}';
let activeDohUrl=currentDohUrl;

const BLOCKED_IPV4=['104.21.16.1','104.21.32.1','104.21.48.1','104.21.64.1','104.21.80.1','104.21.96.1','104.21.112.1'];
const BLOCKED_IPV6=['2606:4700:3030::6815:1001','2606:4700:3030::6815:3001','2606:4700:3030::6815:7001','2606:4700:3030::6815:5001'];
const isBlockedIP=ip=>BLOCKED_IPV4.includes(ip)||BLOCKED_IPV6.includes(ip);

document.getElementById('clearBtn').addEventListener('click',()=>{const d=document.getElementById('domain');d.value='';d.focus()});

document.getElementById('copyBtn').addEventListener('click',function(){
  navigator.clipboard.writeText(document.getElementById('result').textContent).then(()=>{
    const o=this.textContent;this.textContent='已复制';setTimeout(()=>{this.textContent=o},2000);
  }).catch(e=>console.error('Copy failed:',e));
});

function formatTTL(s){s=+s;if(s<60)return s+'秒';if(s<3600)return(s/60|0)+'分钟';if(s<86400)return(s/3600|0)+'小时';return(s/86400|0)+'天'}

async function queryIpGeoInfo(ip){
  try{const r=await fetch(\`./ip-info?ip=\${ip}&token=${dohPath}\`);if(!r.ok)throw new Error(r.status);return r.json()}
  catch(e){console.error('IP geo query failed:',e);return null}
}

function handleCopyClick(el,text){
  navigator.clipboard.writeText(text).then(()=>{el.classList.add('copied');setTimeout(()=>el.classList.remove('copied'),2000)}).catch(e=>console.error('Copy failed:',e));
}

function bindCopy(container){
  container.querySelectorAll('.ip-address').forEach(el=>el.addEventListener('click',function(){handleCopyClick(this,this.dataset.copy)}));
}

function renderGeoInfo(geoSpan,ip){
  const blocked=isBlockedIP(ip);
  queryIpGeoInfo(ip).then(d=>{
    geoSpan.innerHTML='';geoSpan.classList.remove('geo-loading');
    if(blocked){
      geoSpan.innerHTML='<span class="geo-blocked">阻断IP</span>';
      if(d&&d.status==='success'&&d.as)geoSpan.innerHTML+='<span class="geo-as">'+d.as+'</span>';
    }else if(d&&d.status==='success'){
      geoSpan.innerHTML='<span class="geo-country">'+(d.country||'未知国家')+'</span><span class="geo-as">'+(d.as||'未知 AS')+'</span>';
    }else{geoSpan.textContent='位置信息获取失败'}
  }).catch(()=>{
    geoSpan.innerHTML='';geoSpan.classList.remove('geo-loading');
    if(blocked)geoSpan.innerHTML='<span class="geo-blocked">阻断IP</span>';
    else geoSpan.textContent='位置信息获取失败';
  });
}

function renderIpRecords(records,containerId,summaryId,aType){
  const container=document.getElementById(containerId),summary=document.getElementById(summaryId);
  container.innerHTML='';
  if(!records.length){summary.innerHTML='<strong>未找到 '+(aType===1?'IPv4':'IPv6')+' 记录</strong>';return}
  summary.innerHTML='<strong>找到 '+records.length+' 条 '+(aType===1?'IPv4':'IPv6')+' 记录</strong>';
  records.forEach(r=>{
    const div=document.createElement('div');div.className='ip-record';
    if(r.type===5){
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="badge bg-success">CNAME</span><span class="text-muted ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
    }else if(r.type===aType){
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="geo-info geo-loading">正在获取位置信息...</span><span class="text-muted ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
      container.appendChild(div);bindCopy(div);
      renderGeoInfo(div.querySelector('.geo-info'),r.data);return;
    }
    container.appendChild(div);bindCopy(div);
  });
}

function renderNsRecords(records){
  const container=document.getElementById('nsRecords'),summary=document.getElementById('nsSummary');
  container.innerHTML='';
  if(!records.length){summary.innerHTML='<strong>未找到 NS 记录</strong>';return}
  summary.innerHTML='<strong>找到 '+records.length+' 条名称服务器记录</strong>';
  records.forEach(r=>{
    const div=document.createElement('div');div.className='ip-record';
    if(r.type===2){
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="badge bg-info">NS</span><span class="text-muted ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
    }else if(r.type===6){
      const p=r.data.split(' ');let email=p[1].replace('.','@');if(email.endsWith('.'))email=email.slice(0,-1);
      div.innerHTML='<div class="d-flex justify-content-between align-items-center mb-2"><span class="ip-address" data-copy="'+r.name+'">'+r.name+'</span><span class="badge bg-warning">SOA</span><span class="text-muted ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div><div class="ps-3 small"><div><strong>主 NS:</strong> <span class="ip-address" data-copy="'+p[0]+'">'+p[0]+'</span></div><div><strong>管理邮箱:</strong> <span class="ip-address" data-copy="'+email+'">'+email+'</span></div><div><strong>序列号:</strong> '+p[2]+'</div><div><strong>刷新间隔:</strong> '+formatTTL(p[3])+'</div><div><strong>重试间隔:</strong> '+formatTTL(p[4])+'</div><div><strong>过期时间:</strong> '+formatTTL(p[5])+'</div><div><strong>最小 TTL:</strong> '+formatTTL(p[6])+'</div></div>';
    }else{
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="badge bg-secondary">类型: '+r.type+'</span><span class="text-muted ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
    }
    container.appendChild(div);bindCopy(div);
  });
}

function displayRecords(data){
  document.getElementById('resultContainer').style.display='block';
  document.getElementById('errorContainer').style.display='none';
  document.getElementById('result').textContent=JSON.stringify(data,null,2);
  renderIpRecords(data.ipv4?.records||[],'ipv4Records','ipv4Summary',1);
  renderIpRecords(data.ipv6?.records||[],'ipv6Records','ipv6Summary',28);
  renderNsRecords(data.ns?.records||[]);
  document.getElementById('copyBtn').style.display='block';
}

function displayError(msg){
  document.getElementById('resultContainer').style.display='none';
  document.getElementById('errorContainer').style.display='block';
  document.getElementById('errorMessage').textContent=msg;
  document.getElementById('copyBtn').style.display='none';
}

document.getElementById('resolveForm').addEventListener('submit',async function(e){
  e.preventDefault();
  const doh=document.getElementById('customDoh').value;
  if(!doh){alert('获取 DoH 地址失败');return}
  const domain=document.getElementById('domain').value;
  if(!domain){alert('请输入需要解析的域名');return}
  document.getElementById('loading').style.display='block';
  document.getElementById('resultContainer').style.display='none';
  document.getElementById('errorContainer').style.display='none';
  document.getElementById('copyBtn').style.display='none';
  try{
    const r=await fetch(\`?doh=\${encodeURIComponent(doh)}&domain=\${encodeURIComponent(domain)}&type=all\`);
    if(!r.ok)throw new Error('HTTP '+r.status);
    const json=await r.json();
    json.error?displayError(json.error):displayRecords(json);
  }catch(e){displayError('查询失败: '+e.message)}
  finally{document.getElementById('loading').style.display='none'}
});

document.addEventListener('DOMContentLoaded',function(){
  const pathname=location.pathname,customDohInput=document.getElementById('customDoh');
  let pathDoh='';
  if(pathname&&pathname!=='/'&&pathname!=='/'+currentDohPath){
    pathDoh=pathname.substring(1);
    if(pathDoh.endsWith('/'+currentDohPath))pathDoh=pathDoh.substring(0,pathDoh.lastIndexOf('/'+currentDohPath));
    if(pathDoh){
      if(pathDoh.includes(':/')&&!pathDoh.includes('://'))pathDoh=pathDoh.replace(':/','://');
      let f=pathDoh;if(!f.startsWith('http'))f='https://'+f;if(f.endsWith('/'))f=f.slice(0,-1);
      if(!f.endsWith('/'+currentDohPath)&&!f.endsWith('/resolve'))f+='/'+currentDohPath;
      customDohInput.value=f;activeDohUrl=f;
    }else{customDohInput.value=defaultDnsDoh;activeDohUrl=defaultDnsDoh}
  }else{customDohInput.value=defaultDnsDoh;activeDohUrl=defaultDnsDoh}

  let displayPath='/'+currentDohPath,upstreamHost='${DoH}';
  if(activeDohUrl!==defaultDnsDoh){
    displayPath=pathname;
    if(!displayPath.endsWith('/'+currentDohPath))displayPath+=displayPath.endsWith('/')?'':'/'+currentDohPath+'';
    try{upstreamHost=new URL(activeDohUrl).host}catch{}
  }
  const workerFullUrl=currentProtocol+'//'+currentHost+displayPath;
  const dohUrlDisplay=document.getElementById('dohUrlDisplay');
  if(dohUrlDisplay)dohUrlDisplay.textContent=workerFullUrl;
  const upstreamDisplay=document.getElementById('upstreamDomainDisplay');
  if(upstreamDisplay)upstreamDisplay.textContent=upstreamHost;

  const lastDomain=localStorage.getItem('lastDomain');
  if(lastDomain)document.getElementById('domain').value=lastDomain;
  document.getElementById('domain').addEventListener('input',function(){localStorage.setItem('lastDomain',this.value)});
  document.getElementById('currentDomain').textContent=currentHost;

  if(dohUrlDisplay){
    dohUrlDisplay.addEventListener('click',function(){
      navigator.clipboard.writeText(workerFullUrl).then(()=>{dohUrlDisplay.classList.add('copied');setTimeout(()=>dohUrlDisplay.classList.remove('copied'),2000)}).catch(e=>console.error('Copy failed:',e));
    });
  }

  document.getElementById('getJsonBtn').addEventListener('click',function(){
    const d=document.getElementById('customDoh').value;if(!d){alert('获取 DoH 地址失败');return}
    const domain=document.getElementById('domain').value;if(!domain){alert('请输入需要解析的域名');return}
    const u=new URL(d);u.searchParams.set('name',domain);window.open(u.toString(),'_blank');
  });
});
</script>
</body>
</html>`;
}

// ─── URL Proxy ─────────────────────────────────────────────────────
async function proxyUrl(proxyTarget, targetUrl) {
  const urls = parseUrlList(proxyTarget);
  const fullUrl = urls[Math.floor(Math.random() * urls.length)];
  const parsed = new URL(fullUrl);
  const protocol = parsed.protocol.slice(0, -1) || 'https';
  const hostname = parsed.hostname;
  let pathname = parsed.pathname;
  if (pathname.endsWith('/')) pathname = pathname.slice(0, -1);
  pathname += targetUrl.pathname;
  const newUrl = `${protocol}://${hostname}${pathname}${parsed.search}`;

  const response = await fetch(newUrl);
  const newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });
  newResponse.headers.set('X-New-URL', newUrl);
  return newResponse;
}

function parseUrlList(content) {
  let cleaned = content.replace(/[\t|"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (cleaned.startsWith(',')) cleaned = cleaned.slice(1);
  if (cleaned.endsWith(',')) cleaned = cleaned.slice(0, -1);
  return cleaned.split(',');
}

// ─── Nginx Fake Page ───────────────────────────────────────────────
const NGINX_HTML = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>`;