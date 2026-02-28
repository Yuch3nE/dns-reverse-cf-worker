export default {
  async fetch(request, env) {
    let currentDoH = 'cloudflare-dns.com';
    let currentDohPath = 'dns-query';

    if (env.DOH) {
      currentDoH = env.DOH;
      const match = currentDoH.match(/:\/\/([^/]+)/);
      if (match) currentDoH = match[1];
    }
    // Strict separation: PATH is for routing, TOKEN is for auth.
    currentDohPath = env.PATH || currentDohPath;
    if (currentDohPath.includes('/')) currentDohPath = currentDohPath.split('/')[1];

    const secureToken = env.TOKEN || null;

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

    // Global Strict Access Control
    if (secureToken) {
      const urlToken = url.searchParams.get('token');
      const cookieHeader = request.headers.get('Cookie') || '';
      const hasCookie = cookieHeader.includes(`auth_token=${secureToken}`);
      const authHeader = request.headers.get('Authorization') || '';
      const hasAuthHeader = authHeader === `Bearer ${secureToken}` || authHeader === secureToken;

      const isAuthorized = (urlToken === secureToken) || hasCookie || hasAuthHeader;

      if (!isAuthorized) {
        return new Response('401 Unauthorized: Invalid or missing token', {
          status: 401,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }

      if (urlToken === secureToken && isBrowserDirect && path === '/') {
        // Return redirect with cookie to clean up the URL
        const redirectUrl = new URL(url);
        redirectUrl.searchParams.delete('token');
        return new Response(null, {
          status: 302,
          headers: {
            'Location': redirectUrl.toString() || '/',
            'Set-Cookie': `auth_token=${secureToken}; Path=/; HttpOnly; Max-Age=2592000; SameSite=Strict`
          }
        });
      }
    }

    // DoH endpoint
    if (path === `/${currentDohPath}` && !isBrowserDirect) {
      return handleDohRequest(request, currentDoH);
    }

    // Custom DoH via path: /1.1.1.1/dns-query or /dns.google/dns-query
    const pathParts = path.split('/').filter(Boolean);
    if (!isBrowserDirect && pathParts.length > 1 && pathParts[pathParts.length - 1] === currentDohPath) {
      let customDoh = path.substring(1, path.lastIndexOf(`/${currentDohPath}`));
      if (customDoh.includes(':/') && !customDoh.includes('://')) {
        customDoh = customDoh.replace(':/', '://');
      }
      return handleDohRequest(request, customDoh, currentDoH);
    }

    // IP geolocation proxy
    if (path === '/ip-info') {
      return handleIpInfo(request, env, url);
    }

    // DNS query via query params (web UI backend logic)
    if (url.searchParams.has('doh')) {
      return handleWebDnsQuery(request, url, currentDoH, currentDohPath);
    }

    if (env.URL302) return Response.redirect(env.URL302, 302);
    if (env.URL) {
      if (env.URL.toString().toLowerCase() === 'nginx') {
        return new Response(NGINX_HTML, { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
      }
      return proxyUrl(env.URL, url);
    }

    return new Response(renderHtml(currentDoH, currentDohPath, secureToken), { headers: { 'content-type': 'text/html;charset=UTF-8' } });
  }
};

// ─── IP Info Handler ───────────────────────────────────────────────
function handleIpInfo(request, env, url) {
  const CORS_JSON = { 'content-type': 'application/json;charset=UTF-8', 'Access-Control-Allow-Origin': '*' };

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
async function handleWebDnsQuery(request, url, defaultDoH, defaultPath) {
  const JSON_HDR = { 'content-type': 'application/json;charset=UTF-8', 'Access-Control-Allow-Origin': '*' };

  const domain = url.searchParams.get('domain') || url.searchParams.get('name') || 'www.google.com';
  const doh = url.searchParams.get('doh') || `https://${defaultDoH}/dns-query`;
  const type = url.searchParams.get('type') || 'all';

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
async function handleDohRequest(request, targetDoh, defaultDoH) {
  const { method, headers, body } = request;
  const UA = headers.get('User-Agent') || 'DoH Client';
  const url = new URL(request.url);
  const { searchParams } = url;

  if (!targetDoh) targetDoh = defaultDoH;
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
function renderHtml(currentDoH, currentDohPath, secureToken) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DNS-over-HTTPS Resolver</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
<link rel="icon" href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg" type="image/x-icon">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
body { font-family: 'Inter', system-ui, -apple-system, sans-serif; min-height: 100vh; margin: 0; padding: 40px 20px; color: #fff; background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%); display: flex; flex-direction: column; align-items: center; box-sizing: border-box; }
.container { width: 100%; max-width: 850px; background: rgba(255, 255, 255, 0.03); border-radius: 24px; box-shadow: 0 30px 60px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.1); padding: 40px; backdrop-filter: blur(20px) saturate(150%); -webkit-backdrop-filter: blur(20px) saturate(150%); border: 1px solid rgba(255, 255, 255, 0.08); }
h1 { background: linear-gradient(to right, #38bdf8, #818cf8); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; text-align: center; margin-bottom: 30px; font-size: 2.2rem; letter-spacing: -0.5px; }
.hero-section { text-align: center; margin-bottom: 40px; }
.hero-subtitle { color: rgba(255, 255, 255, 0.6); font-size: 1.1rem; margin-bottom: 30px; }
.search-box { position: relative; max-width: 600px; margin: 0 auto; display: flex; background: rgba(0, 0, 0, 0.2); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 20px; padding: 8px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); transition: all 0.3s ease; }
.search-box:focus-within { border-color: rgba(56, 189, 248, 0.5); box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.1), 0 10px 30px rgba(0, 0, 0, 0.3); background: rgba(0, 0, 0, 0.3); }
.search-input { flex-grow: 1; background: transparent; border: none; color: #fff; font-size: 1.1rem; padding: 12px 20px; outline: none; }
.search-input::placeholder { color: rgba(255, 255, 255, 0.3); }
.input-wrapper { position: relative; flex-grow: 1; display: flex; }
.clear-input-btn { position: absolute; right: 15px; top: 50%; transform: translateY(-50%); background: transparent; border: none; color: rgba(255, 255, 255, 0.3); cursor: pointer; padding: 5px; display: flex; align-items: center; transition: all 0.2s ease; border-radius: 50%; }
.clear-input-btn:hover { color: #f87171; background: rgba(255, 255, 255, 0.05); }
.search-btn { background: linear-gradient(135deg, #38bdf8 0%, #3b82f6 100%); border: none; border-radius: 14px; padding: 0 30px; font-weight: 600; font-size: 1.05rem; color: #fff; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(56, 189, 248, 0.3); }
.search-btn:hover { transform: translateY(-1px); box-shadow: 0 8px 25px rgba(56, 189, 248, 0.4); background: linear-gradient(135deg, #7dd3fc 0%, #60a5fa 100%); }
.settings-toggle { display: inline-flex; align-items: center; gap: 6px; color: rgba(255, 255, 255, 0.5); font-size: 0.9rem; cursor: pointer; margin-top: 20px; transition: color 0.2s ease; background: none; border: none; }
.settings-toggle:hover { color: #38bdf8; }
.advanced-settings { display: none; max-width: 600px; margin: 20px auto 0; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; padding: 20px; text-align: left; animation: slideDown 0.3s ease forwards; }
.advanced-settings.show { display: block; }
@keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.form-label { font-weight: 500; margin-bottom: 8px; color: rgba(255, 255, 255, 0.7); font-size: 0.95rem; }
.form-select, .form-control { background: rgba(0, 0, 0, 0.2); border: 1px solid rgba(255, 255, 255, 0.1); color: #fff; border-radius: 12px; padding: 12px 16px; transition: all 0.3s ease; }
.form-control:focus { background: rgba(0, 0, 0, 0.3); border-color: rgba(56, 189, 248, 0.5); box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.1); color: #fff; }
.form-control::placeholder { color: rgba(255, 255, 255, 0.3); }
.form-control:read-only { background: rgba(255, 255, 255, 0.02); color: rgba(255, 255, 255, 0.5); }
.btn-primary { background: linear-gradient(135deg, #38bdf8 0%, #3b82f6 100%); border: none; border-radius: 12px; padding: 12px 24px; font-weight: 600; color: #fff; box-shadow: 0 4px 15px rgba(56, 189, 248, 0.3); transition: all 0.3s ease; }
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(56, 189, 248, 0.4); background: linear-gradient(135deg, #7dd3fc 0%, #60a5fa 100%); }
.btn-outline-secondary, .btn-outline-primary { background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.08); color: rgba(255, 255, 255, 0.7); border-radius: 10px; font-weight: 500; font-size: 0.9rem; padding: 8px 16px; transition: all 0.3s ease; }
.btn-outline-secondary:hover, .btn-outline-primary:hover { background: rgba(255, 255, 255, 0.06); color: #fff; border-color: rgba(255, 255, 255, 0.15); transform: translateY(-1px); }
.results-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding: 0 10px; }
.results-title { font-size: 1.25rem; font-weight: 600; color: rgba(255, 255, 255, 0.9); }
pre { background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.05); padding: 20px; border-radius: 12px; color: #cbd5e1; font-family: Consolas, Monaco, 'Andale Mono', monospace; font-size: 14px; max-height: 400px; overflow: auto; }
pre::-webkit-scrollbar { width: 8px; height: 8px; }
pre::-webkit-scrollbar-track { background: transparent; }
pre::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 4px; }
pre::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.2); }
.nav-tabs { border-bottom: 2px solid rgba(255, 255, 255, 0.05); margin-bottom: 24px; display: flex; gap: 4px; padding-bottom: 0; }
.nav-tabs .nav-link { color: rgba(255, 255, 255, 0.4); background: transparent; border: none; padding: 12px 24px; font-weight: 500; border-radius: 12px 12px 0 0; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; letter-spacing: 0.5px; }
.nav-tabs .nav-link:hover { color: rgba(255, 255, 255, 0.8); background: rgba(255, 255, 255, 0.02); }
.nav-tabs .nav-link::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 100%; height: 2px; background: linear-gradient(90deg, transparent, #38bdf8, transparent); transform: scaleX(0); transition: transform 0.3s ease; }
.nav-tabs .nav-link.active { background: linear-gradient(180deg, rgba(56, 189, 248, 0.05) 0%, transparent 100%); color: #38bdf8; border: none; text-shadow: 0 0 10px rgba(56, 189, 248, 0.3); }
.nav-tabs .nav-link.active::after { transform: scaleX(1); }
.tab-content { background: transparent; border: none; padding: 0; position: relative; z-index: 1; }
.result-summary { background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); padding: 16px 20px; border-radius: 16px; color: #fff; margin-bottom: 24px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); }
.ip-record { padding: 14px 20px; margin-bottom: 12px; border-radius: 14px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.04); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02); }
.ip-record:hover { background: rgba(255, 255, 255, 0.05); border-color: rgba(56, 189, 248, 0.3); transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.05); }
.ip-address { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-weight: 600; min-width: 130px; color: #f8fafc; cursor: pointer; position: relative; transition: all 0.2s ease; display: inline-block; font-size: 15px; letter-spacing: 0.5px; }
.ip-address:hover { color: #7dd3fc; text-shadow: 0 0 8px rgba(125, 211, 252, 0.4); }
.ip-address:after { content: ''; position: absolute; left: 100%; top: 0; opacity: 0; white-space: nowrap; font-size: 13px; color: #4ade80; transition: opacity 0.3s ease; font-family: 'Inter', sans-serif; font-weight: 500; margin-left: 10px; }
.ip-address.copied:after { content: '✓ 复制成功'; opacity: 1; text-shadow: 0 0 10px rgba(74, 222, 128, 0.4); }
.geo-info { margin: 0 12px; font-size: 0.85em; flex-grow: 1; text-align: center; color: rgba(255, 255, 255, 0.5); font-weight: 500; }
.geo-country { background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08); color: #e2e8f0; font-weight: 500; padding: 4px 10px; border-radius: 8px; display: inline-block; box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02); }
.geo-as { background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); color: #7dd3fc; padding: 4px 10px; border-radius: 8px; margin-left: 6px; display: inline-block; box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05); }
.geo-blocked { color: #fff; background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%); padding: 4px 12px; border-radius: 8px; font-weight: 600; display: inline-block; animation: pulse-red 2s infinite; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4); border: 1px solid rgba(255, 255, 255, 0.2); }
@keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.6); } 70% { box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); } 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); } }
.badge { margin-left: 8px; font-size: 11px; vertical-align: middle; padding: 5px 10px; border-radius: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.bg-success { background: rgba(34, 197, 94, 0.1) !important; color: #4ade80 !important; border: 1px solid rgba(34, 197, 94, 0.2); box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05); }
.bg-info { background: rgba(56, 189, 248, 0.1) !important; color: #38bdf8 !important; border: 1px solid rgba(56, 189, 248, 0.2); box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05); }
.bg-warning { background: rgba(234, 179, 8, 0.1) !important; color: #facc15 !important; border: 1px solid rgba(234, 179, 8, 0.2); box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05); }
.bg-secondary { background: rgba(148, 163, 184, 0.1) !important; color: #94a3b8 !important; border: 1px solid rgba(148, 163, 184, 0.2); box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05); }
.ttl-info { min-width: 80px; text-align: right; color: rgba(255, 255, 255, 0.75); font-size: 13px; font-weight: 500; letter-spacing: 0.5px; }
.loading { display: none; text-align: center; padding: 30px 0; color: rgba(255, 255, 255, 0.7); }
.loading-spinner { border: 4px solid rgba(255, 255, 255, 0.1); border-left: 4px solid #38bdf8; border-radius: 50%; width: 36px; height: 36px; animation: spin 1s linear infinite; margin: 0 auto 15px; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
.error-message { color: #f87171; margin-top: 10px; }
.beian-info { text-align: center; font-size: 13px; color: rgba(255, 255, 255, 0.6); margin-top: 30px; }
.copy-link { color: #38bdf8; text-decoration: none; border-bottom: 1px dashed rgba(56, 189, 248, 0.5); padding-bottom: 2px; cursor: pointer; position: relative; transition: all 0.3s; }
.copy-link:hover { color: #7dd3fc; border-bottom: 1px solid #7dd3fc; }
.copy-link:after { content: ''; position: absolute; top: 0; right: -65px; opacity: 0; white-space: nowrap; color: #38bdf8; font-size: 12px; transition: opacity 0.3s ease; }
.copy-link.copied:after { content: '✓ 已复制'; opacity: 1; }
.github-corner svg { fill: rgba(255, 255, 255, 0.1); color: #fff; position: absolute; top: 0; right: 0; border: 0; width: 80px; height: 80px; transition: fill 0.3s; }
.github-corner:hover svg { fill: rgba(255, 255, 255, 0.2); }
.github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
@keyframes octocat-wave { 0%, 100% { transform: rotate(0); } 20%, 60% { transform: rotate(-25deg); } 40%, 80% { transform: rotate(10deg); } }
@media (max-width: 576px) { .container { padding: 20px; border-radius: 16px; } .github-corner:hover .octo-arm { animation: none; } .github-corner .octo-arm { animation: octocat-wave 560ms ease-in-out; } }
.toast-msg { visibility: hidden; min-width: 200px; background-color: rgba(30, 41, 59, 0.9); backdrop-filter: blur(10px); color: #fff; text-align: center; border-radius: 8px; padding: 12px 24px; position: fixed; z-index: 1000; left: 50%; bottom: 30px; transform: translateX(-50%); font-size: 15px; border: 1px solid rgba(56, 189, 248, 0.4); box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4); transition: opacity 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275), bottom 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275); opacity: 0; }
.toast-msg.show { visibility: visible; bottom: 50px; opacity: 1; }
</style>
</head>
<body>
<a href="https://github.com/cmliu/CF-Workers-DoH" target="_blank" class="github-corner" aria-label="View source on Github">
<svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin:130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
</a>
<div class="container">
  <div class="hero-section">
    <h1 class="mb-2">DNS 解析引擎</h1>
    <div class="hero-subtitle">基于 Cloudflare 安全网络的极速 DoH 查询</div>
    <form id="resolveForm">
      <div class="search-box">
        <div class="input-wrapper">
          <input type="text" id="domain" class="search-input" value="www.google.com" placeholder="输入你想查询的域名，如 example.com" autocomplete="off" spellcheck="false" style="padding-right: 45px;">
          <button type="button" class="clear-input-btn" id="clearBtn" title="清空输入">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
          </button>
        </div>
        <button type="submit" class="search-btn">开始解析</button>
      </div>
      <button type="button" class="settings-toggle" id="toggleSettingsBtn">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
        高级设置
      </button>

      <div class="advanced-settings" id="advancedSettings">
        <div class="mb-3">
          <label for="customDoh" class="form-label">上游 DoH 地址配置 (HTTPS)</label>
          <input type="text" id="customDoh" class="form-control" readonly>
        </div>
        <div class="d-flex justify-content-end">
          <button type="button" class="btn btn-outline-primary" id="getJsonBtn">在新标签页中查看 JSON 数据</button>
        </div>
      </div>
    </form>
  </div>

  <div id="loading" class="loading"><div class="loading-spinner"></div><p>正在加速向超级节点发送查询请求...</p></div>

  <div id="resultContainer" style="display:none;">
    <div class="results-header">
      <div class="results-title">解析结果记录</div>
      <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display:none;">全选复制</button>
    </div>
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
<div class="beian-info">
<p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">https://${currentDoH}/${currentDohPath}</span></strong><br>基于 Cloudflare Workers 上游 <span id="upstreamDomainDisplay">${currentDoH}</span> 的 DoH (DNS over HTTPS) 解析服务</p>
</div>
</div>
<div id="toast" class="toast-msg"></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
const currentHost=location.host,currentProtocol=location.protocol;
const currentDohPath=${JSON.stringify(currentDohPath)};
const currentDoH=${JSON.stringify(currentDoH)};
const secureToken=${JSON.stringify(secureToken)};
const currentDohUrl=currentProtocol+'//'+currentHost+'/'+currentDohPath;
const defaultDnsDoh='https://' + currentDoH + '/' + currentDohPath;
let activeDohUrl=currentDohUrl;

const BLOCKED_IPV4=['104.21.16.1','104.21.32.1','104.21.48.1','104.21.64.1','104.21.80.1','104.21.96.1','104.21.112.1'];
const BLOCKED_IPV6=['2606:4700:3030::6815:1001','2606:4700:3030::6815:3001','2606:4700:3030::6815:7001','2606:4700:3030::6815:5001'];
const isBlockedIP=ip=>BLOCKED_IPV4.includes(ip)||BLOCKED_IPV6.includes(ip);

document.getElementById('toggleSettingsBtn').addEventListener('click', function() {
  const panel = document.getElementById('advancedSettings');
  panel.classList.toggle('show');
});

document.getElementById('clearBtn').addEventListener('click',()=>{const d=document.getElementById('domain');d.value='';d.focus()});

document.getElementById('copyBtn').addEventListener('click',function(){
  navigator.clipboard.writeText(document.getElementById('result').textContent).then(()=>{
    showToast('✓ 全部记录已复制到剪贴板');
    const o=this.textContent;this.textContent='已复制';setTimeout(()=>{this.textContent=o},2000);
  }).catch(e=>console.error('Copy failed:',e));
});

function formatTTL(s){s=+s;if(s<60)return s+'秒';if(s<3600)return(s/60|0)+'分钟';if(s<86400)return(s/3600|0)+'小时';return(s/86400|0)+'天'}

function showToast(msg){
  const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
  if(t.timeoutId) clearTimeout(t.timeoutId);
  t.timeoutId=setTimeout(()=>t.classList.remove('show'),2500);
}

async function queryIpGeoInfo(ip){
  try{
    const url = \`./ip-info?ip=\${ip}\` + (secureToken ? \`&token=\${encodeURIComponent(secureToken)}\` : '');
    const r=await fetch(url);
    if(!r.ok)throw new Error(r.status);
    return r.json();
  }
  catch(e){console.error('IP geo query failed:',e);return null}
}

function handleCopyClick(el,text){
  navigator.clipboard.writeText(text).then(()=>{
    showToast('✓ 已复制 ' + text);
    el.classList.add('copied');setTimeout(()=>el.classList.remove('copied'),2000)
  }).catch(e=>console.error('Copy failed:',e));
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
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="badge bg-success">CNAME</span><span class="ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
    }else if(r.type===aType){
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="geo-info geo-loading">正在获取位置信息...</span><span class="ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
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
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="badge bg-info">NS</span><span class="ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
    }else if(r.type===6){
      const p=r.data.split(' ');let email=p[1].replace('.','@');if(email.endsWith('.'))email=email.slice(0,-1);
      div.innerHTML='<div class="d-flex justify-content-between align-items-center mb-2"><span class="ip-address" data-copy="'+r.name+'">'+r.name+'</span><span class="badge bg-warning">SOA</span><span class="ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div><div class="ps-3 small"><div><strong>主 NS:</strong> <span class="ip-address" data-copy="'+p[0]+'">'+p[0]+'</span></div><div><strong>管理邮箱:</strong> <span class="ip-address" data-copy="'+email+'">'+email+'</span></div><div><strong>序列号:</strong> '+p[2]+'</div><div><strong>刷新间隔:</strong> '+formatTTL(p[3])+'</div><div><strong>重试间隔:</strong> '+formatTTL(p[4])+'</div><div><strong>过期时间:</strong> '+formatTTL(p[5])+'</div><div><strong>最小 TTL:</strong> '+formatTTL(p[6])+'</div></div>';
    }else{
      div.innerHTML='<div class="d-flex justify-content-between align-items-center"><span class="ip-address" data-copy="'+r.data+'">'+r.data+'</span><span class="badge bg-secondary">类型: '+r.type+'</span><span class="ttl-info">TTL: '+formatTTL(r.TTL)+'</span></div>';
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
    const url = \`?doh=\${encodeURIComponent(doh)}&domain=\${encodeURIComponent(domain)}&type=all\` + (secureToken ? \`&token=\${encodeURIComponent(secureToken)}\` : '');
    const r=await fetch(url);
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

  let displayPath='/'+currentDohPath,upstreamHost='${currentDoH}';
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

  if(dohUrlDisplay){
    dohUrlDisplay.addEventListener('click',function(){
      navigator.clipboard.writeText(workerFullUrl).then(()=>{
        showToast('✓ DoH 地址已复制');
        dohUrlDisplay.classList.add('copied');setTimeout(()=>dohUrlDisplay.classList.remove('copied'),2000)
      }).catch(e=>console.error('Copy failed:',e));
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