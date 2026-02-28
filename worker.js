let Cloudflare_DoH = "cloudflare-dns.com";
let Google_DoH = "dns.google";
let DoH = Cloudflare_DoH;
const jsonDoH = `https://${DoH}/resolve`;
const dnsDoH = `https://${DoH}/dns-query`;
let DoH路径 = 'dns-query';
export default {
  async fetch(request, env) {
    if (env.DOH) {
      DoH = env.DOH;
      const match = DoH.match(/:\/\/([^\/]+)/);
      if (match) {
        DoH = match[1];
      }
    }
    DoH路径 = env.PATH || env.TOKEN || DoH路径;//DoH路径也单独设置 变量PATH
    if (DoH路径.includes("/")) DoH路径 = DoH路径.split("/")[1];
    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;

    // 处理 OPTIONS 预检请求
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

    // 判断是否是直接浏览器访问端点
    const isBrowserDirect = request.method === 'GET' && !url.search && (request.headers.get('Accept') || '').includes('text/html');

    // 如果请求路径，则作为 DoH 服务器处理
    if (path === `/${DoH路径}` && !isBrowserDirect) {
      return await DOHRequest(request, DoH);
    }

    // 支持使用 url path 选择想用的 DoH，格式如 /1.1.1.1/dns-query 或 /dns.google/dns-query
    const pathParts = path.split('/').filter(Boolean);
    if (!isBrowserDirect && pathParts.length > 1 && pathParts[pathParts.length - 1] === DoH路径) {
      let customDoh = path.substring(1, path.lastIndexOf(`/${DoH路径}`));
      // 处理可能被浏览器单斜线化的情况，比如 /https:/1.1.1.1/dns-query
      if (customDoh.includes(':/') && !customDoh.includes('://')) {
        customDoh = customDoh.replace(':/', '://');
      }
      return await DOHRequest(request, customDoh);
    }

    // 添加IP地理位置信息查询代理
    if (path === '/ip-info') {
      if (env.TOKEN) {
        const token = url.searchParams.get('token');
        if (token != env.TOKEN) {
          return new Response(JSON.stringify({
            status: "error",
            message: "Token不正确",
            code: "AUTH_FAILED",
            timestamp: new Date().toISOString()
          }, null, 4), {
            status: 403,
            headers: {
              "content-type": "application/json; charset=UTF-8",
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) {
        return new Response(JSON.stringify({
          status: "error",
          message: "IP参数未提供",
          code: "MISSING_PARAMETER",
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 400,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      try {
        // 使用Worker代理请求HTTP的IP API
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);

        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }

        const data = await response.json();

        // 添加时间戳到成功的响应数据中
        data.timestamp = new Date().toISOString();

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify(data, null, 4), {
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });

      } catch (error) {
        console.error("IP查询失败:", error);
        return new Response(JSON.stringify({
          status: "error",
          message: `IP查询失败: ${error.message}`,
          code: "API_REQUEST_FAILED",
          query: ip,
          timestamp: new Date().toISOString(),
          details: {
            errorType: error.name,
            stack: error.stack ? error.stack.split('\n')[0] : null
          }
        }, null, 4), {
          status: 500,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }

    // 如果请求参数中包含 domain 和 doh，则执行 DNS 解析
    if (url.searchParams.has("doh")) {
      const domain = url.searchParams.get("domain") || url.searchParams.get("name") || "www.google.com";
      const doh = url.searchParams.get("doh") || `https://${DoH}/dns-query`;
      const type = url.searchParams.get("type") || "all"; // 默认同时查询 A 和 AAAA

      // 如果使用的是当前站点，则使用 DoH 服务
      if (doh.includes(url.host)) {
        let upstreamDoh = `https://${DoH}/dns-query`;
        try {
          const dohUrlObj = new URL(doh);
          const pathParts = dohUrlObj.pathname.split('/').filter(Boolean);
          if (pathParts.length > 1 && pathParts[pathParts.length - 1] === DoH路径) {
            let customDoh = dohUrlObj.pathname.substring(1, dohUrlObj.pathname.lastIndexOf(`/${DoH路径}`));
            if (customDoh.includes(':/') && !customDoh.includes('://')) {
              customDoh = customDoh.replace(':/', '://');
            }
            if (!customDoh.startsWith('http')) {
              customDoh = `https://${customDoh}`;
            }
            upstreamDoh = customDoh.endsWith('/dns-query') ? customDoh : customDoh + '/dns-query';
          }
        } catch (e) {
          // ignore parsing errors, use default
        }
        return await handleLocalDohRequest(domain, type, upstreamDoh);
      }

      try {
        // 根据请求类型进行不同的处理
        if (type === "all") {
          // 同时请求 A、AAAA 和 NS 记录，使用新的查询函数
          const ipv4Result = await queryDns(doh, domain, "A");
          const ipv6Result = await queryDns(doh, domain, "AAAA");
          const nsResult = await queryDns(doh, domain, "NS");

          // 合并结果 - 修改Question字段处理方式以兼容不同格式
          const combinedResult = {
            Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
            TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
            RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
            RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
            AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
            CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,

            // 修改处理Question字段的方式，兼容对象格式和数组格式
            Question: [],

            Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || [])],
            ipv4: {
              records: ipv4Result.Answer || []
            },
            ipv6: {
              records: ipv6Result.Answer || []
            },
            ns: {
              records: []
            }
          };

          // 正确处理Question字段，无论是对象还是数组
          if (ipv4Result.Question) {
            if (Array.isArray(ipv4Result.Question)) {
              combinedResult.Question.push(...ipv4Result.Question);
            } else {
              combinedResult.Question.push(ipv4Result.Question);
            }
          }

          if (ipv6Result.Question) {
            if (Array.isArray(ipv6Result.Question)) {
              combinedResult.Question.push(...ipv6Result.Question);
            } else {
              combinedResult.Question.push(ipv6Result.Question);
            }
          }

          if (nsResult.Question) {
            if (Array.isArray(nsResult.Question)) {
              combinedResult.Question.push(...nsResult.Question);
            } else {
              combinedResult.Question.push(nsResult.Question);
            }
          }

          // 处理NS记录 - 可能在Answer或Authority部分
          const nsRecords = [];

          // 从Answer部分收集NS记录
          if (nsResult.Answer && nsResult.Answer.length > 0) {
            nsResult.Answer.forEach(record => {
              if (record.type === 2) { // NS记录类型是2
                nsRecords.push(record);
              }
            });
          }

          // 从Authority部分收集NS和SOA记录
          if (nsResult.Authority && nsResult.Authority.length > 0) {
            nsResult.Authority.forEach(record => {
              if (record.type === 2 || record.type === 6) { // NS=2, SOA=6
                nsRecords.push(record);
                // 也添加到总Answer数组
                combinedResult.Answer.push(record);
              }
            });
          }

          // 设置NS记录集合
          combinedResult.ns.records = nsRecords;

          return new Response(JSON.stringify(combinedResult, null, 2), {
            headers: { "content-type": "application/json; charset=UTF-8" }
          });
        } else {
          // 普通的单类型查询，使用新的查询函数
          const result = await queryDns(doh, domain, type);
          return new Response(JSON.stringify(result, null, 2), {
            headers: { "content-type": "application/json; charset=UTF-8" }
          });
        }
      } catch (err) {
        console.error("DNS 查询失败:", err);
        return new Response(JSON.stringify({
          error: `DNS 查询失败: ${err.message}`,
          doh: doh,
          domain: domain,
          stack: err.stack
        }, null, 2), {
          headers: { "content-type": "application/json; charset=UTF-8" },
          status: 500
        });
      }
    }

    if (env.URL302) return Response.redirect(env.URL302, 302);
    else if (env.URL) {
      if (env.URL.toString().toLowerCase() == 'nginx') {
        return new Response(await nginx(), {
          headers: {
            'Content-Type': 'text/html; charset=UTF-8',
          },
        });
      } else return await 代理URL(env.URL, url);
    } else return await HTML();
  }
}

// 查询DNS的通用函数
async function queryDns(dohServer, domain, type) {
  // 根据用户要求，网页界面的解析请求都使用 json 方式即 /resolve 端点
  let jsonEndpoint = dohServer;
  if (jsonEndpoint.endsWith('/dns-query')) {
    jsonEndpoint = jsonEndpoint.substring(0, jsonEndpoint.length - 10) + '/resolve';
  } else if (!jsonEndpoint.endsWith('/resolve') && !jsonEndpoint.includes('?')) {
    jsonEndpoint = jsonEndpoint + (jsonEndpoint.endsWith('/') ? 'resolve' : '/resolve');
  }

  // 构造 DoH 请求 URL
  const dohUrl = new URL(jsonEndpoint);
  dohUrl.searchParams.set("name", domain);
  dohUrl.searchParams.set("type", type);

  // 尝试多种请求头格式
  const fetchOptions = [
    // 标准 application/dns-json
    {
      headers: { 'Accept': 'application/dns-json' }
    },
    // 部分服务使用没有指定 Accept 头的请求
    {
      headers: {}
    },
    // 另一个尝试 application/json
    {
      headers: { 'Accept': 'application/json' }
    },
    // 稳妥起见，有些服务可能需要明确的用户代理
    {
      headers: {
        'Accept': 'application/dns-json',
        'User-Agent': 'Mozilla/5.0 DNS Client'
      }
    }
  ];

  let lastError = null;

  // 依次尝试不同的请求头组合
  for (const options of fetchOptions) {
    try {
      const response = await fetch(dohUrl.toString(), options);

      // 如果请求成功，解析JSON
      if (response.ok) {
        const contentType = response.headers.get('content-type') || '';
        // 检查内容类型是否兼容
        if (contentType.includes('json') || contentType.includes('dns-json')) {
          return await response.json();
        } else {
          // 对于非标准的响应，仍尝试进行解析
          const textResponse = await response.text();
          try {
            return JSON.parse(textResponse);
          } catch (jsonError) {
            throw new Error(`无法解析响应为JSON: ${jsonError.message}, 响应内容: ${textResponse.substring(0, 100)}`);
          }
        }
      }

      // 错误情况记录，继续尝试下一个选项
      const errorText = await response.text();
      lastError = new Error(`DoH 服务器返回错误 (${response.status}): ${errorText.substring(0, 200)}`);

    } catch (err) {
      // 记录错误，继续尝试下一个选项
      lastError = err;
    }
  }

  // 所有尝试都失败，抛出最后一个错误
  throw lastError || new Error("无法完成 DNS 查询");
}

// 处理本地 DoH 请求的函数 - 直接调用 DoH，而不是自身服务
async function handleLocalDohRequest(domain, type, upstreamDoh) {
  try {
    if (type === "all") {
      // 同时请求 A、AAAA 和 NS 记录
      const ipv4Promise = queryDns(upstreamDoh, domain, "A");
      const ipv6Promise = queryDns(upstreamDoh, domain, "AAAA");
      const nsPromise = queryDns(upstreamDoh, domain, "NS");

      // 等待所有请求完成
      const [ipv4Result, ipv6Result, nsResult] = await Promise.all([ipv4Promise, ipv6Promise, nsPromise]);

      // 准备NS记录数组
      const nsRecords = [];

      // 从Answer和Authority部分收集NS记录
      if (nsResult.Answer && nsResult.Answer.length > 0) {
        nsRecords.push(...nsResult.Answer.filter(record => record.type === 2));
      }

      if (nsResult.Authority && nsResult.Authority.length > 0) {
        nsRecords.push(...nsResult.Authority.filter(record => record.type === 2 || record.type === 6));
      }

      // 合并结果
      const combinedResult = {
        Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
        TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
        RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
        RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
        AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
        CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
        Question: [...(ipv4Result.Question || []), ...(ipv6Result.Question || []), ...(nsResult.Question || [])],
        Answer: [

              <div id="ipv4Records"></div>
            </div>
            <div class="tab-pane fade" id="ipv6" role="tabpanel" aria-labelledby="ipv6-tab">
              <div class="result-summary" id="ipv6Summary"></div>
              <div id="ipv6Records"></div>
            </div>
            <div class="tab-pane fade" id="ns" role="tabpanel" aria-labelledby="ns-tab">
              <div class="result-summary" id="nsSummary"></div>
              <div id="nsRecords"></div>
            </div>
            <div class="tab-pane fade" id="raw" role="tabpanel" aria-labelledby="raw-tab">
              <pre id="result">等待查询...</pre>
            </div>
          </div>
        </div>

        <!-- 错误信息区域 -->
        <div id="errorContainer" style="display: none;">
          <pre id="errorMessage" class="error-message"></pre>
        </div>
      </div>
    </div>

    <div class="beian-info">
      <p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">https://<span
              id="currentDomain">...</span>/${DoH路径}</span></strong><br>基于 Cloudflare Workers 上游 <span id="upstreamDomainDisplay">${DoH}</span> 的 DoH (DNS over HTTPS)
        解析服务</p>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // 获取当前页面的 URL 和主机名
    const currentUrl = window.location.href;
    const currentHost = window.location.host;
    const currentProtocol = window.location.protocol;
    const currentDohPath = '${DoH路径}';
    const currentDohUrl = currentProtocol + '//' + currentHost + '/' + currentDohPath;

    // 记录当前使用的 DoH 地址
    let activeDohUrl = currentDohUrl;

    // 阻断IP列表
    const 阻断IPv4 = [
      '104.21.16.1',
      '104.21.32.1',
      '104.21.48.1',
      '104.21.64.1',
      '104.21.80.1',
      '104.21.96.1',
      '104.21.112.1'
    ];

    const 阻断IPv6 = [
      '2606:4700:3030::6815:1001',
      '2606:4700:3030::6815:3001',
      '2606:4700:3030::6815:7001',
      '2606:4700:3030::6815:5001'
    ];

    // 检查IP是否在阻断列表中
    function isBlockedIP(ip) {
      return 阻断IPv4.includes(ip) || 阻断IPv6.includes(ip);
    }

    const defaultDnsDoh = 'https://${DoH}/${DoH路径}';

    // 显示当前正在使用的 DoH 服务
    function updateActiveDohDisplay() {
        const customDohInput = document.getElementById('customDoh');
        if (customDohInput && customDohInput.value) {
            activeDohUrl = customDohInput.value;
        }
    }

    // 初始更新
    updateActiveDohDisplay();

    // 清除按钮功能
    document.getElementById('clearBtn').addEventListener('click', function () {
      document.getElementById('domain').value = '';
      document.getElementById('domain').focus();
    });

    // 复制结果功能
    document.getElementById('copyBtn').addEventListener('click', function () {
      const resultText = document.getElementById('result').textContent;
      navigator.clipboard.writeText(resultText).then(function () {
        const originalText = this.textContent;
        this.textContent = '已复制';
        setTimeout(() => {
          this.textContent = originalText;
        }, 2000);
      }.bind(this)).catch(function (err) {
        console.error('无法复制文本: ', err);
      });
    });

    // 格式化 TTL
    function formatTTL(seconds) {
      if (seconds < 60) return seconds + '秒';
      if (seconds < 3600) return Math.floor(seconds / 60) + '分钟';
      if (seconds < 86400) return Math.floor(seconds / 3600) + '小时';
      return Math.floor(seconds / 86400) + '天';
    }

    // 查询 IP 地理位置信息 - 使用我们自己的代理API而非直接访问HTTP地址
    async function queryIpGeoInfo(ip) {
      try {
        // 改为使用我们自己的代理接口
        const response = await fetch(\`./ip-info?ip=\${ip}&token=${DoH路径}\`);
            if (!response.ok) {
              throw new Error(\`HTTP 错误: \${response.status}\`);
            }
            return await response.json();
          } catch (error) {
            console.error('IP 地理位置查询失败:', error);
            return null;
          }
        }
        
        // 处理点击复制功能
        function handleCopyClick(element, textToCopy) {
          navigator.clipboard.writeText(textToCopy).then(function() {
            // 添加复制成功的反馈
            element.classList.add('copied');
            
            // 2秒后移除复制成功效果
            setTimeout(() => {
              element.classList.remove('copied');
            }, 2000);
          }).catch(function(err) {
            console.error('复制失败:', err);
          });
        }
        
        // 显示记录
        function displayRecords(data) {
          document.getElementById('resultContainer').style.display = 'block';
          document.getElementById('errorContainer').style.display = 'none';
          document.getElementById('result').textContent = JSON.stringify(data, null, 2);
          
          // IPv4 记录
          const ipv4Records = data.ipv4?.records || [];
          const ipv4Container = document.getElementById('ipv4Records');
          ipv4Container.innerHTML = '';
          
          if (ipv4Records.length === 0) {
            document.getElementById('ipv4Summary').innerHTML = \`<strong>未找到 IPv4 记录</strong>\`;
          } else {
            document.getElementById('ipv4Summary').innerHTML = \`<strong>找到 \${ipv4Records.length} 条 IPv4 记录</strong>\`;
            
            ipv4Records.forEach(record => {
              const recordDiv = document.createElement('div');
              recordDiv.className = 'ip-record';
              
              if (record.type === 5) { // CNAME 记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="badge bg-success">CNAME</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv4Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 1) {  // A记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="geo-info geo-loading">正在获取位置信息...</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv4Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
                // 添加地理位置信息
                const geoInfoSpan = recordDiv.querySelector('.geo-info');
                
                // 检查是否为阻断IP
                if (isBlockedIP(record.data)) {
                  // 异步查询 IP 地理位置信息获取AS信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    // 显示阻断IP标识（替代国家信息）
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                    
                    // 如果有AS信息，正常显示
                    if (geoData && geoData.status === 'success' && geoData.as) {
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as;
                      geoInfoSpan.appendChild(asSpan);
                    }
                  }).catch(() => {
                    // 查询失败时仍显示阻断IP标识
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                  });
                } else {
                  // 异步查询 IP 地理位置信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    if (geoData && geoData.status === 'success') {
                      // 更新为实际的地理位置信息
                      geoInfoSpan.innerHTML = '';
                      geoInfoSpan.classList.remove('geo-loading');
                      
                      // 添加国家信息
                      const countrySpan = document.createElement('span');
                      countrySpan.className = 'geo-country';
                      countrySpan.textContent = geoData.country || '未知国家';
                      geoInfoSpan.appendChild(countrySpan);
                      
                      // 添加 AS 信息
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as || '未知 AS';
                      geoInfoSpan.appendChild(asSpan);
                    } else {
                      // 查询失败或无结果
                      geoInfoSpan.textContent = '位置信息获取失败';
                    }
                  });
                }
              }
            });
          }
          
          // IPv6 记录
          const ipv6Records = data.ipv6?.records || [];
          const ipv6Container = document.getElementById('ipv6Records');
          ipv6Container.innerHTML = '';
          
          if (ipv6Records.length === 0) {
            document.getElementById('ipv6Summary').innerHTML = \`<strong>未找到 IPv6 记录</strong>\`;
          } else {
            document.getElementById('ipv6Summary').innerHTML = \`<strong>找到 \${ipv6Records.length} 条 IPv6 记录</strong>\`;
            
            ipv6Records.forEach(record => {
              const recordDiv = document.createElement('div');
              recordDiv.className = 'ip-record';
              
              if (record.type === 5) { // CNAME 记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="badge bg-success">CNAME</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv6Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 28) {  // AAAA记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="geo-info geo-loading">正在获取位置信息...</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv6Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
                // 添加地理位置信息
                const geoInfoSpan = recordDiv.querySelector('.geo-info');
                
                // 检查是否为阻断IP
                if (isBlockedIP(record.data)) {
                  // 异步查询 IP 地理位置信息获取AS信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    // 显示阻断IP标识（替代国家信息）
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                    
                    // 如果有AS信息，正常显示
                    if (geoData && geoData.status === 'success' && geoData.as) {
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as;
                      geoInfoSpan.appendChild(asSpan);
                    }
                  }).catch(() => {
                    // 查询失败时仍显示阻断IP标识
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                  });
                } else {
                  // 异步查询 IP 地理位置信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    if (geoData && geoData.status === 'success') {
                      // 更新为实际的地理位置信息
                      geoInfoSpan.innerHTML = '';
                      geoInfoSpan.classList.remove('geo-loading');
                      
                      // 添加国家信息
                      const countrySpan = document.createElement('span');
                      countrySpan.className = 'geo-country';
                      countrySpan.textContent = geoData.country || '未知国家';
                      geoInfoSpan.appendChild(countrySpan);

            } else {
              displayRecords(json);
            }
   

</html>`;

  return new Response(html, {
    headers: { "content-type": "text/html;charset=UTF-8" }
  });
}

async function 代理URL(代理网址, 目标网址) {
  const 网址列表 = await 整理(代理网址);
  const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

  // 解析目标 URL
  const 解析后的网址 = new URL(完整网址);
  console.log(解析后的网址);
  // 提取并可能修改 URL 组件
  const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
  const 主机名 = 解析后的网址.hostname;
  let 路径名 = 解析后的网址.pathname;
  const 查询参数 = 解析后的网址.search;

  // 处理路径名
  if (路径名.charAt(路径名.length - 1) == '/') {
    路径名 = 路径名.slice(0, -1);
  }
  路径名 += 目标网址.pathname;

  // 构建新的 URL
  const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

  // 反向代理请求
  const 响应 = await fetch(新网址);

  // 创建新的响应
  let 新响应 = new Response(响应.body, {
    status: 响应.status,
    statusText: 响应.statusText,
    headers: 响应.headers
  });

  // 添加自定义头部，包含 URL 信息
  //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
  //新响应.headers.set('X-Original-URL', 完整网址);
  新响应.headers.set('X-New-URL', 新网址);

  return 新响应;
}

async function 整理(内容) {
  // 将制表符、双引号、单引号和换行符都替换为逗号
  // 然后将连续的多个逗号替换为单个逗号
  var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');

  // 删除开头和结尾的逗号（如果有的话）
  if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
  if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

  // 使用逗号分割字符串，得到地址数组
  const 地址数组 = 替换后的内容.split(',');

  return 地址数组;
}

async function nginx() {
  const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
  return text;
}