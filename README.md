# Reserve DNS Worker

一个基于 Cloudflare Workers 的 DNS-over-HTTPS (DoH) 代理服务，提供安全的 DNS 查询和 IP 地理位置查询功能。

## 项目功能

### 核心功能

- **DoH 代理服务**：支持标准的 DNS-over-HTTPS 协议，兼容多种 DoH 服务器
- **自定义 DoH 服务器**：支持通过路径指定不同的 DoH 服务器（如 `/1.1.1.1/dns-query` 或 `/dns.google/dns-query`）
- **IP 地理位置查询**：提供 IP 地址的地理位置信息查询接口
- **Web UI 界面**：提供美观的 Web 界面进行 DNS 查询
- **访问控制**：支持 Token 认证保护服务访问
- **URL 重定向**：支持配置重定向 URL 或代理 URL

### 支持的 DNS 记录类型

- A 记录（IPv4 地址）
- AAAA 记录（IPv6 地址）
- NS 记录（名称服务器）
- 其他标准 DNS 记录类型

## 部署方式

### 部署到Cloudflare Worker

1. 登录Cloudflare
2. 创建新的Worker
3. 将代码复制到Worker中
4. 配置环境变量
5. 部署

## 认证方式

### Token认证
在ENV中设置`TOKEN`变量，值为你的认证token。
* **URL 参数**：`?token=your-token`


## 许可证

MIT License