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

## 部署方式

### 部署到Cloudflare Worker

1. 登录Cloudflare
2. 创建新的Worker
3. 将代码复制到Worker中
4. 配置环境变量
5. 部署

### 环境变量说明

| 变量名 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `DOH` | String | 否 | `cloudflare-dns.com` | DoH 服务器地址，如 `cloudflare-dns.com`、`1.1.1.1`、`dns.google` |
| `PATH` | String | 否 | `dns-query` | DoH 路径，如 `dns-query` |
| `TOKEN` | String | 否 | 无 | 访问令牌，用于保护服务访问。设置后需要通过 URL 参数、Cookie 或 Authorization Header 进行认证 |
| `URL302` | String | 否 | 无 | 重定向 URL，设置后所有请求将 302 重定向到该地址 |
| `URL` | String | 否 | 无 | 伪装 URL，设置为 `nginx` 可显示 nginx 欢迎页面，否则伪装为指定 URL |

### 环境变量配置示例

```toml
[vars]
# DoH 服务器配置
DOH = "cloudflare-dns.com"
PATH = "dns-query"

# 访问控制（可选）
TOKEN = "your-secure-token-here"

# 重定向或代理（可选，二选一）
URL302 = "https://example.com"
# 或
URL = "nginx"
```

## 认证方式

### Token认证
在ENV中设置`TOKEN`变量，值为你的认证token。

服务支持三种认证方式：
1. **URL 参数**：`?token=your-token`
2. **Cookie**：`auth_token=your-token`
3. **Authorization Header**：`Bearer your-token` 或直接使用 token 值

### 认证流程

当设置了 `TOKEN` 环境变量后，所有请求必须通过认证才能访问。未认证的请求将返回 401 错误。

**请求示例：**
```
https://your-worker.workers.dev/dns-query?token=your-secure-token
```

> [!TIP]
> 默认配置的DNS地址为`cloudflare-dns.com`
> 支持在URL中指定不同的DoH服务器。

## 许可证

MIT License

## 鸣谢
[cmliu](https://github.com/cmliu/CF-Workers-DoH), [tina-hello](https://github.com/tina-hello/doh-cf-workers)、[ip-api](https://ip-api.com/), [Cloudflare](https://www.cloudflare.com/), [Google Gemini](https://ai.google.dev/)
