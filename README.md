# Xdns — 轻量级纯 C DNS 客户端

一个轻量级的 DNS 客户端协议实现, 支持 `A` (IPv4) / `AAAA` (IPv6) / `CNAME` 记录查询与解析, 并完整处理 RFC 1035 域名压缩指针。

# 优势

* **纯 C99** 编写, 零 C++ 依赖 — 可被 C / C++ 项目直接 `#include` 使用, 也支持被 `extern "C"` 包裹调用。

* **跨平台** — Windows / Linux / macOS / FreeBSD, 支持 gcc / clang / msvc 编译。

* **零系统调用** — 只做协议数据包的构建与解析, 不触碰 socket / 网络 I/O。你自行收发 UDP 报文, 本库只负责"编"和"解"。

* **热路径零堆分配** — `dns_query` / `dns_parse` 全程栈上操作, 无 malloc/free, 适合高频调用。

* **阻塞 / 非阻塞通吃** — 无全局状态依赖 (TID 除外), 可嵌入任何事件循环框架。

* **值语义的解析结果** — `dns_ans_t` 是**具体结构体** (`char ip[64]`, `char domain[256]`), 回调返回后数据仍然有效, 无悬空指针。

* **性能优先** — 线格式 I/O 使用 `static inline` 函数, 编译后等价于手写移位; 域名解压采用迭代跳跃 (非递归), 并内置压缩环检测。

# 平台

* Windows
* Linux
* macOS
* FreeBSD

# 编译器

* gcc (≥ 4.9)
* clang (≥ 3.5)
* msvc (≥ VS 2015)

# 快速开始

## 查询: 构建 DNS 请求包

```c
#include "dns.h"

dns_req_t req;
char      buf[DNS_MAX_BUF_SIZE];

dns_init(&req);
int len = dns_query(&req, DNS_A, "www.example.com", buf);
if (len < 0)
{
    printf("query error: %s\n", dns_get_error(len));
    return;
}
/* 将 buf[0..len-1] 通过 UDP 发送到 DNS 服务器 (通常端口 53) */
```

## 解析: 解析 DNS 响应包

```c
void on_answer(void *udata, const dns_ans_t *ans)
{
    printf("type=%d  domain=%s  ip=%s  ttl=%u\n",
           dns_get_type(ans),
           dns_get_domain(ans),
           dns_get_ip(ans),
           dns_get_ttl(ans));
}

/* resp 是从服务器收到的 UDP 响应, resp_len 是响应长度 */
dns_req_t req;
req.tid = tid;  /* 与查询时的 TID 一致 */
int r = dns_parse(&req, resp, NULL, on_answer);
if (r < 0)
    printf("parse error: %s\n", dns_get_error(r));
```

## 完整示例

参见 `main.c` — 包含一次完整的查询构建 + 预置响应解析演示。

# API 参考

## 数据类型

| 类型 | 说明 |
|---|---|
| `dns_type_t` | 记录类型: `DNS_A`(1), `DNS_NS`(2), `DNS_CNAME`(5), `DNS_AAAA`(28) |
| `dns_class_t` | 记录类别: `DNS_IN`(1) |
| `dns_error_t` | 错误码枚举, 见下表 |
| `dns_req_t` | 查询上下文 (TID + type + class) |
| `dns_ans_t` | 解析结果: `ip[64]`, `domain[256]`, `ttl`, `type`, `class` |

## 错误码

| 枚举值 | 含义 |
|---|---|
| `DNS_OK` (0) | 成功 |
| `DNS_EBADARG` (-1) | 无效参数 (ctx / buffer 为空) |
| `DNS_EBADTID` (-2) | 响应 TID 与请求不匹配 |
| `DNS_EBADFLAGS` (-3) | 响应 flags 未设置 QR 位 |
| `DNS_EBADTYPE` (-4) | 不支持的查询类型 (仅 A/AAAA) |
| `DNS_EBADQUEST` (-5) | 响应包含异常的问题数量 |
| `DNS_EBADDATA` (-6) | 响应包含无法解析的回答数据 |

## 函数

```c
/* 配置 */
void        dns_set_memhook(dns_realloc_t alloc);   /* 自定义内存分配器 */
void        dns_set_unsafe(void);                    /* 跳过 TID/flags 校验 */
const char *dns_get_error(int r);                    /* 错误码 → 描述字符串 */

/* 生命周期 */
dns_req_t  *dns_new(void);                           /* 堆分配请求对象 */
void        dns_init(dns_req_t *req);                /* 栈/静态请求对象清零 */
void        dns_destory(dns_req_t *req);             /* 释放请求对象 */

/* 核心 */
int dns_query(dns_req_t *req, dns_type_t type,
              const char *domain,
              char buffer[DNS_MAX_BUF_SIZE]);         /* 构建 DNS 查询包 → 返回字节数 */
int dns_parse(dns_req_t *req, const char *buffer,
              void *udata,
              dns_parse_callback_t cb);               /* 解析 DNS 响应 → 每个回答触发一次回调 */

/* 访问器 (操作 dns_ans_t) */
const char  *dns_get_ip(const dns_ans_t *ans);
const char  *dns_get_domain(const dns_ans_t *ans);
dns_type_t   dns_get_type(const dns_ans_t *ans);
dns_class_t  dns_get_class(const dns_ans_t *ans);
uint32_t     dns_get_ttl(const dns_ans_t *ans);
```

# 构建

## 直接编译 (无需 CMake)

```bash
# 编译库
gcc -std=c99 -c dns.c -o dns.o

# 编译 + 运行示例
gcc -std=c99 dns.c main.c -o main && ./main

# 编译 + 运行测试
gcc -std=c99 dns.c test_dns.c -o test_dns && ./test_dns
```

## CMake 构建

```bash
mkdir build && cd build
cmake ..
make
```

# 测试

`test_dns.c` 包含 **75 个断言**, 覆盖:

* 查询构建: 参数校验 / A / AAAA / 域名分片 / TID 递增
* 响应解析: A / AAAA / CNAME / NS / 多回答 / 未知类型 / RFC 1035 压缩指针
* 错误路径: 所有 7 个错误码
* 生命周期: 内存钩子 / 初始化 / 分配释放
* 访问器: 5 个 getter 的返回值正确性

```bash
gcc -std=c99 -Wall -Wextra -pedantic dns.c test_dns.c -o test_dns && ./test_dns
# 输出:
# ========================================
#   PASS: 75   FAIL: 0   TOTAL: 75
# ========================================
```

# v2.0 变更说明 (vs v1.x C++ 版本)

| 项目 | v1.x (dns.cc) | v2.0 (dns.c) |
|---|---|---|
| 语言 | C++11 (`extern "C"`) | **纯 C99** |
| 头文件 | `<cstdio>`, `<cstring>`, `<cstdlib>` | `<stdio.h>`, `<string.h>`, `<stdlib.h>` |
| 模板 | `template<T> dns_get/set` | `static inline dns_get_u16/u32` |
| TID 生成 | `std::atomic<uint16_t>` | `static uint16_t` |
| `dns_ans_t` | 不透明指针, `const char *` 成员 → **悬空指针 bug** | **具体结构体**, `char[]` 成员, 值语义 |
| 域名解压 | 递归, 无环检测 | **迭代 + 压缩环守卫** |
| 测试 | 无 | **75 个断言, 零外部依赖** |
| 文件 | `dns.h` + `dns.cc` | `dns.h` + `dns.c` + `test_dns.c` |

# 许可证

MIT — 详见源文件头部。
