# dns.cc

> 写协议、不碰 Socket —— 把 DNS 查询和解析从网络 I/O 里拆出来。

dns.cc 是一个 **纯 C99** 的 DNS 客户端协议库：你负责收发 UDP，它负责编包和拆包。支持 A / AAAA / CNAME 记录，完整处理 RFC 1035 域名压缩。

```c
// 1. 构建查询
dns_req_t req;
char buf[4096];
dns_init(&req);
int len = dns_query(&req, DNS_A, "www.example.com", buf);
// → 把 buf[0..len-1] 发到 8.8.8.8:53

// 2. 解析响应
void cb(void *u, const dns_ans_t *a) {
    printf("%s → %s  ttl=%u\n", dns_get_domain(a), dns_get_ip(a), dns_get_ttl(a));
}
req.tid = /* 查询时用的 TID */;
dns_parse(&req, resp_bytes, NULL, cb);
```

## 五个特点

| | |
|---|---|
| **纯算法** | 只有 struct 和 memcpy，零系统调用、零全局锁 |
| **跨平台** | Windows / Linux / macOS / FreeBSD，gcc / clang / msvc 都能编 |
| **值语义** | 回调给的 `dns_ans_t` 是栈上拷贝，回调结束数据还在 |
| **线程安全** | TID 用 CAS 原子递增，多线程并发查询不冲突 |
| **零依赖** | 两个文件 `dns.h` + `dns.c`，拷走就能用 |

## 编译

```bash
gcc -std=c99 dns.c main.c   -o main       # 示例
gcc -std=c99 dns.c test_dns.c -o test_dns # 75 项测试
```

## API 一览

```c
/* 配置（按需调用） */
void dns_set_memhook(dns_realloc_t alloc);  // 自定义内存分配器
void dns_set_unsafe(void);                  // 跳过 TID/Flags 校验
const char *dns_get_error(int r);           // 错误码 → 文字

/* 请求对象 */
dns_req_t *dns_new(void);                   // 堆上分配
void dns_init(dns_req_t *req);              // 栈上初始化
void dns_destory(dns_req_t *req);           // 释放

/* 核心 */
int dns_query(dns_req_t *req, dns_type_t type,
              const char *domain, char buf[4096]);   // 编包 → 返回字节数
int dns_parse(dns_req_t *req, const char *buf,
              void *udata, void (*cb)(void*, const dns_ans_t*)); // 拆包 → 回调

/* 读取结果 */
const char  *dns_get_ip(const dns_ans_t *a);
const char  *dns_get_domain(const dns_ans_t *a);
dns_type_t   dns_get_type(const dns_ans_t *a);
dns_class_t  dns_get_class(const dns_ans_t *a);
uint32_t     dns_get_ttl(const dns_ans_t *a);
```

查询类型：`DNS_A` / `DNS_AAAA`（老代码也能用 `A` / `AAAA` 别名）。

## 错误码

| 值 | 含义 |
|---|---|
| `0` | 正常 |
| `-1` | 传了空指针 |
| `-2` | TID 对不上（响应不属于当前请求） |
| `-3` | 响应 flags 没设 QR 位（不是应答包） |
| `-4` | 查询类型只支持 A / AAAA |
| `-5` | 响应 question 数量异常 |
| `-6` | 响应 answer 数据无法解析 |

## 许可证

MIT
