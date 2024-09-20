#include "dns.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <atomic>

#define DNS_NAMES_MAX (8)
#define DNS_IP_MAX    (64)

static std::atomic<uint16_t> dns_tid(1);

struct dns_ans
{
  uint32_t        ttl;
  dns_class_t     cls;
  dns_type_t     type;
  const char      *ip;
  const char  *domain;
};

struct dns_names
{
  uint8_t   len;
  const char *s;
};

struct dns_error_info
{
  int         code;
  const char *info;
};

/* Error code and error message mapping. */
static dns_error_info dns_errors[] =
{
  { 0, "Successed." },
  { 1, "Invalid dns ctx or buffer." },
  { 2, "Invalid dns tid." },
  { 3, "Unexpected dns flags." },
  { 4, "Unexpected dns type." },
  { 5, "Unexpected dns questions." },
  { 6, "Unexpected dns answer data." },
};

/* Allow unsafe parsing behavior. */
static bool dns_unsafe = false;
/* Setting the default memory allocator. */
static dns_realloc_t dns_realloc = realloc;
#define dns_malloc(sz)  dns_realloc(nullptr, sz)
#define dns_free(ptr)   dns_realloc(ptr, 0)

const char *dns_get_error(int r)
{
  if (r > 0 or r < -6) 
    return nullptr;
  return dns_errors[-r].info;
}

void dns_set_memhook(const dns_realloc_t alloc)
{
  dns_realloc = alloc;
}

void dns_set_unsafe()
{
  dns_unsafe = true;
}

const char *dns_get_domain(const dns_ans_t *ans)
{
  // return ans->domain.c_str();
  return ans->domain;
}

const char *dns_get_ip(const dns_ans_t *ans)
{
  // return ans->ip.c_str();
  return ans->ip;
}

dns_type_t dns_get_type(const dns_ans_t *ans)
{
  return ans->type;
}

dns_class_t dns_get_class(const dns_ans_t *ans)
{
  return ans->cls;
}

uint32_t dns_get_ttl(const dns_ans_t *ans)
{
  return ans->ttl;
}

void dns_init(dns_req_t *req)
{
  memset(req, 0x0, sizeof(dns_req_t));
}

dns_req_t* dns_new()
{
  return (dns_req_t*) dns_malloc(sizeof(dns_req_t));
}

void dns_destory(dns_req_t *req)
{
  dns_free(req);
}

template<typename T>
T dns_get(const char *buffer, int &pos)
{
  T val = 0;
  for (size_t i = 0; i < sizeof(T); i++)
    val = val << 8 | (uint8_t)buffer[pos + i];
  pos += sizeof(T);
  return val;
}

template<typename T>
void dns_set(char *buffer, T &&val, int &pos)
{
  for (size_t i = 0; i < sizeof(T); i++)
    buffer[pos + i] = val >> ((sizeof(T) - i - 1) * 8) & 0xff;
  pos += sizeof(T);
}

static inline void dns_split_domain(dns_names names[DNS_NAMES_MAX], const char *domain, int &pos)
{
  for (size_t i = 0; i < strlen(domain); i++)
  {
    if (domain[i] == '.')
    {
      pos++;
    }
    else
    {
      if (!names[pos].s)
        names[pos].s = domain + i;
      names[pos].len++;
    }
  }
  pos++;
}

void dns_write_request(const dns_type_t dt, char *buffer, dns_names names[DNS_NAMES_MAX], const int &n, int &blen)
{
  for (int i = 0; i < n; i++)
  {
    // printf("i = %d, blen = %d\n", i, blen);
    memcpy(buffer + blen, &names[i].len, 1);
    memcpy(buffer + blen + 1, names[i].s, names[i].len);
    blen += names[i].len + 1;
  }
  buffer[blen++] = '\x00';
  /* Type */
  dns_set(buffer, (uint16_t)dt, blen);
  /* Class */
  dns_set(buffer, (uint16_t)0x0001, blen);
}

int dns_query(dns_req_t *req, const dns_type_t type, const char *domain, char buffer[DNS_MAX_BUF_SIZE])
{
  if (!req or !buffer)
    return -1;
  if (type != A and type != AAAA)
    return -4;
  /* init ctx */
  dns_tid_t tid = dns_tid++;
  if (!tid)
    tid = dns_tid++;
  req->tid = tid;
  req->type = type;
  req->cls = IN;
  int blen = 0;
  /* Transaction ID */
  dns_set(buffer, (uint16_t)req->tid, blen);
  /* Flags (Standard Query) */
  dns_set(buffer, (uint16_t)0x0100, blen);
  /* Query Count */
  dns_set(buffer, (uint16_t)0x0001, blen); /* Question: 1 */
  dns_set(buffer, (uint16_t)0x0000, blen); /* Answer RRs: 0 */
  dns_set(buffer, (uint16_t)0x0000, blen); /* Authority RRs: 0 */
  dns_set(buffer, (uint16_t)0x0000, blen); /* Additional RRs: 0 */
  /* Query payload:  */
  int pos = 0;
  dns_names names[DNS_NAMES_MAX]; memset(names, 0x0, sizeof(names));
  dns_split_domain(names, domain, pos);
  dns_write_request(type, buffer, names, pos, blen);
  /* Over. */
  return blen;
}

static inline void dns_skip_domain_parse(const char *buffer, int &pos)
{
  uint8_t len;
  while ((len = buffer[pos]))
    pos += len + 1;
  pos++;
}

static inline void dns_copy_domain(const char *buffer, int &pos, char *data)
{
  uint8_t len;
  while ((len = buffer[pos]))
  {
    if (len >= (uint8_t)0xc0)
    {
      char ptr[UINT8_MAX] = { 0 };
      int p = (len & 0b00111111) << 8 | (uint8_t)buffer[pos+1];
      dns_copy_domain(buffer, p, data); memcpy(data, ptr, strlen(ptr));
      pos += 2; return;
    }
    else
    {
      memcpy(data, buffer + pos + 1, len); pos = pos + len + 1;
      if (buffer[pos])
        { memcpy(data + len, ".", 1); data = data + len + 1; }
    }
  }
  pos++;
}

int dns_parse(dns_req_t *req, const char *buffer, void *udata, dns_parse_callback_t cb)
{
  if (!buffer or !req)
    return -1;
  /* Transaction ID */
  int pos = 0;
  uint16_t tid = dns_get<uint16_t>(buffer, pos);
  if (!dns_unsafe and tid != req->tid)
    return -2;
  /* flags */
  uint16_t flags = dns_get<uint16_t>(buffer, pos);
  if (!dns_unsafe and flags >> 15 != 0x1)
    return -3;

  int questions = dns_get<uint16_t>(buffer, pos);
  int answers = dns_get<uint16_t>(buffer, pos);
  int authorities = dns_get<uint16_t>(buffer, pos);
  int additional = dns_get<uint16_t>(buffer, pos);
  (void)authorities;(void)additional;
  // printf("questions = %hu, answers = %hu, authorities = %hu, additional = %hu\n", questions, answers, authorities, additional);
  if (questions != 1)
    return -5;

  if (answers == 0)
    return 0;

  /* Skip query domain verification */
  dns_skip_domain_parse(buffer, pos); pos += 4;

  /* Parsing answer information */
  for (int i = 0; i < answers; i++)
  {
    char domain[UINT16_MAX] = { 0 }; dns_copy_domain(buffer, pos, domain);
    dns_type_t  dt  = (dns_type_t)dns_get<uint16_t>(buffer, pos);
    dns_class_t cls = (dns_class_t)dns_get<uint16_t>(buffer, pos);
    uint32_t    ttl = dns_get<uint32_t>(buffer, pos);
    uint16_t    len = dns_get<uint16_t>(buffer, pos);
    // printf("%d, %d, %d, %d\n", dt, cls, ttl, len);
    if (dt == dns_type_t::A or dt == dns_type_t::AAAA or dt == dns_type_t::CNAME)
    {
      char ip[DNS_IP_MAX] = { 0 }; int p;
      switch (dt)
      {
        case dns_type_t::A:
          snprintf(ip, DNS_IP_MAX, "%u.%u.%u.%u", (uint8_t)buffer[pos], (uint8_t)buffer[pos+1], (uint8_t)buffer[pos+2], (uint8_t)buffer[pos+3]);
          break;
        case dns_type_t::AAAA:
          snprintf(ip, DNS_IP_MAX, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
            (uint8_t)buffer[pos +  0], (uint8_t)buffer[pos +  1], (uint8_t)buffer[pos +  2], (uint8_t)buffer[pos +   3],
            (uint8_t)buffer[pos +  4], (uint8_t)buffer[pos +  5], (uint8_t)buffer[pos +  6], (uint8_t)buffer[pos +   7],
            (uint8_t)buffer[pos +  8], (uint8_t)buffer[pos +  9], (uint8_t)buffer[pos + 10], (uint8_t)buffer[pos +  11],
            (uint8_t)buffer[pos + 12], (uint8_t)buffer[pos + 13], (uint8_t)buffer[pos + 14], (uint8_t)buffer[pos +  15]
          );
          break;
        case dns_type_t::CNAME:
          p = pos; dns_copy_domain(buffer, p, ip); break;
        /* TODO */
        default:
          return -6;
      }
      // printf("len = %d, ip = %s, ttl = %d\n", len, ip, ttl);
      dns_ans_t ans; ans.type = dt; ans.cls = cls; ans.ttl = ttl; ans.ip = ip; ans.domain = domain;
      cb(udata, &ans);
    }
    pos += len;
  }

  return 0;
}
