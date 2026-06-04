/*
**  LICENSE: MIT
**  Author: CandyMi[https://github.com/candymi]
*/
#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Internal constants                                                 */
/* ------------------------------------------------------------------ */
#define DNS_NAMES_MAX   (8)
#define DNS_IP_MAX      (64)

/* ------------------------------------------------------------------ */
/*  Error table                                                        */
/* ------------------------------------------------------------------ */
typedef struct dns_error_info
{
  int         code;
  const char *info;
} dns_error_info_t;

static const dns_error_info_t dns_errors[] =
{
  {  0, "Successed."                     },
  { -1, "Invalid dns ctx or buffer."     },
  { -2, "Invalid dns tid."               },
  { -3, "Unexpected dns flags."          },
  { -4, "Unexpected dns type."           },
  { -5, "Unexpected dns questions."      },
  { -6, "Unexpected dns answer data."    },
};

/* ------------------------------------------------------------------ */
/*  Global state                                                       */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  TID generator — atomic increment, cross-platform                    */
/* ------------------------------------------------------------------ */
static uint16_t dns_tid = 1;

static inline uint16_t dns_tid_next(void)
{
#if defined(__GNUC__) || defined(__clang__)
  /* GCC 4.7+ / Clang 3.3+ — relaxed ordering is sufficient for a
   * monotonic counter; no memory barrier needed.                     */
  return (uint16_t)__atomic_fetch_add(&dns_tid, 1, __ATOMIC_RELAXED);
#elif defined(_MSC_VER)
  /* MSVC 2010+ — InterlockedIncrement16 returns the *new* value.   */
  return (uint16_t)(_InterlockedIncrement16((short volatile *)&dns_tid) - 1);
#else
  /* Fallback — NOT thread-safe.                                     */
  return dns_tid++;
#endif
}

/* Unsafe mode: skip TID + flags validation. */
static int dns_unsafe = 0;

/* Memory hook — defaults to standard realloc. */
static dns_realloc_t dns_realloc_fn = realloc;

#define dns_malloc(sz)  dns_realloc_fn(NULL, sz)
#define dns_free(ptr)   dns_realloc_fn((ptr), 0)

/* ------------------------------------------------------------------ */
/*  Internal domain-name helpers                                        */
/* ------------------------------------------------------------------ */
typedef struct dns_names
{
  uint8_t      len;
  const char    *s;
} dns_names_t;

/* ------------------------------------------------------------------ */
/*  Wire-format I/O (big-endian, portable, compile to 1-2 insns)        */
/* ------------------------------------------------------------------ */
static inline uint16_t dns_get_u16(const unsigned char *buffer, int *pos)
{
  uint16_t v = ((uint16_t)buffer[*pos] << 8) | buffer[*pos + 1];
  *pos += 2;
  return v;
}

static inline uint32_t dns_get_u32(const unsigned char *buffer, int *pos)
{
  uint32_t v = ((uint32_t)buffer[*pos]     << 24) |
               ((uint32_t)buffer[*pos + 1] << 16) |
               ((uint32_t)buffer[*pos + 2] <<  8) |
                (uint32_t)buffer[*pos + 3];
  *pos += 4;
  return v;
}

static inline void dns_set_u16(unsigned char *buffer, uint16_t val, int *pos)
{
  buffer[*pos]     = (unsigned char)(val >> 8);
  buffer[*pos + 1] = (unsigned char)(val);
  *pos += 2;
}

/* ------------------------------------------------------------------ */
/*  Domain splitting & request writing                                  */
/* ------------------------------------------------------------------ */

/* Split "www.example.com" into labels in one pass. */
static void dns_split_domain(dns_names_t names[DNS_NAMES_MAX],
                             const char *domain, int *count)
{
  int n = 0;
  const char *p = domain;
  const char *start = domain;

  memset(names, 0, DNS_NAMES_MAX * sizeof(dns_names_t));

  while (*p)
  {
    if (*p == '.')
    {
      names[n].s   = start;
      names[n].len = (uint8_t)(p - start);
      n++;
      start = p + 1;
    }
    p++;
  }
  /* Final label (or single-label domain). */
  if (p > start)
  {
    names[n].s   = start;
    names[n].len = (uint8_t)(p - start);
    n++;
  }
  *count = n;
}

/* Write the QNAME + QTYPE + QCLASS into buffer at blen. */
static void dns_write_request(dns_type_t dt, unsigned char *buffer,
                              dns_names_t names[DNS_NAMES_MAX],
                              int n, int *blen)
{
  int i;
  for (i = 0; i < n; i++)
  {
    buffer[(*blen)++] = names[i].len;
    memcpy(buffer + *blen, names[i].s, names[i].len);
    *blen += names[i].len;
  }
  buffer[(*blen)++] = 0x00;  /* root label */

  dns_set_u16(buffer, (uint16_t)dt,    blen);  /* QTYPE  */
  dns_set_u16(buffer, (uint16_t)DNS_IN, blen);  /* QCLASS */
}

/* ------------------------------------------------------------------ */
/*  Domain-name decompression (RFC 1035 §4.1.4)                        */
/* ------------------------------------------------------------------ */

/* Skip a domain name (including compressed pointers) without copying. */
static void dns_skip_domain(const unsigned char *buffer, int *pos)
{
  uint8_t len;
  while ((len = buffer[*pos]))
  {
    if (len >= 0xc0)
    {
      *pos += 2;  /* compression pointer — 2 bytes, then done */
      return;
    }
    *pos += len + 1;
  }
  (*pos)++;  /* zero-length terminator */
}

/* Decode a domain name into `dst` (caller-provided buffer).
 * Handles RFC 1035 message compression (0xc0 prefix).
 * Returns the number of bytes written (excluding NUL). */
static int dns_copy_domain(const unsigned char *buffer, int pos,
                           char *dst, int dst_sz)
{
  int    start  = pos;
  int    jumped = 0;
  int    offset = 0;
  int    ptr_count = 0;  /* guard against compression loops */
  uint8_t len;

  while (ptr_count < 40 && (len = buffer[pos]))
  {
    if (len >= 0xc0)
    {
      /* Compression pointer */
      if (!jumped)
        start = pos + 2;  /* resume here after jump */
      pos = ((int)(len & 0x3f) << 8) | (int)buffer[pos + 1];
      jumped = 1;
      ptr_count++;
      continue;
    }

    /* Label */
    if (offset > 0 && offset < dst_sz - 1)
      dst[offset++] = '.';
    if (offset + len < dst_sz)
    {
      memcpy(dst + offset, buffer + pos + 1, len);
      offset += len;
    }
    pos += len + 1;
  }

  if (offset < dst_sz)
    dst[offset] = '\0';

  return jumped ? (start) : (pos + 1);  /* return next position */
}

/* ------------------------------------------------------------------ */
/*  Public API — error / config                                         */
/* ------------------------------------------------------------------ */
const char *dns_get_error(int r)
{
  unsigned int idx;
  if (r > 0 || r < -6)
    return NULL;
  idx = (unsigned int)(-r);
  return dns_errors[idx].info;
}

void dns_set_memhook(dns_realloc_t alloc)
{
  if (alloc)
    dns_realloc_fn = alloc;
  else
    dns_realloc_fn = realloc;
}

void dns_set_unsafe(void)
{
  dns_unsafe = 1;
}

/* ------------------------------------------------------------------ */
/*  Public API — accessors                                              */
/* ------------------------------------------------------------------ */
const char *dns_get_ip(const dns_ans_t *ans)
{
  return ans->ip;
}

const char *dns_get_domain(const dns_ans_t *ans)
{
  return ans->domain;
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

/* ------------------------------------------------------------------ */
/*  Public API — lifecycle                                              */
/* ------------------------------------------------------------------ */
void dns_init(dns_req_t *req)
{
  memset(req, 0, sizeof(dns_req_t));
}

dns_req_t *dns_new(void)
{
  dns_req_t *req = (dns_req_t *)dns_malloc(sizeof(dns_req_t));
  if (req)
    dns_init(req);
  return req;
}

void dns_destory(dns_req_t *req)
{
  dns_free(req);
}

/* ------------------------------------------------------------------ */
/*  Public API — build query                                            */
/* ------------------------------------------------------------------ */
int dns_query(dns_req_t *req, dns_type_t type, const char *domain,
              char buffer[DNS_MAX_BUF_SIZE])
{
  int blen = 0, n = 0;
  unsigned char       *buf = (unsigned char *)buffer;
  dns_names_t names[DNS_NAMES_MAX];
  uint16_t tid;

  if (!req || !buffer || !domain)
    return DNS_EBADARG;
  if (type != DNS_A && type != DNS_AAAA)
    return DNS_EBADTYPE;

  /* Allocate TID (skip zero — RFC 1035 discourages it for queries). */
  tid = dns_tid_next();
  if (!tid)
    tid = dns_tid_next();
  req->tid  = tid;
  req->type = type;
  req->cls  = DNS_IN;

  /* Header */
  dns_set_u16(buf, (uint16_t)req->tid, &blen);   /* Transaction ID  */
  dns_set_u16(buf, (uint16_t)0x0100,  &blen);    /* Flags: RD=1     */
  dns_set_u16(buf, (uint16_t)1,       &blen);    /* QDCOUNT = 1     */
  dns_set_u16(buf, (uint16_t)0,       &blen);    /* ANCOUNT  = 0    */
  dns_set_u16(buf, (uint16_t)0,       &blen);    /* NSCOUNT  = 0    */
  dns_set_u16(buf, (uint16_t)0,       &blen);    /* ARCOUNT  = 0    */

  /* Question section */
  dns_split_domain(names, domain, &n);
  dns_write_request(type, buf, names, n, &blen);

  return blen;
}

/* ------------------------------------------------------------------ */
/*  Public API — parse response                                         */
/* ------------------------------------------------------------------ */
int dns_parse(dns_req_t *req, const char *buffer, void *udata,
              dns_parse_callback_t cb)
{
  const unsigned char *buf = (const unsigned char *)buffer;
  int pos = 0;
  uint16_t tid, flags;
  uint16_t questions, answers;
  int i;

  if (!buffer || !req || !cb)
    return DNS_EBADARG;

  /* Header */
  tid   = dns_get_u16(buf, &pos);
  flags = dns_get_u16(buf, &pos);

  if (!dns_unsafe)
  {
    if (tid != req->tid)
      return DNS_EBADTID;
    if ((flags >> 15) != 1)
      return DNS_EBADFLAGS;
  }

  questions   = dns_get_u16(buf, &pos);
  answers     = dns_get_u16(buf, &pos);
  /* authorities  = */ dns_get_u16(buf, &pos);
  /* additional   = */ dns_get_u16(buf, &pos);

  if (questions != 1)
    return DNS_EBADQUEST;

  if (answers == 0)
    return DNS_OK;

  /* Skip question section (domain name + QTYPE + QCLASS). */
  dns_skip_domain(buf, &pos);
  pos += 4;  /* QTYPE(2) + QCLASS(2) */

  /* Answer section */
  for (i = 0; i < answers; i++)
  {
    dns_ans_t  ans;
    dns_type_t dt;
    dns_class_t cls;
    uint32_t   ttl;
    uint16_t   rdlen;

    memset(&ans, 0, sizeof(ans));

    dns_copy_domain(buf, pos, ans.domain, sizeof(ans.domain));
    /* Advance past the (possibly compressed) owner name. */
    pos = dns_copy_domain(buf, pos, NULL, 0);

    dt    = (dns_type_t) dns_get_u16(buf, &pos);
    cls   = (dns_class_t)dns_get_u16(buf, &pos);
    ttl   = dns_get_u32(buf, &pos);
    rdlen = dns_get_u16(buf, &pos);

    ans.type = dt;
    ans.cls  = cls;
    ans.ttl  = ttl;

    switch (dt)
    {
      case DNS_A:
        snprintf(ans.ip, sizeof(ans.ip), "%u.%u.%u.%u",
                 buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
        break;

      case DNS_AAAA:
        snprintf(ans.ip, sizeof(ans.ip),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 buf[pos +  0], buf[pos +  1], buf[pos +  2], buf[pos +  3],
                 buf[pos +  4], buf[pos +  5], buf[pos +  6], buf[pos +  7],
                 buf[pos +  8], buf[pos +  9], buf[pos + 10], buf[pos + 11],
                 buf[pos + 12], buf[pos + 13], buf[pos + 14], buf[pos + 15]);
        break;

      case DNS_CNAME:
        dns_copy_domain(buf, pos, ans.ip, sizeof(ans.ip));
        break;

      default:
        /* Unknown type — skip, don't fail. */
        break;
    }

    cb(udata, &ans);
    pos += rdlen;
  }

  return DNS_OK;
}
