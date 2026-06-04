/*
**  LICENSE: MIT
**  Author: CandyMi[https://github.com/candymi]
*/
#ifndef __XDNS__
#define __XDNS__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define dns_export extern

#define DNS_MAX_BUF_SIZE  (4096)

typedef enum dns_error
{
  DNS_OK           =  0,
  DNS_EBADARG      = -1,  /* Invalid ctx or buffer      */
  DNS_EBADTID      = -2,  /* TID mismatch                */
  DNS_EBADFLAGS    = -3,  /* Unexpected flags            */
  DNS_EBADTYPE     = -4,  /* Unsupported query type      */
  DNS_EBADQUEST    = -5,  /* Unexpected question count   */
  DNS_EBADDATA     = -6,  /* Unexpected answer data      */
} dns_error_t;

typedef enum dns_type
{
  DNS_A     = 1,
  DNS_NS    = 2,
  DNS_CNAME = 5,
  DNS_AAAA  = 28,
} dns_type_t;

typedef enum dns_class
{
  DNS_IN    = 1,
} dns_class_t;

typedef uint16_t dns_tid_t;

typedef struct dns_req
{
  dns_tid_t        tid;
  dns_type_t      type;
  dns_class_t      cls;
} dns_req_t;

/* Concrete answer struct — value semantics, no dangling pointers.
 * ip    : textual IP (IPv4 dotted-decimal or IPv6 colon-hex)
 * domain: owner name from the answer section
 */
typedef struct dns_ans
{
  char           ip[64];
  char       domain[256];
  uint32_t        ttl;
  dns_type_t     type;
  dns_class_t     cls;
} dns_ans_t;

/* Memory allocator hook (realloc-style).
 * Called with (NULL, sz) → malloc, (ptr, 0) → free, (ptr, sz) → realloc.
 */
typedef void *(*dns_realloc_t)(void *ptr, size_t sz);

/* Called once per answer record during dns_parse. */
typedef void (*dns_parse_callback_t)(void *udata, const dns_ans_t *res);

/* ------------------- */

dns_export void dns_set_memhook(dns_realloc_t alloc);

dns_export void dns_set_unsafe(void);

dns_export const char *dns_get_error(int r);

/* ------------------- */

dns_export dns_req_t *dns_new(void);

dns_export void dns_init(dns_req_t *req);

dns_export void dns_destory(dns_req_t *req);

/* ------------------- */

dns_export int dns_query(dns_req_t *req, dns_type_t type, const char *domain, char buffer[DNS_MAX_BUF_SIZE]);

dns_export int dns_parse(dns_req_t *req, const char *buffer, void *udata, dns_parse_callback_t cb);

/* ------------------- */

dns_export const char *dns_get_ip(const dns_ans_t *ans);

dns_export const char *dns_get_domain(const dns_ans_t *ans);

dns_export dns_type_t dns_get_type(const dns_ans_t *ans);

dns_export dns_class_t dns_get_class(const dns_ans_t *ans);

dns_export uint32_t dns_get_ttl(const dns_ans_t *ans);

#endif /* __XDNS__ */
