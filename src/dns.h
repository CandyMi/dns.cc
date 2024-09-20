/*
**  LICENSE: MIT
**  Author: CandyMi[https://github.com/candymi]
*/
#ifndef __XDNS__
#define __XDNS__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#if defined(__cplusplus)
  #if _MSC_VER
    #define dns_export __declspec(dllexport)
  #else
    #define dns_export
  #endif
  extern "C" {
#else
  #define dns_export extern
#endif

#define DNS_MAX_BUF_SIZE  (4096)

typedef enum dns_type
{
  A         = 1,
  NS        = 2,
  CNAME     = 5,
  AAAA      = 28,
} dns_type_t;

typedef enum dns_class
{
  IN        = 1,
} dns_class_t;

typedef uint16_t dns_tid_t;

typedef struct dns_req
{
  dns_tid_t        tid;
  dns_type_t      type;
  dns_class_t      cls;
} dns_req_t;

struct dns_ans;
typedef struct dns_ans dns_ans_t;

/* Memory Allocation Type (realloc.) */
typedef void *(*dns_realloc_t)(void*, size_t);
/* Called once each time an Answer is found. */
typedef void (*dns_parse_callback_t)(void *udata, const dns_ans_t *res);

/* ------------------- */

dns_export void dns_set_memhook(dns_realloc_t alloc);

dns_export void dns_set_unsafe();

dns_export const char *dns_get_error(int r);

/* ------------------- */

dns_export dns_req_t *dns_new();

dns_export void dns_init(dns_req_t *req);

dns_export void dns_destory(dns_req_t *req);

/* ------------------- */

dns_export int dns_query(dns_req_t *req, const dns_type_t type, const char *domain, char buffer[DNS_MAX_BUF_SIZE]);

dns_export int dns_parse(dns_req_t *req, const char *buffer, void *udata, dns_parse_callback_t cb);

/* ------------------- */

dns_export const char *dns_get_ip(const dns_ans_t *ans);

dns_export const char *dns_get_domain(const dns_ans_t *ans);

dns_export dns_type_t dns_get_type(const dns_ans_t *ans);

dns_export dns_class_t dns_get_class(const dns_ans_t *ans);

dns_export uint32_t dns_get_ttl(const dns_ans_t *ans);

#if defined(__cplusplus)
}
#endif

#endif
