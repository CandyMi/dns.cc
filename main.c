/*
**  LICENSE: MIT
**  Author: CandyMi[https://github.com/candymi]
**
**  Demo: build a query and parse a pre-canned DNS response.
*/
#include <stdio.h>
#include <string.h>

#include "dns.h"

static void cb(void *udata, const dns_ans_t *ans)
{
  (void)udata;
  printf("  type=%d  class=%d  ttl=%u\n"
         "  domain='%s'\n"
         "  ip='%s'\n\n",
         dns_get_type(ans),
         dns_get_class(ans),
         dns_get_ttl(ans),
         dns_get_domain(ans),
         dns_get_ip(ans));
}

int main(void)
{
  /* Pre-built DNS response for "ipv6.google.com AAAA" (captured). */
  static const unsigned char resp[] =
    ".o\201\200\000\001\000\002\000\004\000\b"
    "\004ipv6\006google\003com\000\000\034\000\001"
    "\300\f\000\005\000\001\000\000\000i\000\t"
    "\004ipv6\001l\300\021\300-\000\034\000\001\000\000\001,\000\020"
    "$\004h\000@\005\b\021\000\000\000\000\000\000 \016"
    "\300\021\000\002\000\001\000\003\372\334\000\006\003ns2\300\021"
    "\300\021\000\002\000\001\000\003\372\334\000\006\003ns3\300\021"
    "\300\021\000\002\000\001\000\003\372\334\000\006\003ns1\300\021"
    "\300\021\000\002\000\001\000\003\372\334\000\006\003ns4\300\021"
    "\300\202\000\001\000\001\000\000\365A\000\004\330\357 \n"
    "\300\202\000\034\000\001\000\000\365A\000\020"
    " \001H`H\002\0002\000\000\000\000\000\000\000\n"
    "\300^\000\001\000\001\000\000\365A\000\004\330\357\"\n"
    "\300^\000\034\000\001\000\000\365A\000\020"
    " \001H`H\002\0004\000\000\000\000\000\000\000\n"
    "\300p\000\001\000\001\000\000\365A\000\004\330\357$\n"
    "\300p\000\034\000\001\000\000\365A\000\020"
    " \001H`H\002\0006\000\000\000\000\000\000\000\n"
    "\300\224\000\001\000\001\000\000\365A\000\004\330\357&\n"
    "\300\224\000\034\000\001\000\000\365A\000\020"
    " \001H`H\002\0008\000\000\000\000\000\000\000\n";

  dns_req_t *req;
  int r;
  char data[10086];

  req = dns_new();
  if (!req)
  {
    printf("dns_new failed\n");
    return 1;
  }

  dns_set_unsafe();

  /* Build query */
  r = dns_query(req, DNS_A, "ipv6.google.com", data);
  printf("dns_query → %d bytes (error=%s)\n", r,
         r < 0 ? dns_get_error(r) : "n/a");

  /* Parse response */
  printf("\n--- Parsing response ---\n");
  r = dns_parse(req, (const char *)resp, NULL, cb);
  printf("dns_parse → %d (%s)\n", r, dns_get_error(r));

  dns_destory(req);
  return 0;
}
