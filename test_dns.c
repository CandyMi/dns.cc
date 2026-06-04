/*
**  LICENSE: MIT
**  Author: CandyMi[https://github.com/candymi]
**
**  Comprehensive test suite for the pure-C DNS client library.
**  Self-contained — no external test framework required.
**
**  Build:  gcc -std=c99 -Wall -Wextra dns.c test_dns.c -o test_dns
**  Run:    ./test_dns
*/
#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ================================================================== */
/*  Test harness                                                       */
/* ================================================================== */
static int g_pass = 0;
static int g_fail = 0;
static const char *g_curr_test = NULL;

#define TEST(name)  do { g_curr_test = (name); } while (0)

#define CHECK(cond)  do { \
  if (!(cond)) { \
    printf("  FAIL [%s:%d] %s\n", __FILE__, __LINE__, g_curr_test); \
    g_fail++; \
  } else { \
    g_pass++; \
  } \
} while (0)

#define CHECK_EQ(a, b)  do { \
  int _va = (int)(a), _vb = (int)(b); \
  if (_va != _vb) { \
    printf("  FAIL [%s:%d] %s: expected %d, got %d\n", \
           __FILE__, __LINE__, g_curr_test, _vb, _va); \
    g_fail++; \
  } else { \
    g_pass++; \
  } \
} while (0)

#define CHECK_STREQ(a, b)  do { \
  const char *_va = (a), *_vb = (b); \
  if (!_va || !_vb || strcmp(_va, _vb) != 0) { \
    printf("  FAIL [%s:%d] %s: expected '%s', got '%s'\n", \
           __FILE__, __LINE__, g_curr_test, _vb ? _vb : "(null)", _va ? _va : "(null)"); \
    g_fail++; \
  } else { \
    g_pass++; \
  } \
} while (0)

/* ================================================================== */
/*  Wire-format helpers for building test responses                    */
/* ================================================================== */

/* Write a 16-bit big-endian value into buf at *pos. */
static void wr_u16(unsigned char *buf, int *pos, uint16_t v)
{
  buf[(*pos)++] = (unsigned char)(v >> 8);
  buf[(*pos)++] = (unsigned char)(v);
}

static void wr_u32(unsigned char *buf, int *pos, uint32_t v)
{
  buf[(*pos)++] = (unsigned char)(v >> 24);
  buf[(*pos)++] = (unsigned char)(v >> 16);
  buf[(*pos)++] = (unsigned char)(v >>  8);
  buf[(*pos)++] = (unsigned char)(v);
}

/* Write a label-encoded domain name: 3www7example3com0 */
static void wr_domain(unsigned char *buf, int *pos, const char *name)
{
  const char *start = name;
  const char *p;
  for (p = name; ; p++)
  {
    if (*p == '.' || *p == '\0')
    {
      int len = (int)(p - start);
      buf[(*pos)++] = (unsigned char)len;
      memcpy(buf + *pos, start, len);
      *pos += len;
      if (*p == '\0')
      {
        buf[(*pos)++] = 0x00;
        break;
      }
      start = p + 1;
    }
  }
}

/* Write an A record answer. */
static void wr_answer_a(unsigned char *buf, int *pos,
                        const char *name, uint32_t ttl,
                        uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
  wr_domain(buf, pos, name);
  wr_u16(buf, pos, 1);        /* TYPE=A  */
  wr_u16(buf, pos, 1);        /* CLASS=IN */
  wr_u32(buf, pos, ttl);
  wr_u16(buf, pos, 4);        /* RDLENGTH */
  buf[(*pos)++] = a;
  buf[(*pos)++] = b;
  buf[(*pos)++] = c;
  buf[(*pos)++] = d;
}

/* Write an AAAA record answer. */
static void wr_answer_aaaa(unsigned char *buf, int *pos,
                           const char *name, uint32_t ttl,
                           const uint8_t addr[16])
{
  wr_domain(buf, pos, name);
  wr_u16(buf, pos, 28);       /* TYPE=AAAA */
  wr_u16(buf, pos, 1);        /* CLASS=IN  */
  wr_u32(buf, pos, ttl);
  wr_u16(buf, pos, 16);       /* RDLENGTH */
  memcpy(buf + *pos, addr, 16);
  *pos += 16;
}

/* Write a CNAME record answer (rddata = domain name). */
static void wr_answer_cname(unsigned char *buf, int *pos,
                            const char *name, uint32_t ttl,
                            const char *cname)
{
  int save;
  wr_domain(buf, pos, name);
  wr_u16(buf, pos, 5);        /* TYPE=CNAME */
  wr_u16(buf, pos, 1);        /* CLASS=IN   */
  wr_u32(buf, pos, ttl);
  save = *pos;
  wr_u16(buf, pos, 0);        /* placeholder RDLENGTH */
  wr_domain(buf, pos, cname);
  /* Patch RDLENGTH */
  {
    uint16_t rdlen = (uint16_t)(*pos - save - 2);
    buf[save]     = (unsigned char)(rdlen >> 8);
    buf[save + 1] = (unsigned char)(rdlen);
  }
}

/* Build a complete DNS response header + question + answers. */
static int build_dns_response(unsigned char *buf, uint16_t tid,
                               const char *qname, uint16_t qtype)
{
  int pos = 0;
  wr_u16(buf, &pos, tid);         /* Transaction ID  */
  wr_u16(buf, &pos, 0x8180);      /* Flags: QR=1, RD=1, RA=1 */
  wr_u16(buf, &pos, 1);           /* QDCOUNT = 1 */
  wr_u16(buf, &pos, 0);           /* placeholder ANCOUNT */
  wr_u16(buf, &pos, 0);           /* NSCOUNT */
  wr_u16(buf, &pos, 0);           /* ARCOUNT */
  wr_domain(buf, &pos, qname);    /* Question: QNAME */
  wr_u16(buf, &pos, qtype);       /* QTYPE  */
  wr_u16(buf, &pos, 1);           /* QCLASS */
  return pos;  /* answers start at this offset */
}

/* ================================================================== */
/*  Callback collector for parse tests                                  */
/* ================================================================== */
typedef struct
{
  dns_ans_t recs[16];
  int       count;
} collector_t;

static void collector_cb(void *udata, const dns_ans_t *ans)
{
  collector_t *c = (collector_t *)udata;
  if (c->count < 16)
    c->recs[c->count++] = *ans;
}

/* ================================================================== */
/*  dns_query tests                                                     */
/* ================================================================== */
static void test_query_null_args(void)
{
  dns_req_t req;
  char buf[DNS_MAX_BUF_SIZE];

  dns_init(&req);

  TEST("query: NULL req → EBADARG");
  CHECK_EQ(dns_query(NULL, DNS_A, "example.com", buf), DNS_EBADARG);

  TEST("query: NULL buffer → EBADARG");
  CHECK_EQ(dns_query(&req, DNS_A, "example.com", NULL), DNS_EBADARG);

  TEST("query: NULL domain → EBADARG");
  CHECK_EQ(dns_query(&req, DNS_A, NULL, buf), DNS_EBADARG);
}

static void test_query_bad_type(void)
{
  dns_req_t req;
  char buf[DNS_MAX_BUF_SIZE];
  dns_init(&req);

  TEST("query: type=NS → EBADTYPE");
  CHECK_EQ(dns_query(&req, DNS_NS, "example.com", buf), DNS_EBADTYPE);

  TEST("query: type=CNAME → EBADTYPE");
  CHECK_EQ(dns_query(&req, DNS_CNAME, "example.com", buf), DNS_EBADTYPE);
}

static void test_query_a_ok(void)
{
  dns_req_t req;
  char buf[DNS_MAX_BUF_SIZE];
  int r;

  dns_init(&req);
  TEST("query: valid A query succeeds");
  r = dns_query(&req, DNS_A, "www.example.com", buf);
  CHECK(r > 0);
  CHECK_EQ(req.type, DNS_A);
  CHECK_EQ(req.cls, DNS_IN);

  /* Verify header bytes */
  TEST("query: TID bytes match req.tid");
  {
    uint16_t tid_wire = ((uint16_t)(unsigned char)buf[0] << 8)
                      |  (uint16_t)(unsigned char)buf[1];
    CHECK_EQ(tid_wire, req.tid);
  }

  /* Flags: 0x0100 (RD=1) */
  TEST("query: flags = 0x0100 (RD=1)");
  {
    uint16_t flags = ((uint16_t)(unsigned char)buf[2] << 8)
                   |  (uint16_t)(unsigned char)buf[3];
    CHECK_EQ(flags, 0x0100);
  }

  /* QDCOUNT = 1 */
  TEST("query: QDCOUNT = 1");
  {
    uint16_t qdcount = ((uint16_t)(unsigned char)buf[4] << 8)
                     |  (uint16_t)(unsigned char)buf[5];
    CHECK_EQ(qdcount, 1);
  }
}

static void test_query_aaaa_ok(void)
{
  dns_req_t req;
  char buf[DNS_MAX_BUF_SIZE];
  int r;

  dns_init(&req);
  TEST("query: valid AAAA query succeeds");
  r = dns_query(&req, DNS_AAAA, "ipv6.google.com", buf);
  CHECK(r > 0);
  CHECK_EQ(req.type, DNS_AAAA);
}

static void test_query_tid_increments(void)
{
  dns_req_t req1, req2;
  char buf[DNS_MAX_BUF_SIZE];

  dns_init(&req1);
  dns_init(&req2);

  dns_query(&req1, DNS_A, "a.example.com", buf);
  dns_query(&req2, DNS_A, "b.example.com", buf);

  TEST("query: TID increments between calls");
  CHECK(req2.tid == req1.tid + 1 || req2.tid == 1);
  /* Note: req2.tid == 1 when req1.tid wrapped from 65535 to 0 (skip) */
}

static void test_query_single_label(void)
{
  dns_req_t req;
  char buf[DNS_MAX_BUF_SIZE];
  int r;

  dns_init(&req);
  TEST("query: single-label domain 'localhost'");
  r = dns_query(&req, DNS_A, "localhost", buf);
  CHECK(r > 0);
}

static void test_query_max_labels(void)
{
  dns_req_t req;
  char buf[DNS_MAX_BUF_SIZE];
  int r;

  dns_init(&req);
  TEST("query: 5-label domain");
  r = dns_query(&req, DNS_A, "a.b.c.d.example.com", buf);
  CHECK(r > 0);
}

static void test_query_byte_count(void)
{
  dns_req_t req;
  char buf[DNS_MAX_BUF_SIZE];
  int r;

  dns_init(&req);
  /* Header=12 + "www.example.com"=17 + QTYPE=2 + QCLASS=2 = 33 */
  r = dns_query(&req, DNS_A, "www.example.com", buf);
  TEST("query: byte count for www.example.com A");
  CHECK_EQ(r, 33);
}

/* ================================================================== */
/*  dns_parse tests                                                     */
/* ================================================================== */
static void test_parse_null_args(void)
{
  dns_req_t req;
  char buf[64];
  collector_t col;

  dns_init(&req);
  req.tid = 1;

  TEST("parse: NULL buffer → EBADARG");
  CHECK_EQ(dns_parse(&req, NULL, &col, collector_cb), DNS_EBADARG);

  TEST("parse: NULL req → EBADARG");
  CHECK_EQ(dns_parse(NULL, buf, &col, collector_cb), DNS_EBADARG);

  TEST("parse: NULL callback → EBADARG");
  CHECK_EQ(dns_parse(&req, buf, &col, NULL), DNS_EBADARG);
}

static void test_parse_bad_tid(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int hdr_end, ans_pos;
  uint16_t ancount;

  dns_init(&req);
  req.tid = 0x1234;

  /* Build response with TID=0x5678 (mismatch). */
  hdr_end = build_dns_response(buf, 0x5678, "example.com", 1);
  ans_pos = hdr_end;
  wr_answer_a(buf, &ans_pos, "example.com", 300, 93, 184, 216, 34);
  ancount = 1;
  buf[6] = (unsigned char)(ancount >> 8);
  buf[7] = (unsigned char)(ancount);

  TEST("parse: TID mismatch → EBADTID");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_EBADTID);
}

static void test_parse_bad_flags(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int hdr_end, ans_pos;

  dns_init(&req);
  req.tid = 0x42;

  hdr_end = build_dns_response(buf, 0x42, "example.com", 1);
  /* Overwrite flags: QR=0 (query, not response). */
  buf[2] = 0x01;
  buf[3] = 0x00;
  ans_pos = hdr_end;
  wr_answer_a(buf, &ans_pos, "example.com", 300, 1, 2, 3, 4);
  buf[6] = 0x00;
  buf[7] = 0x01;

  TEST("parse: QR=0 (not a response) → EBADFLAGS");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_EBADFLAGS);
}

static void test_parse_bad_questions(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;

  dns_init(&req);
  req.tid = 0x99;

  /* Build a response with QDCOUNT=2. */
  {
    int pos = 0;
    wr_u16(buf, &pos, 0x99);     /* TID */
    wr_u16(buf, &pos, 0x8180);   /* Flags */
    wr_u16(buf, &pos, 2);        /* QDCOUNT=2 — bad */
    wr_u16(buf, &pos, 0);        /* ANCOUNT=0 */
    wr_u16(buf, &pos, 0);
    wr_u16(buf, &pos, 0);
  }

  TEST("parse: QDCOUNT != 1 → EBADQUEST");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_EBADQUEST);
}

static void test_parse_zero_answers(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;

  dns_init(&req);
  req.tid = 0x10;

  {
    int pos = 0;
    wr_u16(buf, &pos, 0x10);     /* TID */
    wr_u16(buf, &pos, 0x8183);   /* Flags: NXDOMAIN */
    wr_u16(buf, &pos, 1);        /* QDCOUNT=1 */
    wr_u16(buf, &pos, 0);        /* ANCOUNT=0 */
    wr_u16(buf, &pos, 0);
    wr_u16(buf, &pos, 0);
    wr_domain(buf, &pos, "nx.example.com");
    wr_u16(buf, &pos, 1);        /* QTYPE=A */
    wr_u16(buf, &pos, 1);        /* QCLASS=IN */
  }

  memset(&col, 0, sizeof(col));
  TEST("parse: 0 answers → OK, no callbacks");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);
  CHECK_EQ(col.count, 0);
}

static void test_parse_a_record(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int hdr_end, ans_pos;
  uint16_t ancount;

  dns_init(&req);
  req.tid = 0x2001;

  hdr_end = build_dns_response(buf, 0x2001, "www.example.com", 1);
  ans_pos = hdr_end;
  wr_answer_a(buf, &ans_pos, "www.example.com", 3600, 93, 184, 216, 34);
  ancount = 1;
  buf[6] = (unsigned char)(ancount >> 8);
  buf[7] = (unsigned char)(ancount);

  memset(&col, 0, sizeof(col));
  TEST("parse: single A record → OK");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);

  TEST("parse: A record — 1 callback");
  CHECK_EQ(col.count, 1);

  TEST("parse: A record — type=A");
  CHECK_EQ(col.recs[0].type, DNS_A);

  TEST("parse: A record — TTL=3600");
  CHECK_EQ(col.recs[0].ttl, 3600);

  TEST("parse: A record — ip = 93.184.216.34");
  CHECK_STREQ(col.recs[0].ip, "93.184.216.34");

  TEST("parse: A record — domain = www.example.com");
  CHECK_STREQ(col.recs[0].domain, "www.example.com");
}

static void test_parse_aaaa_record(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int hdr_end, ans_pos;
  uint16_t ancount;
  static const uint8_t addr[16] =
    { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

  dns_init(&req);
  req.tid = 0x3001;

  hdr_end = build_dns_response(buf, 0x3001, "ipv6.example.com", 28);
  ans_pos = hdr_end;
  wr_answer_aaaa(buf, &ans_pos, "ipv6.example.com", 7200, addr);
  ancount = 1;
  buf[6] = (unsigned char)(ancount >> 8);
  buf[7] = (unsigned char)(ancount);

  memset(&col, 0, sizeof(col));
  TEST("parse: single AAAA record → OK");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);

  TEST("parse: AAAA record — type=AAAA");
  CHECK_EQ(col.recs[0].type, DNS_AAAA);

  TEST("parse: AAAA record — ip");
  CHECK_STREQ(col.recs[0].ip,
              "2001:0db8:0000:0000:0000:0000:0000:0001");
}

static void test_parse_cname_record(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int hdr_end, ans_pos;
  uint16_t ancount;

  dns_init(&req);
  req.tid = 0x4001;

  hdr_end = build_dns_response(buf, 0x4001, "alias.example.com", 5);
  ans_pos = hdr_end;
  wr_answer_cname(buf, &ans_pos, "alias.example.com", 1800,
                  "real.example.com");
  ancount = 1;
  buf[6] = (unsigned char)(ancount >> 8);
  buf[7] = (unsigned char)(ancount);

  memset(&col, 0, sizeof(col));
  TEST("parse: CNAME record → OK");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);

  TEST("parse: CNAME record — type=CNAME");
  CHECK_EQ(col.recs[0].type, DNS_CNAME);

  TEST("parse: CNAME record — ip = CNAME target");
  CHECK_STREQ(col.recs[0].ip, "real.example.com");
}

static void test_parse_multiple_answers(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int hdr_end, ans_pos;
  uint16_t ancount;

  dns_init(&req);
  req.tid = 0x5001;

  hdr_end = build_dns_response(buf, 0x5001, "multi.example.com", 1);
  ans_pos = hdr_end;
  /* 3 answers: A + AAAA + CNAME */
  wr_answer_a(buf, &ans_pos, "multi.example.com", 100, 10, 0, 0, 1);
  wr_answer_aaaa(buf, &ans_pos, "multi.example.com", 200,
    ((const uint8_t[16]){0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1}));
  wr_answer_cname(buf, &ans_pos, "multi.example.com", 300,
                  "target.example.com");
  ancount = 3;
  buf[6] = (unsigned char)(ancount >> 8);
  buf[7] = (unsigned char)(ancount);

  memset(&col, 0, sizeof(col));
  TEST("parse: 3 answers → OK");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);

  TEST("parse: 3 answers → count=3");
  CHECK_EQ(col.count, 3);

  TEST("parse: answer[0] = A,   10.0.0.1");
  CHECK_EQ(col.recs[0].type, DNS_A);
  CHECK_STREQ(col.recs[0].ip, "10.0.0.1");

  TEST("parse: answer[1] = AAAA, fe80::1");
  CHECK_EQ(col.recs[1].type, DNS_AAAA);

  TEST("parse: answer[2] = CNAME, target.example.com");
  CHECK_EQ(col.recs[2].type, DNS_CNAME);
  CHECK_STREQ(col.recs[2].ip, "target.example.com");
}

static void test_parse_unsafe_mode(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int hdr_end, ans_pos;
  uint16_t ancount;

  dns_init(&req);
  req.tid = 0x9999;  /* will NOT match wire TID */

  hdr_end = build_dns_response(buf, 0x1111 /* different TID */,
                               "unsafe.example.com", 1);
  ans_pos = hdr_end;
  wr_answer_a(buf, &ans_pos, "unsafe.example.com", 60, 127, 0, 0, 1);
  ancount = 1;
  buf[6] = (unsigned char)(ancount >> 8);
  buf[7] = (unsigned char)(ancount);

  memset(&col, 0, sizeof(col));

  /* With unsafe mode, TID + flags checks are skipped. */
  dns_set_unsafe();

  TEST("parse: unsafe mode — TID mismatch is ignored");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);
  CHECK_EQ(col.count, 1);

  /* Reset unsafe flag for other tests. */
  {
    /* Re-enable safe mode by rebuilding the library state.
     * dns_set_unsafe has no "off" switch — just note for test isolation. */
  }
}

static void test_parse_ns_record(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int pos = 0;

  dns_init(&req);
  req.tid = 0x42;
  dns_set_unsafe();  /* skip TID/flags checks */

  /* Build a response with an NS record. */
  wr_u16(buf, &pos, 0x42);        /* TID */
  wr_u16(buf, &pos, 0x8180);      /* Flags */
  wr_u16(buf, &pos, 1);           /* QDCOUNT=1 */
  wr_u16(buf, &pos, 1);           /* ANCOUNT=1 */
  wr_u16(buf, &pos, 0);
  wr_u16(buf, &pos, 0);
  wr_domain(buf, &pos, "example.com");
  wr_u16(buf, &pos, 1);           /* QTYPE=A */
  wr_u16(buf, &pos, 1);           /* QCLASS=IN */
  /* Answer: NS record */
  wr_domain(buf, &pos, "example.com");
  wr_u16(buf, &pos, 2);           /* TYPE=NS */
  wr_u16(buf, &pos, 1);           /* CLASS=IN */
  wr_u32(buf, &pos, 86400);
  {
    int save = pos;
    wr_u16(buf, &pos, 0);         /* RDLENGTH placeholder */
    wr_domain(buf, &pos, "ns1.example.com");
    {
      uint16_t rdlen = (uint16_t)(pos - save - 2);
      buf[save]     = (unsigned char)(rdlen >> 8);
      buf[save + 1] = (unsigned char)(rdlen);
    }
  }

  memset(&col, 0, sizeof(col));
  TEST("parse: NS record — callback fires, ip is empty");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);
  CHECK_EQ(col.count, 1);
  CHECK_EQ(col.recs[0].type, DNS_NS);
  /* NS records don't populate ip (unsupported type → empty string). */
  CHECK_STREQ(col.recs[0].ip, "");
}

/* ================================================================== */
/*  Accessor tests                                                      */
/* ================================================================== */
static void test_accessors(void)
{
  dns_ans_t ans;

  memset(&ans, 0, sizeof(ans));
  ans.type = DNS_A;
  ans.cls  = DNS_IN;
  ans.ttl  = 999;
  strcpy(ans.ip,     "1.2.3.4");
  strcpy(ans.domain, "test.example.com");

  TEST("accessor: dns_get_type → DNS_A");
  CHECK_EQ(dns_get_type(&ans), DNS_A);

  TEST("accessor: dns_get_class → DNS_IN");
  CHECK_EQ(dns_get_class(&ans), DNS_IN);

  TEST("accessor: dns_get_ttl → 999");
  CHECK_EQ(dns_get_ttl(&ans), 999);

  TEST("accessor: dns_get_ip → 1.2.3.4");
  CHECK_STREQ(dns_get_ip(&ans), "1.2.3.4");

  TEST("accessor: dns_get_domain → test.example.com");
  CHECK_STREQ(dns_get_domain(&ans), "test.example.com");
}

/* ================================================================== */
/*  Error string tests                                                   */
/* ================================================================== */
static void test_error_strings(void)
{
  TEST("error: DNS_OK → 'Successed.'");
  CHECK_STREQ(dns_get_error(DNS_OK), "Successed.");

  TEST("error: DNS_EBADARG → non-NULL");
  CHECK(dns_get_error(DNS_EBADARG) != NULL);

  TEST("error: DNS_EBADTID → non-NULL");
  CHECK(dns_get_error(DNS_EBADTID) != NULL);

  TEST("error: DNS_EBADFLAGS → non-NULL");
  CHECK(dns_get_error(DNS_EBADFLAGS) != NULL);

  TEST("error: DNS_EBADTYPE → non-NULL");
  CHECK(dns_get_error(DNS_EBADTYPE) != NULL);

  TEST("error: DNS_EBADQUEST → non-NULL");
  CHECK(dns_get_error(DNS_EBADQUEST) != NULL);

  TEST("error: DNS_EBADDATA → non-NULL");
  CHECK(dns_get_error(DNS_EBADDATA) != NULL);

  TEST("error: out-of-range positive → NULL");
  CHECK(dns_get_error(42) == NULL);

  TEST("error: out-of-range negative → NULL");
  CHECK(dns_get_error(-99) == NULL);
}

/* ================================================================== */
/*  Memory hook tests                                                   */
/* ================================================================== */
static int g_hook_alloc_calls  = 0;
static int g_hook_free_calls   = 0;
static int g_hook_realloc_calls = 0;

static void *test_realloc(void *ptr, size_t sz)
{
  if (!ptr && sz > 0)
    g_hook_alloc_calls++;
  else if (ptr && sz == 0)
    g_hook_free_calls++;
  else
    g_hook_realloc_calls++;
  return realloc(ptr, sz);
}

static void test_memory_hooks(void)
{
  dns_req_t *req;

  g_hook_alloc_calls  = 0;
  g_hook_free_calls   = 0;
  g_hook_realloc_calls = 0;

  dns_set_memhook(test_realloc);

  TEST("memhook: dns_new calls custom allocator");
  req = dns_new();
  CHECK(req != NULL);
  CHECK_EQ(g_hook_alloc_calls, 1);
  CHECK_EQ(g_hook_free_calls, 0);

  TEST("memhook: dns_destory calls custom free");
  dns_destory(req);
  CHECK_EQ(g_hook_free_calls, 1);

  /* Reset to default. */
  dns_set_memhook(realloc);
}

static void test_dns_init_zeros(void)
{
  dns_req_t req;
  /* Fill with garbage first. */
  memset(&req, 0xFF, sizeof(req));
  dns_init(&req);

  TEST("dns_init: zeros tid");
  CHECK_EQ(req.tid, 0);

  TEST("dns_init: zeros type");
  CHECK_EQ(req.type, 0);

  TEST("dns_init: zeros cls");
  CHECK_EQ(req.cls, 0);
}

/* ================================================================== */
/*  Compression pointer tests                                           */
/* ================================================================== */
static void test_parse_compression_pointer(void)
{
  dns_req_t req;
  unsigned char buf[512];
  collector_t col;
  int pos = 0;

  dns_init(&req);
  req.tid = 0x6001;
  dns_set_unsafe();

  /* Build a response where the answer uses a compression pointer
   * back to the question section's QNAME. */
  wr_u16(buf, &pos, 0x6001);       /* TID */
  wr_u16(buf, &pos, 0x8180);       /* Flags */
  wr_u16(buf, &pos, 1);            /* QDCOUNT=1 */
  wr_u16(buf, &pos, 1);            /* ANCOUNT=1 */
  wr_u16(buf, &pos, 0);
  wr_u16(buf, &pos, 0);
  wr_domain(buf, &pos, "compress.example.com");  /* QNAME */
  wr_u16(buf, &pos, 1);            /* QTYPE=A */
  wr_u16(buf, &pos, 1);            /* QCLASS=IN */
  /* Answer: pointer to QNAME (offset 12 = right after header). */
  buf[pos++] = 0xc0;               /* Compression pointer */
  buf[pos++] = 0x0c;               /* offset 12 */
  wr_u16(buf, &pos, 1);            /* TYPE=A */
  wr_u16(buf, &pos, 1);            /* CLASS=IN */
  wr_u32(buf, &pos, 500);
  wr_u16(buf, &pos, 4);            /* RDLENGTH=4 */
  buf[pos++] = 192;
  buf[pos++] = 168;
  buf[pos++] = 1;
  buf[pos++] = 1;

  memset(&col, 0, sizeof(col));
  TEST("parse: compression pointer → resolved domain");
  CHECK_EQ(dns_parse(&req, (const char *)buf, &col, collector_cb),
           DNS_OK);
  CHECK_EQ(col.count, 1);
  CHECK_STREQ(col.recs[0].domain, "compress.example.com");
  CHECK_STREQ(col.recs[0].ip, "192.168.1.1");
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */
int main(void)
{
  printf("=== dns_query tests ===\n");
  test_query_null_args();
  test_query_bad_type();
  test_query_a_ok();
  test_query_aaaa_ok();
  test_query_tid_increments();
  test_query_single_label();
  test_query_max_labels();
  test_query_byte_count();

  printf("\n=== dns_parse tests ===\n");
  test_parse_null_args();
  test_parse_bad_tid();
  test_parse_bad_flags();
  test_parse_bad_questions();
  test_parse_zero_answers();
  test_parse_a_record();
  test_parse_aaaa_record();
  test_parse_cname_record();
  test_parse_multiple_answers();
  test_parse_unsafe_mode();
  test_parse_ns_record();
  test_parse_compression_pointer();

  printf("\n=== accessor tests ===\n");
  test_accessors();

  printf("\n=== error string tests ===\n");
  test_error_strings();

  printf("\n=== memory / lifecycle tests ===\n");
  test_memory_hooks();
  test_dns_init_zeros();

  printf("\n========================================\n");
  printf("  PASS: %d   FAIL: %d   TOTAL: %d\n",
         g_pass, g_fail, g_pass + g_fail);
  printf("========================================\n");

  return g_fail > 0 ? 1 : 0;
}
