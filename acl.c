#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acl.h"
#include "log.h"

/* ===========================================================================
 * Minimal JSON parser (dependency-free)
 *
 * Supports the subset emitted by the hcl2acl helper: objects, arrays, strings,
 * numbers, booleans and null. Strings handle the standard escapes plus \uXXXX
 * (BMP). This is deliberately small; socket_vmnet vendors no third-party code.
 * ===========================================================================*/

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;

typedef struct jnode {
  jtype type;
  bool b;
  double num;
  char *str;           /* J_STR value (owned) */
  struct jnode **vals; /* J_ARR / J_OBJ children (owned) */
  char **keys;         /* J_OBJ keys (owned), parallel to vals; NULL for arrays */
  size_t n;
} jnode;

typedef struct {
  const char *p;
  const char *end;
} jcur;

static void jfree(jnode *v) {
  if (v == NULL)
    return;
  free(v->str);
  for (size_t i = 0; i < v->n; i++) {
    jfree(v->vals[i]);
    if (v->keys != NULL)
      free(v->keys[i]);
  }
  free(v->vals);
  free(v->keys);
  free(v);
}

static void jskip_ws(jcur *c) {
  while (c->p < c->end && isspace((unsigned char)*c->p))
    c->p++;
}

static jnode *jparse_value(jcur *c);

static void jutf8_encode(uint32_t cp, char **out) {
  if (cp < 0x80) {
    *(*out)++ = (char)cp;
  } else if (cp < 0x800) {
    *(*out)++ = (char)(0xC0 | (cp >> 6));
    *(*out)++ = (char)(0x80 | (cp & 0x3F));
  } else {
    *(*out)++ = (char)(0xE0 | (cp >> 12));
    *(*out)++ = (char)(0x80 | ((cp >> 6) & 0x3F));
    *(*out)++ = (char)(0x80 | (cp & 0x3F));
  }
}

/* Parse a JSON string starting at the opening quote. Returns a malloc'd C
 * string, or NULL on error. */
static char *jparse_string_raw(jcur *c) {
  if (c->p >= c->end || *c->p != '"')
    return NULL;
  c->p++;
  /* The decoded string is never longer than the encoded one. */
  char *out = malloc((size_t)(c->end - c->p) + 1);
  if (out == NULL)
    return NULL;
  char *w = out;
  while (c->p < c->end && *c->p != '"') {
    char ch = *c->p++;
    if (ch != '\\') {
      *w++ = ch;
      continue;
    }
    if (c->p >= c->end)
      goto err;
    char esc = *c->p++;
    switch (esc) {
    case '"':
      *w++ = '"';
      break;
    case '\\':
      *w++ = '\\';
      break;
    case '/':
      *w++ = '/';
      break;
    case 'b':
      *w++ = '\b';
      break;
    case 'f':
      *w++ = '\f';
      break;
    case 'n':
      *w++ = '\n';
      break;
    case 'r':
      *w++ = '\r';
      break;
    case 't':
      *w++ = '\t';
      break;
    case 'u': {
      if (c->end - c->p < 4)
        goto err;
      uint32_t cp = 0;
      for (int i = 0; i < 4; i++) {
        char h = *c->p++;
        cp <<= 4;
        if (h >= '0' && h <= '9')
          cp |= (uint32_t)(h - '0');
        else if (h >= 'a' && h <= 'f')
          cp |= (uint32_t)(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F')
          cp |= (uint32_t)(h - 'A' + 10);
        else
          goto err;
      }
      jutf8_encode(cp, &w);
      break;
    }
    default:
      goto err;
    }
  }
  if (c->p >= c->end || *c->p != '"')
    goto err;
  c->p++; /* closing quote */
  *w = '\0';
  return out;
err:
  free(out);
  return NULL;
}

static jnode *jparse_string(jcur *c) {
  char *s = jparse_string_raw(c);
  if (s == NULL)
    return NULL;
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL) {
    free(s);
    return NULL;
  }
  v->type = J_STR;
  v->str = s;
  return v;
}

static jnode *jparse_number(jcur *c) {
  char *endp = NULL;
  errno = 0;
  double d = strtod(c->p, &endp);
  if (endp == c->p || endp > c->end)
    return NULL;
  c->p = endp;
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = J_NUM;
  v->num = d;
  return v;
}

static jnode *jparse_literal(jcur *c, const char *lit, jtype type, bool bval) {
  size_t len = strlen(lit);
  if ((size_t)(c->end - c->p) < len || strncmp(c->p, lit, len) != 0)
    return NULL;
  c->p += len;
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = type;
  v->b = bval;
  return v;
}

static bool jpush(jnode *parent, char *key, jnode *child) {
  jnode **nv = realloc(parent->vals, sizeof(*nv) * (parent->n + 1));
  if (nv == NULL)
    return false;
  parent->vals = nv;
  if (key != NULL) {
    char **nk = realloc(parent->keys, sizeof(*nk) * (parent->n + 1));
    if (nk == NULL)
      return false;
    parent->keys = nk;
    parent->keys[parent->n] = key;
  }
  parent->vals[parent->n] = child;
  parent->n++;
  return true;
}

static jnode *jparse_array(jcur *c) {
  c->p++; /* '[' */
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = J_ARR;
  jskip_ws(c);
  if (c->p < c->end && *c->p == ']') {
    c->p++;
    return v;
  }
  for (;;) {
    jskip_ws(c);
    jnode *item = jparse_value(c);
    if (item == NULL)
      goto err;
    if (!jpush(v, NULL, item)) {
      jfree(item);
      goto err;
    }
    jskip_ws(c);
    if (c->p >= c->end)
      goto err;
    if (*c->p == ',') {
      c->p++;
      continue;
    }
    if (*c->p == ']') {
      c->p++;
      return v;
    }
    goto err;
  }
err:
  jfree(v);
  return NULL;
}

static jnode *jparse_object(jcur *c) {
  c->p++; /* '{' */
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = J_OBJ;
  jskip_ws(c);
  if (c->p < c->end && *c->p == '}') {
    c->p++;
    return v;
  }
  for (;;) {
    jskip_ws(c);
    char *key = jparse_string_raw(c);
    if (key == NULL)
      goto err;
    jskip_ws(c);
    if (c->p >= c->end || *c->p != ':') {
      free(key);
      goto err;
    }
    c->p++;
    jskip_ws(c);
    jnode *val = jparse_value(c);
    if (val == NULL) {
      free(key);
      goto err;
    }
    if (!jpush(v, key, val)) {
      free(key);
      jfree(val);
      goto err;
    }
    jskip_ws(c);
    if (c->p >= c->end)
      goto err;
    if (*c->p == ',') {
      c->p++;
      continue;
    }
    if (*c->p == '}') {
      c->p++;
      return v;
    }
    goto err;
  }
err:
  jfree(v);
  return NULL;
}

static jnode *jparse_value(jcur *c) {
  jskip_ws(c);
  if (c->p >= c->end)
    return NULL;
  switch (*c->p) {
  case '{':
    return jparse_object(c);
  case '[':
    return jparse_array(c);
  case '"':
    return jparse_string(c);
  case 't':
    return jparse_literal(c, "true", J_BOOL, true);
  case 'f':
    return jparse_literal(c, "false", J_BOOL, false);
  case 'n':
    return jparse_literal(c, "null", J_NULL, false);
  default:
    return jparse_number(c);
  }
}

static const jnode *jget(const jnode *obj, const char *key) {
  if (obj == NULL || obj->type != J_OBJ)
    return NULL;
  for (size_t i = 0; i < obj->n; i++) {
    if (strcmp(obj->keys[i], key) == 0)
      return obj->vals[i];
  }
  return NULL;
}

/* ===========================================================================
 * ACL model and matcher
 * ===========================================================================*/

enum acl_action { ACL_DENY = 0, ACL_ALLOW = 1 };
enum rule_dir { RDIR_ANY = 0, RDIR_EGRESS, RDIR_INGRESS };

struct rule {
  enum acl_action action;
  enum rule_dir dir;

  bool has_src_mac, has_dst_mac;
  uint8_t src_mac[6], dst_mac[6];

  bool has_src_cidr, has_dst_cidr;
  uint32_t src_net, src_mask; /* host byte order */
  uint32_t dst_net, dst_mask;

  int proto; /* -1 = any, else IP protocol number */

  bool has_sport, has_dport;
  int sport_min, sport_max;
  int dport_min, dport_max;
};

struct acl {
  enum acl_action default_action;
  struct rule *rules;
  size_t n;
};

static bool parse_mac(const char *s, uint8_t out[6]) {
  unsigned v[6];
  if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
    return false;
  for (int i = 0; i < 6; i++) {
    if (v[i] > 0xFF)
      return false;
    out[i] = (uint8_t)v[i];
  }
  return true;
}

static bool parse_cidr(const char *s, uint32_t *net, uint32_t *mask) {
  unsigned a, b, c, d, bits;
  if (sscanf(s, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &bits) != 5)
    return false;
  if (a > 255 || b > 255 || c > 255 || d > 255 || bits > 32)
    return false;
  uint32_t ip = (a << 24) | (b << 16) | (c << 8) | d;
  uint32_t m = bits == 0 ? 0 : (0xFFFFFFFFu << (32 - bits));
  *net = ip & m;
  *mask = m;
  return true;
}

static int proto_number(const char *s) {
  if (strcmp(s, "any") == 0)
    return -1;
  if (strcmp(s, "icmp") == 0)
    return 1;
  if (strcmp(s, "tcp") == 0)
    return 6;
  if (strcmp(s, "udp") == 0)
    return 17;
  return -2; /* invalid */
}

/* Read a port field that is either a number (single port) or a 2-element array
 * [min, max]. Returns false on a malformed value. */
static bool parse_port_field(const jnode *v, bool *has, int *min, int *max) {
  if (v == NULL || v->type == J_NULL) {
    *has = false;
    return true;
  }
  if (v->type == J_NUM) {
    *has = true;
    *min = *max = (int)v->num;
    return true;
  }
  if (v->type == J_ARR && v->n == 2 && v->vals[0]->type == J_NUM && v->vals[1]->type == J_NUM) {
    *has = true;
    *min = (int)v->vals[0]->num;
    *max = (int)v->vals[1]->num;
    return true;
  }
  return false;
}

static bool parse_rule(const jnode *r, struct rule *out) {
  memset(out, 0, sizeof(*out));
  out->proto = -1;

  const jnode *action = jget(r, "action");
  if (action == NULL || action->type != J_STR) {
    ERROR("acl: rule is missing a string \"action\"");
    return false;
  }
  if (strcmp(action->str, "allow") == 0)
    out->action = ACL_ALLOW;
  else if (strcmp(action->str, "deny") == 0)
    out->action = ACL_DENY;
  else {
    ERRORF("acl: invalid action \"%s\" (want allow|deny)", action->str);
    return false;
  }

  const jnode *dir = jget(r, "direction");
  if (dir != NULL && dir->type == J_STR) {
    if (strcmp(dir->str, "any") == 0)
      out->dir = RDIR_ANY;
    else if (strcmp(dir->str, "egress") == 0)
      out->dir = RDIR_EGRESS;
    else if (strcmp(dir->str, "ingress") == 0)
      out->dir = RDIR_INGRESS;
    else {
      ERRORF("acl: invalid direction \"%s\"", dir->str);
      return false;
    }
  }

  const jnode *sm = jget(r, "src_mac");
  if (sm != NULL && sm->type == J_STR) {
    if (!parse_mac(sm->str, out->src_mac)) {
      ERRORF("acl: invalid src_mac \"%s\"", sm->str);
      return false;
    }
    out->has_src_mac = true;
  }
  const jnode *dm = jget(r, "dst_mac");
  if (dm != NULL && dm->type == J_STR) {
    if (!parse_mac(dm->str, out->dst_mac)) {
      ERRORF("acl: invalid dst_mac \"%s\"", dm->str);
      return false;
    }
    out->has_dst_mac = true;
  }

  const jnode *sc = jget(r, "src_cidr");
  if (sc != NULL && sc->type == J_STR) {
    if (!parse_cidr(sc->str, &out->src_net, &out->src_mask)) {
      ERRORF("acl: invalid src_cidr \"%s\"", sc->str);
      return false;
    }
    out->has_src_cidr = true;
  }
  const jnode *dc = jget(r, "dst_cidr");
  if (dc != NULL && dc->type == J_STR) {
    if (!parse_cidr(dc->str, &out->dst_net, &out->dst_mask)) {
      ERRORF("acl: invalid dst_cidr \"%s\"", dc->str);
      return false;
    }
    out->has_dst_cidr = true;
  }

  const jnode *proto = jget(r, "proto");
  if (proto != NULL && proto->type == J_STR) {
    int p = proto_number(proto->str);
    if (p == -2) {
      ERRORF("acl: invalid proto \"%s\"", proto->str);
      return false;
    }
    out->proto = p;
  }

  if (!parse_port_field(jget(r, "src_port"), &out->has_sport, &out->sport_min, &out->sport_max) ||
      !parse_port_field(jget(r, "dst_port"), &out->has_dport, &out->dport_min, &out->dport_max)) {
    ERROR("acl: invalid src_port/dst_port (want a number or [min, max])");
    return false;
  }
  return true;
}

struct acl *acl_load(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    ERRORF("acl: cannot open \"%s\": %s", path, strerror(errno));
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    ERRORN("acl: fseek");
    fclose(fp);
    return NULL;
  }
  long size = ftell(fp);
  if (size < 0) {
    ERRORN("acl: ftell");
    fclose(fp);
    return NULL;
  }
  rewind(fp);
  char *data = malloc((size_t)size + 1);
  if (data == NULL) {
    ERRORN("acl: malloc");
    fclose(fp);
    return NULL;
  }
  size_t got = fread(data, 1, (size_t)size, fp);
  fclose(fp);
  data[got] = '\0';

  jcur c = {.p = data, .end = data + got};
  jnode *root = jparse_value(&c);
  free(data);
  if (root == NULL) {
    ERRORF("acl: failed to parse JSON in \"%s\"", path);
    return NULL;
  }

  struct acl *acl = calloc(1, sizeof(*acl));
  if (acl == NULL) {
    jfree(root);
    return NULL;
  }
  acl->default_action = ACL_ALLOW;
  const jnode *def = jget(root, "default_action");
  if (def != NULL && def->type == J_STR) {
    if (strcmp(def->str, "deny") == 0)
      acl->default_action = ACL_DENY;
    else if (strcmp(def->str, "allow") == 0)
      acl->default_action = ACL_ALLOW;
    else {
      ERRORF("acl: invalid default_action \"%s\"", def->str);
      goto err;
    }
  }

  const jnode *rules = jget(root, "rules");
  if (rules != NULL && rules->type == J_ARR && rules->n > 0) {
    acl->rules = calloc(rules->n, sizeof(*acl->rules));
    if (acl->rules == NULL)
      goto err;
    for (size_t i = 0; i < rules->n; i++) {
      if (rules->vals[i]->type != J_OBJ || !parse_rule(rules->vals[i], &acl->rules[i]))
        goto err;
      acl->n++;
    }
  }

  jfree(root);
  INFOF("acl: loaded %zu rule(s) from \"%s\" (default: %s)", acl->n, path,
        acl->default_action == ACL_ALLOW ? "allow" : "deny");
  return acl;
err:
  jfree(root);
  acl_destroy(acl);
  return NULL;
}

void acl_destroy(struct acl *acl) {
  if (acl == NULL)
    return;
  free(acl->rules);
  free(acl);
}

static bool port_in(int p, int min, int max) { return p >= min && p <= max; }

bool acl_allows(const struct acl *acl, enum acl_dir dir, const uint8_t *frame, size_t len) {
  if (acl == NULL)
    return true;

  /* Only IPv4 is classified in this first version; everything else (ARP, IPv6,
   * runt frames) is allowed so that basic networking keeps working. */
  if (len < 14)
    return true;
  uint16_t ethertype = (uint16_t)((frame[12] << 8) | frame[13]);
  if (ethertype != 0x0800)
    return true;

  const uint8_t *ip = frame + 14;
  size_t iplen = len - 14;
  if (iplen < 20)
    return true;
  size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
  if (ihl < 20 || iplen < ihl)
    return true;
  uint8_t protocol = ip[9];
  uint32_t src = (uint32_t)((ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15]);
  uint32_t dst = (uint32_t)((ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8) | ip[19]);

  int sport = -1, dport = -1;
  if ((protocol == 6 || protocol == 17) && iplen >= ihl + 4) {
    const uint8_t *l4 = ip + ihl;
    sport = (l4[0] << 8) | l4[1];
    dport = (l4[2] << 8) | l4[3];
  }

  enum rule_dir want = dir == ACL_EGRESS ? RDIR_EGRESS : RDIR_INGRESS;
  for (size_t i = 0; i < acl->n; i++) {
    const struct rule *r = &acl->rules[i];
    if (r->dir != RDIR_ANY && r->dir != want)
      continue;
    if (r->has_src_mac && memcmp(frame + 6, r->src_mac, 6) != 0)
      continue;
    if (r->has_dst_mac && memcmp(frame + 0, r->dst_mac, 6) != 0)
      continue;
    if (r->has_src_cidr && (src & r->src_mask) != r->src_net)
      continue;
    if (r->has_dst_cidr && (dst & r->dst_mask) != r->dst_net)
      continue;
    if (r->proto >= 0 && r->proto != protocol)
      continue;
    if (r->has_sport && (sport < 0 || !port_in(sport, r->sport_min, r->sport_max)))
      continue;
    if (r->has_dport && (dport < 0 || !port_in(dport, r->dport_min, r->dport_max)))
      continue;
    return r->action == ACL_ALLOW;
  }
  return acl->default_action == ACL_ALLOW;
}
