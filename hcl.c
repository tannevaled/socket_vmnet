#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acl.h"
#include "hcl.h"
#include "log.h"

/* ===========================================================================
 * Growable string buffer (for emitting JSON)
 * ===========================================================================*/
struct sbuf {
  char *p;
  size_t len, cap;
  bool oom;
};

static void sb_putn(struct sbuf *s, const char *data, size_t n) {
  if (s->oom)
    return;
  if (s->len + n + 1 > s->cap) {
    size_t cap = s->cap ? s->cap * 2 : 256;
    while (cap < s->len + n + 1)
      cap *= 2;
    char *np = realloc(s->p, cap);
    if (np == NULL) {
      s->oom = true;
      return;
    }
    s->p = np;
    s->cap = cap;
  }
  memcpy(s->p + s->len, data, n);
  s->len += n;
  s->p[s->len] = '\0';
}
static void sb_puts(struct sbuf *s, const char *str) { sb_putn(s, str, strlen(str)); }
static void sb_putq(struct sbuf *s, const char *str) { /* quoted (values are simple) */
  sb_puts(s, "\"");
  sb_puts(s, str);
  sb_puts(s, "\"");
}

/* ===========================================================================
 * Lexer
 * ===========================================================================*/
enum tok {
  T_EOF,
  T_ERR,
  T_IDENT,
  T_STRING,
  T_NUMBER,
  T_LBRACE,
  T_RBRACE,
  T_LBRACK,
  T_RBRACK,
  T_EQ,
  T_COMMA,
};

struct lexer {
  const char *p, *end;
  enum tok tok;
  char text[256]; /* current token text (ident/string value/number) */
};

static bool ident_char(int c) { return isalnum(c) || c == '_' || c == '-' || c == '.'; }

static void lex_next(struct lexer *l) {
  /* skip whitespace and comments */
  for (;;) {
    while (l->p < l->end && isspace((unsigned char)*l->p))
      l->p++;
    if (l->p < l->end && *l->p == '#') {
      while (l->p < l->end && *l->p != '\n')
        l->p++;
      continue;
    }
    if (l->end - l->p >= 2 && l->p[0] == '/' && l->p[1] == '/') {
      while (l->p < l->end && *l->p != '\n')
        l->p++;
      continue;
    }
    if (l->end - l->p >= 2 && l->p[0] == '/' && l->p[1] == '*') {
      l->p += 2;
      while (l->end - l->p >= 2 && !(l->p[0] == '*' && l->p[1] == '/'))
        l->p++;
      if (l->end - l->p >= 2)
        l->p += 2;
      continue;
    }
    break;
  }
  if (l->p >= l->end) {
    l->tok = T_EOF;
    return;
  }
  char c = *l->p;
  switch (c) {
  case '{':
    l->p++;
    l->tok = T_LBRACE;
    return;
  case '}':
    l->p++;
    l->tok = T_RBRACE;
    return;
  case '[':
    l->p++;
    l->tok = T_LBRACK;
    return;
  case ']':
    l->p++;
    l->tok = T_RBRACK;
    return;
  case '=':
    l->p++;
    l->tok = T_EQ;
    return;
  case ',':
    l->p++;
    l->tok = T_COMMA;
    return;
  }
  if (c == '"') {
    l->p++;
    size_t n = 0;
    while (l->p < l->end && *l->p != '"') {
      if (n + 1 >= sizeof(l->text)) {
        l->tok = T_ERR;
        return;
      }
      l->text[n++] = *l->p++;
    }
    if (l->p >= l->end) {
      l->tok = T_ERR;
      return;
    }
    l->p++; /* closing quote */
    l->text[n] = '\0';
    l->tok = T_STRING;
    return;
  }
  if (isdigit((unsigned char)c)) {
    size_t n = 0;
    while (l->p < l->end && isdigit((unsigned char)*l->p)) {
      if (n + 1 >= sizeof(l->text)) {
        l->tok = T_ERR;
        return;
      }
      l->text[n++] = *l->p++;
    }
    l->text[n] = '\0';
    l->tok = T_NUMBER;
    return;
  }
  if (ident_char((unsigned char)c)) {
    size_t n = 0;
    while (l->p < l->end && ident_char((unsigned char)*l->p)) {
      if (n + 1 >= sizeof(l->text)) {
        l->tok = T_ERR;
        return;
      }
      l->text[n++] = *l->p++;
    }
    l->text[n] = '\0';
    l->tok = T_IDENT;
    return;
  }
  l->tok = T_ERR;
}

/* ===========================================================================
 * Parser -> JSON
 * ===========================================================================*/

/* A parsed rule: each field is a malloc'd JSON fragment (string fields already
 * quoted; ports a number or [a,b]) or NULL if absent. */
struct rule_kv {
  char *action, *direction, *src_mac, *dst_mac, *src_cidr, *dst_cidr, *proto, *src_port, *dst_port;
};

static void rule_kv_free(struct rule_kv *r) {
  free(r->action);
  free(r->direction);
  free(r->src_mac);
  free(r->dst_mac);
  free(r->src_cidr);
  free(r->dst_cidr);
  free(r->proto);
  free(r->src_port);
  free(r->dst_port);
}

#define HCL_ERR(msg)                                                                               \
  do {                                                                                             \
    ERROR("hcl: " msg);                                                                            \
    return false;                                                                                  \
  } while (0)

/* Parse a value (after '='): a JSON-encoded fragment into *out (malloc'd). */
static bool parse_value(struct lexer *l, char **out) {
  lex_next(l);
  if (l->tok == T_STRING) {
    size_t n = strlen(l->text);
    char *s = malloc(n + 3);
    if (s == NULL)
      return false;
    snprintf(s, n + 3, "\"%s\"", l->text);
    *out = s;
    return true;
  }
  if (l->tok == T_NUMBER) {
    *out = strdup(l->text);
    return *out != NULL;
  }
  if (l->tok == T_LBRACK) {
    /* a list: emit as a JSON array of the (string/number) elements */
    struct sbuf sb = {0};
    sb_puts(&sb, "[");
    bool first = true;
    for (;;) {
      lex_next(l);
      if (l->tok == T_RBRACK)
        break;
      if (l->tok == T_COMMA)
        continue;
      if (!first)
        sb_puts(&sb, ",");
      first = false;
      if (l->tok == T_STRING)
        sb_putq(&sb, l->text);
      else if (l->tok == T_NUMBER)
        sb_puts(&sb, l->text);
      else {
        free(sb.p);
        return false;
      }
    }
    sb_puts(&sb, "]");
    if (sb.oom) {
      free(sb.p);
      return false;
    }
    *out = sb.p;
    return true;
  }
  return false;
}

/* Parse a `rule { ... }` block body (the '{' has been consumed). */
static bool parse_rule_block(struct lexer *l, struct rule_kv *r) {
  for (;;) {
    lex_next(l);
    if (l->tok == T_RBRACE)
      return true;
    if (l->tok != T_IDENT)
      HCL_ERR("expected attribute name in rule");
    char key[64];
    snprintf(key, sizeof(key), "%s", l->text);
    lex_next(l);
    if (l->tok != T_EQ)
      HCL_ERR("expected '=' in rule attribute");
    char *val = NULL;
    if (!parse_value(l, &val))
      HCL_ERR("bad attribute value in rule");
    char **slot = NULL;
    if (strcmp(key, "action") == 0)
      slot = &r->action;
    else if (strcmp(key, "direction") == 0)
      slot = &r->direction;
    else if (strcmp(key, "src_mac") == 0)
      slot = &r->src_mac;
    else if (strcmp(key, "dst_mac") == 0)
      slot = &r->dst_mac;
    else if (strcmp(key, "src_cidr") == 0)
      slot = &r->src_cidr;
    else if (strcmp(key, "dst_cidr") == 0)
      slot = &r->dst_cidr;
    else if (strcmp(key, "proto") == 0)
      slot = &r->proto;
    else if (strcmp(key, "src_port") == 0)
      slot = &r->src_port;
    else if (strcmp(key, "dst_port") == 0)
      slot = &r->dst_port;
    if (slot == NULL) {
      free(val);
      ERRORF("hcl: unknown rule attribute \"%s\"", key);
      return false;
    }
    free(*slot);
    *slot = val;
  }
}

/* Emit one JSON rule object. dir/mac overrides apply to group expansion. */
static void emit_rule(struct sbuf *sb, bool *first, const struct rule_kv *r, const char *dir,
                      const char *src_mac, const char *dst_mac) {
  if (!*first)
    sb_puts(sb, ",");
  *first = false;
  sb_puts(sb, "{");
  bool f2 = true;
#define FIELD(name, jsonval)                                                                       \
  do {                                                                                             \
    if (jsonval) {                                                                                 \
      if (!f2)                                                                                     \
        sb_puts(sb, ",");                                                                          \
      f2 = false;                                                                                  \
      sb_puts(sb, "\"" name "\":");                                                                \
      sb_puts(sb, jsonval);                                                                        \
    }                                                                                              \
  } while (0)
#define FIELD_Q(name, str)                                                                         \
  do {                                                                                             \
    if (str) {                                                                                     \
      if (!f2)                                                                                     \
        sb_puts(sb, ",");                                                                          \
      f2 = false;                                                                                  \
      sb_puts(sb, "\"" name "\":");                                                                \
      sb_putq(sb, str);                                                                            \
    }                                                                                              \
  } while (0)
  FIELD("action", r->action);
  FIELD("direction", dir ? NULL : r->direction); /* overridden below if dir set */
  if (dir)
    FIELD_Q("direction", dir);
  FIELD("src_mac", src_mac ? NULL : r->src_mac);
  if (src_mac)
    FIELD_Q("src_mac", src_mac);
  FIELD("dst_mac", dst_mac ? NULL : r->dst_mac);
  if (dst_mac)
    FIELD_Q("dst_mac", dst_mac);
  FIELD("src_cidr", r->src_cidr);
  FIELD("dst_cidr", r->dst_cidr);
  FIELD("proto", r->proto);
  FIELD("src_port", r->src_port);
  FIELD("dst_port", r->dst_port);
#undef FIELD
#undef FIELD_Q
  sb_puts(sb, "}");
}

#define MAX_MEMBERS 256

/* Parse a `group "name" { ... }` body (the '{' has been consumed), emitting the
 * expanded rules. */
static bool parse_group_block(struct lexer *l, struct sbuf *sb, bool *first) {
  char *members[MAX_MEMBERS];
  int nmember = 0;
  bool ok = true;
  for (;;) {
    lex_next(l);
    if (l->tok == T_RBRACE)
      break;
    if (l->tok != T_IDENT) {
      ERROR("hcl: expected attribute or rule in group");
      ok = false;
      break;
    }
    if (strcmp(l->text, "member_mac") == 0) {
      lex_next(l);
      if (l->tok != T_EQ) {
        ERROR("hcl: expected '=' after member_mac");
        ok = false;
        break;
      }
      lex_next(l);
      if (l->tok != T_LBRACK) {
        ERROR("hcl: member_mac must be a list");
        ok = false;
        break;
      }
      for (;;) {
        lex_next(l);
        if (l->tok == T_RBRACK)
          break;
        if (l->tok == T_COMMA)
          continue;
        if (l->tok != T_STRING) {
          ERROR("hcl: member_mac entries must be strings");
          ok = false;
          break;
        }
        if (nmember >= MAX_MEMBERS) {
          ERROR("hcl: too many member_mac entries");
          ok = false;
          break;
        }
        members[nmember++] = strdup(l->text);
      }
      if (!ok)
        break;
    } else if (strcmp(l->text, "rule") == 0) {
      lex_next(l);
      if (l->tok != T_LBRACE) {
        ERROR("hcl: expected '{' after rule");
        ok = false;
        break;
      }
      struct rule_kv r = {0};
      if (!parse_rule_block(l, &r)) {
        rule_kv_free(&r);
        ok = false;
        break;
      }
      if (nmember == 0) {
        ERROR("hcl: group rule appears before member_mac");
        rule_kv_free(&r);
        ok = false;
        break;
      }
      const char *d = r.direction; /* note: r.direction is JSON-quoted, e.g. "egress" */
      bool any = (d == NULL) || strcmp(d, "\"any\"") == 0;
      bool egress = any || strcmp(d, "\"egress\"") == 0;
      bool ingress = any || strcmp(d, "\"ingress\"") == 0;
      for (int i = 0; i < nmember; i++) {
        if (egress)
          emit_rule(sb, first, &r, "egress", members[i], NULL);
        if (ingress)
          emit_rule(sb, first, &r, "ingress", NULL, members[i]);
      }
      rule_kv_free(&r);
    } else {
      ERRORF("hcl: unknown group attribute \"%s\"", l->text);
      ok = false;
      break;
    }
  }
  for (int i = 0; i < nmember; i++)
    free(members[i]);
  return ok;
}

char *hcl_to_json(const char *src, size_t len) {
  struct lexer l = {.p = src, .end = src + len};
  struct sbuf sb = {0};
  char *default_action = NULL;
  bool first = true;
  bool ok = true;

  sb_puts(&sb, "{\"rules\":[");
  for (;;) {
    lex_next(&l);
    if (l.tok == T_EOF)
      break;
    if (l.tok != T_IDENT) {
      ERROR("hcl: expected default_action, group or rule at top level");
      ok = false;
      break;
    }
    if (strcmp(l.text, "default_action") == 0) {
      lex_next(&l);
      if (l.tok != T_EQ) {
        ERROR("hcl: expected '=' after default_action");
        ok = false;
        break;
      }
      lex_next(&l);
      if (l.tok != T_STRING) {
        ERROR("hcl: default_action must be a string");
        ok = false;
        break;
      }
      free(default_action);
      default_action = strdup(l.text);
    } else if (strcmp(l.text, "rule") == 0) {
      lex_next(&l);
      if (l.tok != T_LBRACE) {
        ERROR("hcl: expected '{' after rule");
        ok = false;
        break;
      }
      struct rule_kv r = {0};
      if (!parse_rule_block(&l, &r)) {
        rule_kv_free(&r);
        ok = false;
        break;
      }
      emit_rule(&sb, &first, &r, NULL, NULL, NULL);
      rule_kv_free(&r);
    } else if (strcmp(l.text, "group") == 0) {
      lex_next(&l);
      if (l.tok != T_STRING) { /* the group label */
        ERROR("hcl: expected a name after group");
        ok = false;
        break;
      }
      lex_next(&l);
      if (l.tok != T_LBRACE) {
        ERROR("hcl: expected '{' after group name");
        ok = false;
        break;
      }
      if (!parse_group_block(&l, &sb, &first)) {
        ok = false;
        break;
      }
    } else {
      ERRORF("hcl: unexpected top-level keyword \"%s\"", l.text);
      ok = false;
      break;
    }
  }
  sb_puts(&sb, "]");
  if (default_action != NULL) {
    sb_puts(&sb, ",\"default_action\":");
    sb_putq(&sb, default_action);
  }
  sb_puts(&sb, "}");
  free(default_action);

  if (!ok || sb.oom) {
    free(sb.p);
    return NULL;
  }
  return sb.p;
}

struct acl *hcl_load(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    ERRORF("hcl: cannot open \"%s\": %s", path, strerror(errno));
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0 || ftell(fp) < 0) {
    ERRORN("hcl: seek");
    fclose(fp);
    return NULL;
  }
  long size = ftell(fp);
  rewind(fp);
  char *data = malloc((size_t)size + 1);
  if (data == NULL) {
    ERRORN("hcl: malloc");
    fclose(fp);
    return NULL;
  }
  size_t got = fread(data, 1, (size_t)size, fp);
  fclose(fp);
  data[got] = '\0';

  char *json = hcl_to_json(data, got);
  free(data);
  if (json == NULL) {
    ERRORF("hcl: failed to compile \"%s\"", path);
    return NULL;
  }
  struct acl *acl = acl_parse(json, strlen(json));
  free(json);
  return acl;
}
