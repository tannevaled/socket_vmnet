#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "acl.h"
#include "acl_hcl.h" /* acl_load_hcl */
#include "conntrack.h"
#include "control.h"
#include "daemon.h"
#include "json.h" /* libfw/c-fw JSON reader (request parsing) */
#include "log.h"

#define CTL_RING_CAP 1024u        /* recent events kept for polling */
#define CTL_MAX_LINE (256 * 1024) /* request line cap (set_acl can be large) */

struct ctl_event {
  uint64_t seq;
  uint64_t ts;
  uint8_t dir;   /* 0 egress, 1 ingress */
  uint8_t allow; /* 0/1 */
  int32_t rule;  /* matched rule index, or -1 */
  uint32_t len;
  int family; /* 0 if non-IP */
  int proto;
  int sport, dport;
  uint8_t src[16], dst[16];
};

struct control {
  struct state *state;
  char *path;
  int listen_fd;
  pthread_t thread;
  volatile bool running;
  pthread_mutex_t ring_mtx;
  struct ctl_event *ring;
  uint64_t seq; /* total events recorded (next sequence number) */
};

/* ----- tiny growable output buffer -------------------------------------- */

struct sb {
  char *p;
  size_t len, cap;
  bool oom;
};

static void sb_put(struct sb *s, const char *d, size_t n) {
  if (s->oom)
    return;
  if (s->len + n + 1 > s->cap) {
    size_t nc = s->cap ? s->cap * 2 : 256;
    while (nc < s->len + n + 1)
      nc *= 2;
    char *np = realloc(s->p, nc);
    if (np == NULL) {
      s->oom = true;
      return;
    }
    s->p = np;
    s->cap = nc;
  }
  memcpy(s->p + s->len, d, n);
  s->len += n;
  s->p[s->len] = '\0';
}

static void sb_puts(struct sb *s, const char *str) { sb_put(s, str, strlen(str)); }

static void sb_u64(struct sb *s, uint64_t v) {
  char b[24];
  snprintf(b, sizeof b, "%llu", (unsigned long long)v);
  sb_puts(s, b);
}

static void sb_i64(struct sb *s, long long v) {
  char b[24];
  snprintf(b, sizeof b, "%lld", v);
  sb_puts(s, b);
}

/* append a JSON string literal (with surrounding quotes), escaping as needed. */
static void sb_jstr(struct sb *s, const char *str) {
  sb_put(s, "\"", 1);
  for (const unsigned char *p = (const unsigned char *)str; *p; p++) {
    switch (*p) {
    case '"':
      sb_puts(s, "\\\"");
      break;
    case '\\':
      sb_puts(s, "\\\\");
      break;
    case '\n':
      sb_puts(s, "\\n");
      break;
    case '\r':
      sb_puts(s, "\\r");
      break;
    case '\t':
      sb_puts(s, "\\t");
      break;
    default:
      if (*p < 0x20) {
        char b[8];
        snprintf(b, sizeof b, "\\u%04x", *p);
        sb_puts(s, b);
      } else {
        sb_put(s, (const char *)p, 1);
      }
    }
  }
  sb_put(s, "\"", 1);
}

static void sb_ip(struct sb *s, int family, const uint8_t *a) {
  char b[64];
  if (family == 4) {
    snprintf(b, sizeof b, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  } else {
    int o = 0;
    for (int i = 0; i < 16; i += 2)
      o += snprintf(b + o, sizeof b - (size_t)o, "%s%x", i ? ":" : "",
                    (unsigned)((a[i] << 8) | a[i + 1]));
  }
  sb_jstr(s, b);
}

/* ----- ACL load / swap helpers (operate on struct state) ---------------- */

static struct acl *ctl_load_acl_file(const char *path) {
  size_t n = strlen(path);
  if (n >= 4 && strcmp(path + n - 4, ".hcl") == 0)
    return acl_load_hcl(path);
  return acl_load(path);
}

static char *read_file_text(const char *path) {
  FILE *f = fopen(path, "rb");
  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long sz = ftell(f);
  if (sz < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *buf = malloc((size_t)sz + 1);
  if (buf == NULL) {
    fclose(f);
    return NULL;
  }
  size_t rd = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  buf[rd] = '\0';
  return buf;
}

/* Swap in `fresh` (ownership taken) and replace the stored source text with
 * `raw` (ownership taken; may be NULL). Frees the previous ACL/source. */
static void swap_acl(struct state *state, struct acl *fresh, char *raw) {
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  struct acl *old = state->acl;
  char *oldraw = state->acl_json;
  state->acl = fresh;
  state->acl_json = raw;
  dispatch_semaphore_signal(state->sem);
  acl_destroy(old);
  free(oldraw);
}

bool control_set_acl_json(struct state *state, const char *json, size_t len) {
  struct acl *fresh = acl_parse(json, len);
  if (fresh == NULL)
    return false;
  char *raw = malloc(len + 1);
  if (raw != NULL) {
    memcpy(raw, json, len);
    raw[len] = '\0';
  }
  swap_acl(state, fresh, raw);
  return true;
}

bool control_reload_acl(struct state *state) {
  if (state->cliopt == NULL || state->cliopt->acl_path == NULL)
    return false;
  struct acl *fresh = ctl_load_acl_file(state->cliopt->acl_path);
  if (fresh == NULL)
    return false;
  swap_acl(state, fresh, read_file_text(state->cliopt->acl_path));
  return true;
}

void control_reset_stats(struct state *state) {
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  acl_reset_stats(state->acl);
  dispatch_semaphore_signal(state->sem);
}

/* ----- event ring ------------------------------------------------------- */

void control_record_event(struct control *ctl, enum acl_dir dir, bool allow, int rule,
                          const uint8_t *frame, uint32_t len, uint64_t ts) {
  if (ctl == NULL)
    return;
  struct acl_l3l4 t;
  bool ip = acl_classify(frame, len, &t);
  pthread_mutex_lock(&ctl->ring_mtx);
  struct ctl_event *e = &ctl->ring[ctl->seq % CTL_RING_CAP];
  e->seq = ctl->seq;
  e->ts = ts;
  e->dir = (uint8_t)dir;
  e->allow = allow ? 1 : 0;
  e->rule = rule;
  e->len = len;
  if (ip) {
    e->family = t.family;
    e->proto = t.proto;
    e->sport = t.sport;
    e->dport = t.dport;
    memcpy(e->src, t.src, 16);
    memcpy(e->dst, t.dst, 16);
  } else {
    e->family = 0;
    e->proto = -1;
    e->sport = e->dport = -1;
    memset(e->src, 0, 16);
    memset(e->dst, 0, 16);
  }
  ctl->seq++;
  pthread_mutex_unlock(&ctl->ring_mtx);
}

/* ----- request handlers ------------------------------------------------- */

static void emit_dir_stats(struct sb *s, const struct acl_stats *st, int d) {
  sb_puts(s, "{\"allow\":");
  sb_u64(s, st->allow[d]);
  sb_puts(s, ",\"deny\":");
  sb_u64(s, st->deny[d]);
  sb_puts(s, ",\"bytes_allow\":");
  sb_u64(s, st->bytes_allow[d]);
  sb_puts(s, ",\"bytes_deny\":");
  sb_u64(s, st->bytes_deny[d]);
  sb_puts(s, ",\"nonip\":");
  sb_u64(s, st->nonip[d]);
  sb_put(s, "}", 1);
}

static void handle_get_stats(struct control *ctl, struct sb *s) {
  struct state *st = ctl->state;
  struct acl_stats as;
  struct conntrack_stats cs;
  uint64_t now = (uint64_t)time(NULL);
  dispatch_semaphore_wait(st->sem, DISPATCH_TIME_FOREVER);
  acl_get_stats(st->acl, &as);
  size_t nrules = acl_rule_count(st->acl);
  /* snapshot per-rule hits while holding the lock */
  uint64_t *hits = nrules ? calloc(nrules, sizeof(uint64_t)) : NULL;
  for (size_t i = 0; i < nrules && hits != NULL; i++)
    hits[i] = acl_rule_hits(st->acl, i);
  conntrack_get_stats(st->ct, now, &cs);
  dispatch_semaphore_signal(st->sem);

  sb_puts(s, "{\"ok\":true,\"acl\":{\"egress\":");
  emit_dir_stats(s, &as, ACL_EGRESS);
  sb_puts(s, ",\"ingress\":");
  emit_dir_stats(s, &as, ACL_INGRESS);
  sb_puts(s, "},\"rules\":[");
  for (size_t i = 0; i < nrules; i++) {
    if (i)
      sb_put(s, ",", 1);
    sb_puts(s, "{\"index\":");
    sb_u64(s, i);
    sb_puts(s, ",\"hits\":");
    sb_u64(s, hits ? hits[i] : 0);
    sb_put(s, "}", 1);
  }
  free(hits);
  sb_puts(s, "],\"conntrack\":{\"capacity\":");
  sb_u64(s, cs.capacity);
  sb_puts(s, ",\"live\":");
  sb_u64(s, cs.live);
  sb_puts(s, ",\"lookups\":");
  sb_u64(s, cs.lookups);
  sb_puts(s, ",\"hits\":");
  sb_u64(s, cs.hits);
  sb_puts(s, ",\"inserts\":");
  sb_u64(s, cs.inserts);
  sb_puts(s, "}}");
}

static void handle_get_events(struct control *ctl, const jnode *req, struct sb *s) {
  const jnode *since = jget(req, "since");
  uint64_t from =
      (since != NULL && since->type == J_NUM && since->num > 0) ? (uint64_t)since->num : 0;
  pthread_mutex_lock(&ctl->ring_mtx);
  uint64_t next = ctl->seq;
  uint64_t lo = (next > CTL_RING_CAP) ? next - CTL_RING_CAP : 0;
  if (from < lo)
    from = lo;
  sb_puts(s, "{\"ok\":true,\"next\":");
  sb_u64(s, next);
  sb_puts(s, ",\"events\":[");
  bool first = true;
  for (uint64_t q = from; q < next; q++) {
    const struct ctl_event *e = &ctl->ring[q % CTL_RING_CAP];
    if (e->seq != q) /* overwritten since we computed lo */
      continue;
    if (!first)
      sb_put(s, ",", 1);
    first = false;
    sb_puts(s, "{\"seq\":");
    sb_u64(s, e->seq);
    sb_puts(s, ",\"ts\":");
    sb_u64(s, e->ts);
    sb_puts(s, ",\"dir\":");
    sb_jstr(s, e->dir == (uint8_t)ACL_EGRESS ? "egress" : "ingress");
    sb_puts(s, ",\"verdict\":");
    sb_jstr(s, e->allow ? "allow" : "deny");
    sb_puts(s, ",\"rule\":");
    sb_i64(s, e->rule);
    sb_puts(s, ",\"len\":");
    sb_u64(s, e->len);
    sb_puts(s, ",\"family\":");
    sb_i64(s, e->family);
    sb_puts(s, ",\"proto\":");
    sb_i64(s, e->proto);
    if (e->family != 0) {
      sb_puts(s, ",\"src\":");
      sb_ip(s, e->family, e->src);
      sb_puts(s, ",\"dst\":");
      sb_ip(s, e->family, e->dst);
    }
    if (e->sport >= 0) {
      sb_puts(s, ",\"sport\":");
      sb_i64(s, e->sport);
      sb_puts(s, ",\"dport\":");
      sb_i64(s, e->dport);
    }
    sb_put(s, "}", 1);
  }
  pthread_mutex_unlock(&ctl->ring_mtx);
  sb_puts(s, "]}");
}

static void handle_get_rules(struct control *ctl, struct sb *s) {
  struct state *st = ctl->state;
  dispatch_semaphore_wait(st->sem, DISPATCH_TIME_FOREVER);
  const char *path = st->cliopt ? st->cliopt->acl_path : NULL;
  bool hcl = path != NULL && strlen(path) >= 4 && strcmp(path + strlen(path) - 4, ".hcl") == 0;
  sb_puts(s, "{\"ok\":true,\"format\":");
  sb_jstr(s, hcl ? "hcl" : "json");
  sb_puts(s, ",\"source\":");
  if (st->acl_json != NULL)
    sb_jstr(s, st->acl_json);
  else
    sb_puts(s, "null");
  sb_put(s, "}", 1);
  dispatch_semaphore_signal(st->sem);
}

static void emit_err(struct sb *s, const char *msg) {
  sb_puts(s, "{\"ok\":false,\"error\":");
  sb_jstr(s, msg);
  sb_put(s, "}", 1);
}

char *control_handle(struct control *ctl, const char *req, size_t len) {
  struct sb s = {0};
  jnode *root = json_parse(req, len);
  if (root == NULL || root->type != J_OBJ) {
    emit_err(&s, "malformed request");
    jfree(root);
    return s.oom ? (free(s.p), NULL) : s.p;
  }
  const jnode *cmd = jget(root, "cmd");
  const char *c = (cmd != NULL && cmd->type == J_STR) ? cmd->str : "";

  if (strcmp(c, "get_stats") == 0) {
    handle_get_stats(ctl, &s);
  } else if (strcmp(c, "get_events") == 0) {
    handle_get_events(ctl, root, &s);
  } else if (strcmp(c, "get_rules") == 0) {
    handle_get_rules(ctl, &s);
  } else if (strcmp(c, "set_acl") == 0) {
    const jnode *j = jget(root, "json");
    if (j == NULL || j->type != J_STR) {
      emit_err(&s, "set_acl requires a \"json\" string");
    } else if (!control_set_acl_json(ctl->state, j->str, strlen(j->str))) {
      emit_err(&s, "set_acl: ruleset failed to compile");
    } else {
      sb_puts(&s, "{\"ok\":true,\"rules\":");
      sb_u64(&s, acl_rule_count(ctl->state->acl));
      sb_put(&s, "}", 1);
    }
  } else if (strcmp(c, "reload") == 0) {
    if (control_reload_acl(ctl->state))
      sb_puts(&s, "{\"ok\":true}");
    else
      emit_err(&s, "reload failed (no --acl path or parse error)");
  } else if (strcmp(c, "reset_stats") == 0) {
    control_reset_stats(ctl->state);
    sb_puts(&s, "{\"ok\":true}");
  } else {
    emit_err(&s, "unknown command");
  }
  jfree(root);
  if (s.oom) {
    free(s.p);
    return NULL;
  }
  return s.p != NULL ? s.p : strdup("{\"ok\":false,\"error\":\"empty\"}");
}

/* ----- socket server ---------------------------------------------------- */

static bool write_all(int fd, const char *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, buf + off, n - off);
    if (w <= 0) {
      if (w < 0 && errno == EINTR)
        continue;
      return false;
    }
    off += (size_t)w;
  }
  return true;
}

static void handle_client(struct control *ctl, int fd) {
  char *buf = malloc(CTL_MAX_LINE);
  if (buf == NULL)
    return;
  size_t used = 0;
  for (;;) {
    ssize_t r = read(fd, buf + used, CTL_MAX_LINE - used);
    if (r <= 0)
      break;
    used += (size_t)r;
    size_t start = 0;
    for (size_t i = 0; i < used; i++) {
      if (buf[i] != '\n')
        continue;
      char *resp = control_handle(ctl, buf + start, i - start);
      if (resp != NULL) {
        bool ok = write_all(fd, resp, strlen(resp)) && write_all(fd, "\n", 1);
        free(resp);
        if (!ok) {
          free(buf);
          return;
        }
      }
      start = i + 1;
    }
    if (start > 0) {
      memmove(buf, buf + start, used - start);
      used -= start;
    }
    if (used == CTL_MAX_LINE) /* oversized line with no newline: drop it */
      used = 0;
  }
  free(buf);
}

static void *accept_loop(void *arg) {
  struct control *ctl = arg;
  while (ctl->running) {
    int fd = accept(ctl->listen_fd, NULL, NULL);
    if (fd < 0) {
      if (!ctl->running)
        break;
      continue;
    }
    handle_client(ctl, fd);
    close(fd);
  }
  return NULL;
}

struct control *control_start(struct state *state, const char *path) {
  struct sockaddr_un addr;
  if (strlen(path) >= sizeof(addr.sun_path)) {
    ERROR("control: socket path too long");
    return NULL;
  }
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    ERRORN("control: socket");
    return NULL;
  }
  memset(&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path);
  unlink(path);
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
    ERRORN("control: bind");
    close(fd);
    return NULL;
  }
  chmod(path, 0660);
  if (listen(fd, 4) != 0) {
    ERRORN("control: listen");
    close(fd);
    unlink(path);
    return NULL;
  }
  struct control *ctl = calloc(1, sizeof *ctl);
  if (ctl == NULL)
    goto fail;
  ctl->ring = calloc(CTL_RING_CAP, sizeof(*ctl->ring));
  if (ctl->ring == NULL)
    goto fail;
  pthread_mutex_init(&ctl->ring_mtx, NULL);
  ctl->state = state;
  ctl->listen_fd = fd;
  ctl->path = strdup(path);
  ctl->running = true;
  if (pthread_create(&ctl->thread, NULL, accept_loop, ctl) != 0) {
    ERRORN("control: pthread_create");
    pthread_mutex_destroy(&ctl->ring_mtx);
    goto fail;
  }
  INFOF("control: listening on %s", path);
  return ctl;
fail:
  close(fd);
  unlink(path);
  if (ctl != NULL) {
    free(ctl->ring);
    free(ctl->path);
    free(ctl);
  }
  return NULL;
}

void control_stop(struct control *ctl) {
  if (ctl == NULL)
    return;
  ctl->running = false;
  shutdown(ctl->listen_fd, SHUT_RDWR);
  close(ctl->listen_fd);
  pthread_join(ctl->thread, NULL);
  unlink(ctl->path);
  pthread_mutex_destroy(&ctl->ring_mtx);
  free(ctl->ring);
  free(ctl->path);
  free(ctl);
}
