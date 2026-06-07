#ifndef SOCKET_VMNET_CONTROL_H
#define SOCKET_VMNET_CONTROL_H

/* A small stats + control plane for the firewall: a local UNIX-domain socket
 * speaking a line-delimited JSON request/response protocol, plus a ring buffer
 * of recent allow/deny events fed from the data path. Used by an out-of-process
 * web UI to observe counters/events in real time and to edit the ruleset live.
 *
 * Requests and responses are single '\n'-terminated JSON objects. Commands:
 *   {"cmd":"get_stats"}                  -> ACL aggregate + per-rule hits + conntrack
 *   {"cmd":"get_events","since":SEQ}     -> events with seq >= SEQ (+ "next")
 *   {"cmd":"get_rules"}                  -> current ruleset source text + format
 *   {"cmd":"set_acl","json":"..."}       -> compile + hot-swap the ACL (JSON)
 *   {"cmd":"reload"}                     -> re-read the --acl file and swap
 *   {"cmd":"reset_stats"}                -> zero the counters
 * Every response is an object with "ok":true|false (and "error" on failure). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "acl.h" /* enum acl_dir */

struct state;
struct control;

/* Create+bind+listen a UNIX socket at `path` and spawn the server thread.
 * `state` is borrowed (must outlive the control server). NULL on error. */
struct control *control_start(struct state *state, const char *path);

/* Stop the server, close+unlink the socket and free the control object. */
void control_stop(struct control *ctl);

/* ACL load/swap helpers (operate on struct state under state->sem). Shared by
 * the daemon's startup/SIGHUP path and the control protocol. */

/* Compile JSON and atomically swap it in (keeping the old ACL on a parse
 * error). Returns false on failure. */
bool control_set_acl_json(struct state *state, const char *json, size_t len);

/* Re-read the --acl file (cliopt->acl_path) and swap it in. False on error
 * (no path, or parse failure) — the previous ACL is kept. */
bool control_reload_acl(struct state *state);

/* Zero the ACL counters (under state->sem). */
void control_reset_stats(struct state *state);

/* Append an allow/deny decision to the event ring (thread-safe, lock-light).
 * `rule` is the matched rule index, or -1 for the default action / a
 * conntrack-established frame. No-op if ctl is NULL. */
void control_record_event(struct control *ctl, enum acl_dir dir, bool allow, int rule,
                          const uint8_t *frame, uint32_t len, uint64_t ts);

/* Handle one request line and return a newly-allocated, NUL-terminated JSON
 * response (no trailing newline). Never returns NULL on success of allocation;
 * returns NULL only on OOM. Exposed for unit testing without a socket. */
char *control_handle(struct control *ctl, const char *req, size_t len);

#endif /* SOCKET_VMNET_CONTROL_H */
