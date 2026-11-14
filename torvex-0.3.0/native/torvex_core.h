/*
 * Torvex native core - stable C ABI.
 *
 * The Rust crate owns all policy (severity, MITRE mapping, remediation). This
 * library does the byte-level work that benefits from a tight loop:
 *
 *   - Aho-Corasick multi-pattern matching over a whole file in one pass
 *   - Shannon entropy (whole file, worst 4 KiB window, longest base64 run)
 *   - structural analysis of ELF and PE images (W^X, ASLR, NX, packers)
 *   - indicator extraction (URLs, IPv4 addresses, e-mail addresses)
 *
 * Every entry point below is `extern "C"`, never throws, and is safe to call
 * from any thread as long as a single matcher is not mutated while scanning.
 * Strings returned by tv_scan must be released with tv_free.
 */

#ifndef TORVEX_CORE_H
#define TORVEX_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque compiled Aho-Corasick matcher. */
typedef struct tv_matcher tv_matcher;

/* Creates an empty matcher, or NULL when allocation fails. */
tv_matcher *tv_matcher_create(void);

/* Adds a rule. `needles` are byte strings of the given lengths. When
 * `require_all` is non-zero the rule fires only after every needle matched
 * somewhere in the file. `nocase` is an optional array parallel to `needles`;
 * a non-zero entry selects the case-folded automaton. Pass NULL to treat every
 * needle as case-sensitive. Returns 0 on success, non-zero on invalid input. */
int tv_matcher_add_rule(tv_matcher *matcher,
                        const char *rule_id,
                        int require_all,
                        const char *const *needles,
                        const size_t *lengths,
                        const int *nocase,
                        size_t needle_count);

/* Compiles the automaton. Must be called once after adding rules. */
int tv_matcher_build(tv_matcher *matcher);

/* Number of rules currently registered (useful for diagnostics). */
size_t tv_matcher_rule_count(const tv_matcher *matcher);

/* Scans `len` bytes at `data` and returns a newly allocated UTF-8 JSON
 * document, or NULL on allocation failure. Release with tv_free. */
char *tv_scan(const tv_matcher *matcher, const uint8_t *data, size_t len);

/* Returns the native core version string, for `torvex info`. */
const char *tv_core_version(void);

/* Releases a string returned by tv_scan. NULL is accepted. */
void tv_free(char *value);

/* Releases a matcher returned by tv_matcher_create. NULL is accepted. */
void tv_matcher_destroy(tv_matcher *matcher);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TORVEX_CORE_H */
