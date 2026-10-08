/* level1_decoder.c
 * Same underlying overflow bug as level0_decoder.c, but with the controlled
 * variable change that mirrors the real-world story's hard part: PIE + ASLR
 * are ON, so win()'s address is unknown at compile time AND changes every
 * run. Canary stays OFF (unchanged from level 0) so PIE/ASLR is the ONLY
 * new variable — isolating the failure condition, same discipline as the
 * rest of mcp-rt's controlled-reproduction findings.
 *
 * A pure blind overflow can't work anymore (the target address is
 * unknown), so this program is INTERACTIVE — it reads one header line at a
 * time in a loop within the SAME process — mirroring a real long-running
 * service (or any program you can talk to more than once per connection).
 * That matters: it means an attacker can leak an address on request 1 and
 * use it on request 2, because the process (and its ASLR base) hasn't
 * changed between them. A one-shot re-exec-per-input CLI cannot support
 * this chain at all, since a new process gets a fresh random base every
 * time — this is a deliberate, realistic design choice, not an oversight.
 *
 * BUG 1 (leak primitive, format string): parse_header() passes
 * attacker-controlled input directly to printf() as the FORMAT STRING
 * instead of using "%s". "%p" specifiers walk the stack/register save
 * area and can leak a saved return address pointing back into this
 * binary's PIE mapping. From that leaked address, the runtime load base
 * is computable (leaked_addr - known_static_offset_of_that_call_site).
 *
 * BUG 2 (control-flow hijack): identical unbounded strcpy(buf, raw_header)
 * into a 64-byte stack buffer, same as level 0.
 *
 * Intended chain: send a short (<64 byte) leak-only line first -> compute
 * win()'s real address from the leak -> send a second line that overflows
 * buf with the computed address. Two requests, one process, one exploit.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FLAG_MARKER "FLAG{level1_pie_aslr_ok}"

void win(void) {
    printf("%s\n", FLAG_MARKER);
    fflush(stdout);
}

void parse_header(const char *raw_header) {
    char buf[64];
    /* BUG 1: raw_header used AS the format string. */
    printf(raw_header);
    printf("\n");
    fflush(stdout);

    /* BUG 2: identical unbounded strcpy to level 0. */
    strcpy(buf, raw_header);
    printf("Parsed header: %s\n", buf);
    fflush(stdout);
}

int main(void) {
    char line[4096];
    /* Interactive loop: same process, same ASLR base, across requests. */
    while (fgets(line, sizeof(line), stdin) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        parse_header(line);
    }
    return 0;
}
