/*
 * ipv4_extract.c
 *
 * Reads a line of input and finds a valid IPv4 address embedded in it,
 * optionally followed by a port number (address:port). Exactly one
 * valid address is assumed to appear in the input line.
 *
 * Scanning rules:
 *   - Every character that is NOT a digit, '.', or ':' is treated as a
 *     separator and is otherwise ignored.
 *   - Consecutive digit/'.'/':' characters form one "candidate token".
 *   - A candidate token is checked as a WHOLE: if any part of it is
 *     invalid, the entire token is rejected (no partial matches are
 *     pulled out of a longer, invalid sequence). This naturally
 *     rejects: wrong octet counts, empty octets (e.g. "1..2.3.4" or
 *     ".1.2.3.4"), extra periods/colons, out-of-range values, leading
 *     zeros, and punctuation glued onto an otherwise-valid address
 *     (the punctuation simply isn't a token character, so if it sits
 *     where a digit/'.'/':' is required, the token shape breaks).
 *
 * Validation rules:
 *   IPv4 address: exactly four octets separated by '.'
 *     - each octet is 1-3 digits
 *     - each octet's numeric value is between 0 and 225 (inclusive)
 *     - no leading zero unless the octet is exactly "0"
 *   Optional port (after a single ':'):
 *     - 1-5 digits
 *     - numeric value between 0 and 65535 (inclusive)
 *     - no leading zero unless the port is exactly "0"
 *     - if a ':' is present but the port is invalid (or missing, or
 *       there is more than one ':'), the WHOLE token is invalid.
 *
 * Constraints honored:
 *   - No string-to-integer library calls (no atoi/strtol/strtoul/
 *     sscanf-as-int/stoi/etc.) - digit strings are converted to
 *     numeric values by hand in digits_to_value(), one digit at a
 *     time using only subtraction/multiplication/addition.
 *   - No networking/address-parsing functions (no inet_aton,
 *     inet_pton, inet_addr, etc.).
 *   - No regular-expression library.
 *   - isdigit() (a plain character-class check, not a conversion or
 *     parsing function) is used, which is explicitly allowed.
 *
 * Output:
 *   Extracted IPv4 address: A.B.C.D (decimal value: N, port: P)
 *   where N is the 32-bit unsigned decimal representation of the
 *   address (A*256^3 + B*256^2 + C*256 + D) and P is the port number,
 *   or the word "none" if no port was present.
 *
 * Build:  gcc -Wall -Wextra -o ipv4_extract ipv4_extract.c
 * Run:    ./ipv4_extract
 *         (then type a line of text and press Enter)
 */

#define _POSIX_C_SOURCE 200809L /* for getline() / ssize_t */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_FIELDS 8   /* generous upper bound; a valid IP only needs 4 */

/* Is this character one we keep as part of a candidate token? */
static int is_token_char(int c) {
    return isdigit(c) || c == '.' || c == ':';
}

/*
 * Split 's' in place on 'delim', turning each delimiter into '\0'.
 * Stores pointers to each resulting field (which may be empty strings)
 * in out[]. Returns the number of fields, or -1 if there would be more
 * than max_fields (clearly not a valid IPv4 shape).
 */
static int split_fields(char *s, char delim, char *out[], int max_fields) {
    int count = 0;
    char *start = s;
    char *p = s;

    for (;;) {
        if (*p == delim || *p == '\0') {
            if (count >= max_fields) return -1;
            out[count++] = start;
            int at_end = (*p == '\0');
            *p = '\0';
            start = p + 1;
            if (at_end) break;
        }
        p++;
    }
    return count;
}

/*
 * Manually convert a string of 'len' decimal digits into an unsigned
 * numeric value, without calling any string-to-integer library
 * function. Each character's numeric value is its distance from '0'.
 * Returns 1 on success (value written to *out), 0 if any character
 * is not a digit or the string is empty.
 */
static int digits_to_value(const char *s, size_t len, unsigned long *out) {
    if (len == 0) return 0;
    unsigned long val = 0;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)s[i])) return 0;
        unsigned int digit = (unsigned int)(s[i] - '0'); /* char-class arithmetic, not a conversion call */
        val = val * 10u + digit;
    }
    *out = val;
    return 1;
}

/* Validate one octet: 1-3 digits, value 0-225, no leading zero unless "0".
 * On success, writes the numeric value to *value. */
static int valid_octet(const char *s, unsigned long *value) {
    size_t len = strlen(s);
    if (len < 1 || len > 3) return 0;
    if (len > 1 && s[0] == '0') return 0;   /* leading zero, e.g. "01" */

    unsigned long val;
    if (!digits_to_value(s, len, &val)) return 0;
    if (val > 225) return 0;
    *value = val;
    return 1;
}

/* Validate a port: 1-5 digits, value 0-65535, no leading zero unless "0".
 * On success, writes the numeric value to *value. */
static int valid_port(const char *s, unsigned long *value) {
    size_t len = strlen(s);
    if (len < 1 || len > 5) return 0;
    if (len > 1 && s[0] == '0') return 0;

    unsigned long val;
    if (!digits_to_value(s, len, &val)) return 0;
    if (val > 65535) return 0;
    *value = val;
    return 1;
}

/* Validate the IP portion: must split into exactly 4 dotted fields,
 * each a valid octet. On success, fills octets[0..3]. */
static int valid_ip(char *ip_part, unsigned long octets[4]) {
    char *fields[MAX_FIELDS];
    int n = split_fields(ip_part, '.', fields, MAX_FIELDS);
    if (n != 4) return 0;

    for (int i = 0; i < 4; i++) {
        if (!valid_octet(fields[i], &octets[i])) return 0;
    }
    return 1;
}

/*
 * Validate a whole candidate token (already isolated - only digits,
 * '.', ':' characters). Token is modified in place (colons/dots get
 * replaced with '\0' during splitting), which is fine since the
 * caller keeps its own untouched copy for printing.
 *
 * On success: fills octets[0..3] and *port (0 if no port was
 * present) and sets *has_port accordingly.
 */
static int valid_address_token(char *token, unsigned long octets[4],
                                unsigned long *port, int *has_port) {
    char *colon_fields[MAX_FIELDS];
    int n = split_fields(token, ':', colon_fields, MAX_FIELDS);

    if (n == 1) {
        /* No colon at all: just an IP address. */
        *has_port = 0;
        *port = 0;
        return valid_ip(colon_fields[0], octets);
    }
    if (n == 2) {
        /* Exactly one colon: address ':' port */
        if (!valid_ip(colon_fields[0], octets)) return 0;
        if (!valid_port(colon_fields[1], port)) return 0;
        *has_port = 1;
        return 1;
    }
    /* More than one colon (n > 2) is never valid. */
    return 0;
}

/*
 * Scan one already-trimmed line for a single valid IPv4 address
 * (optionally with a port) and print the result. Prints the
 * "Extracted..." message and returns 1 if one was found, otherwise
 * prints "Invalid input: no valid IPv4 address found" and returns 0.
 */
static int process_line(char *line, size_t len) {
    int found = 0;
    size_t i = 0;

    while (i < (size_t)len && !found) {
        if (is_token_char((unsigned char)line[i])) {
            size_t start = i;
            while (i < (size_t)len && is_token_char((unsigned char)line[i])) {
                i++;
            }
            size_t tok_len = i - start;

            /* Keep an untouched copy for printing (validation mutates
             * its working copy while splitting on '.'/':' ). */
            char *original = malloc(tok_len + 1);
            char *working = malloc(tok_len + 1);
            if (!original || !working) {
                fprintf(stderr, "Out of memory.\n");
                free(original);
                free(working);
                return -1; /* signal fatal error to caller */
            }
            memcpy(original, line + start, tok_len);
            original[tok_len] = '\0';
            memcpy(working, line + start, tok_len);
            working[tok_len] = '\0';

            unsigned long octets[4];
            unsigned long port = 0;
            int has_port = 0;

            if (valid_address_token(working, octets, &port, &has_port)) {
                /* 32-bit decimal representation, built by hand with
                 * plain arithmetic (no library conversion helpers). */
                unsigned long decimal_value =
                    octets[0] * 16777216u /* 256^3 */
                  + octets[1] * 65536u    /* 256^2 */
                  + octets[2] * 256u      /* 256^1 */
                  + octets[3];            /* 256^0 */

                printf("Extracted IPv4 address: %lu.%lu.%lu.%lu "
                       "(decimal value: %lu, port: ",
                       octets[0], octets[1], octets[2], octets[3],
                       decimal_value);
                if (has_port) {
                    printf("%lu)\n", port);
                } else {
                    printf("none)\n");
                }
                found = 1;
            }

            free(original);
            free(working);
        } else {
            i++;
        }
    }

    if (!found) {
        printf("Invalid input: no valid IPv4 address found\n");
    }

    return found;
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;

    for (;;) {
        printf("Enter a string (or 'END' to quit): ");
        fflush(stdout);

        ssize_t len = getline(&line, &cap, stdin);
        if (len < 0) {
            /* EOF (e.g. input piped in, or Ctrl-D) */
            printf("\nProgram terminated.\n");
            break;
        }

        /* Strip trailing newline, if present. */
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (strcmp(line, "END") == 0) {
            printf("Program terminated.\n");
            break;
        }

        if (process_line(line, (size_t)len) < 0) {
            /* Fatal (out-of-memory) error inside process_line(). */
            break;
        }
    }

    free(line);
    return 0;
}
