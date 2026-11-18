/* ngx.encode/decode_base64, ngx.escape/unescape_uri, ngx.md5/sha1_bin/crc32 backends. */
#include "fuzz_common.h"

extern size_t ngx_stream_lua_ffi_encode_base64(const u_char *src, size_t slen,
    u_char *dst, int no_padding);
extern int ngx_stream_lua_ffi_decode_base64(const u_char *src, size_t slen,
    u_char *dst, size_t *dlen);
extern size_t ngx_stream_lua_ffi_unescape_uri(const u_char *src, size_t len,
    u_char *dst);
extern size_t ngx_stream_lua_ffi_uri_escaped_length(const u_char *src,
    size_t len, int type);
extern void ngx_stream_lua_ffi_escape_uri(const u_char *src, size_t len,
    u_char *dst, int type);
extern void ngx_stream_lua_ffi_md5(const u_char *src, size_t len, u_char *dst);
extern void ngx_stream_lua_ffi_md5_bin(const u_char *src, size_t len,
    u_char *dst);
extern int ngx_stream_lua_ffi_sha1_bin(const u_char *src, size_t len,
    u_char *dst);
extern unsigned int ngx_stream_lua_ffi_crc32_short(const u_char *src,
    size_t len);
extern unsigned int ngx_stream_lua_ffi_crc32_long(const u_char *src,
    size_t len);

/* [op][arg][payload...]; buffer sizes follow resty.core's own computations. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int      op, arg;
    size_t   n, dlen, r, i;
    u_char  *src, *dst;

    slnm_init();

    if (size < 2) {
        return -1;
    }

    op = data[0] % 5;
    arg = data[1];
    n = size - 2;
    src = slnm_dup(data + 2, n);

    switch (op) {

    case 0:
        dlen = (arg & 1) ? (n * 8 + 5) / 6 : (n + 2) / 3 * 4;
        dst = malloc(dlen + 1);
        r = ngx_stream_lua_ffi_encode_base64(src, n, dst, arg & 1);
        if (r > dlen) {
            abort();
        }

        if (!(arg & 1)) {
            u_char *back = malloc((r + 3) / 4 * 3 + 1);
            size_t  blen;

            if (!ngx_stream_lua_ffi_decode_base64(dst, r, back, &blen)
                || blen != n || (n && memcmp(back, src, n) != 0))
            {
                abort();
            }

            free(back);
        }

        free(dst);
        break;

    case 1:
        dlen = (n + 3) / 4 * 3;
        dst = malloc(dlen + 1);
        ngx_stream_lua_ffi_decode_base64(src, n, dst, &r);
        free(dst);
        break;

    case 2:
        dst = malloc(n + 1);
        ngx_stream_lua_ffi_unescape_uri(src, n, dst);
        free(dst);
        break;

    case 3:
        arg %= 7;
        dlen = ngx_stream_lua_ffi_uri_escaped_length(src, n, arg);
        dst = malloc(dlen + 1);
        ngx_stream_lua_ffi_escape_uri(src, n, dst, arg);
        free(dst);
        break;

    case 4:
        dst = malloc(33);
        ngx_stream_lua_ffi_md5(src, n, dst);
        for (i = 0; i < 32; i++) {
            if (!((dst[i] >= '0' && dst[i] <= '9')
                  || (dst[i] >= 'a' && dst[i] <= 'f')))
            {
                abort();
            }
        }

        free(dst);
        dst = malloc(20);
        ngx_stream_lua_ffi_md5_bin(src, n, dst);
        ngx_stream_lua_ffi_sha1_bin(src, n, dst);
        free(dst);
        if (ngx_stream_lua_ffi_crc32_long(src, n)
            != ngx_stream_lua_ffi_crc32_long(src, n))
        {
            abort();
        }

        ngx_stream_lua_ffi_crc32_short(src, n);
        break;
    }

    free(src);
    return 0;
}
