/* lua_shared_dict backend (ngx.shared.DICT:set/add/replace/safe_set/get/incr/...) over a fresh slab zone per input. */
#include "fuzz_common.h"
#include "ngx_stream_lua_shdict.h"

#include <stdio.h>

#define ZONE_SIZE   (1024 * 1024)

#define OP_ADD      0x01
#define OP_REPLACE  0x02
#define OP_SAFE     0x04

#define T_NIL       0
#define T_BOOLEAN   1
#define T_NUMBER    3
#define T_STRING    4

extern ngx_int_t ngx_stream_lua_shdict_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
extern int ngx_stream_lua_ffi_shdict_store(ngx_shm_zone_t *zone, int op,
    u_char *key, size_t key_len, int value_type, u_char *str_value_buf,
    size_t str_value_len, double num_value, long exptime, int user_flags,
    char **errmsg, int *forcible);
extern int ngx_stream_lua_ffi_shdict_get(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, int *value_type, u_char **str_value_buf,
    size_t *str_value_len, double *num_value, int *user_flags,
    int get_stale, int *is_stale, char **err);
extern int ngx_stream_lua_ffi_shdict_incr(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, double *value, char **err, int has_init, double init,
    long init_ttl, int *forcible);
extern int ngx_stream_lua_ffi_shdict_flush_all(ngx_shm_zone_t *zone);
extern long ngx_stream_lua_ffi_shdict_get_ttl(ngx_shm_zone_t *zone,
    u_char *key, size_t key_len);
extern int ngx_stream_lua_ffi_shdict_set_expire(ngx_shm_zone_t *zone,
    u_char *key, size_t key_len, long exptime);
extern int ngx_stream_lua_ffi_shdict_compare_expire(ngx_shm_zone_t *zone,
    const u_char *key, size_t key_len, const u_char *value, size_t value_len,
    long exptime);
extern size_t ngx_stream_lua_ffi_shdict_free_space(ngx_shm_zone_t *zone);

/* A key of up to 65657 bytes crosses the 65535-byte limit of the u_short key_len in the node. */
static size_t
key_length(unsigned code)
{
    return code < 128 ? code : 65530 + (code - 128);
}

/* After a successful store, the same key must read back the same value. */
static void
check_roundtrip(ngx_shm_zone_t *zone, u_char *key, size_t klen, int type,
    const u_char *val, size_t vlen, double num)
{
    int      vt = -1, flags, stale;
    char    *err;
    u_char  *buf, *orig;
    size_t   blen = 64;
    double   got = 0;

    orig = buf = malloc(blen);
    if (ngx_stream_lua_ffi_shdict_get(zone, key, klen, &vt, &buf, &blen, &got,
                                      &flags, 0, &stale, &err) != NGX_OK
        || vt != type)
    {
        abort();
    }

    if (type == T_STRING && (blen != vlen || (vlen && memcmp(buf, val, vlen))))
    {
        abort();
    }

    if (type == T_NUMBER && memcmp(&got, &num, sizeof(double)) != 0) {
        abort();
    }

    if (type == T_BOOLEAN && (buf[0] != 0) != (num != 0)) {
        abort();
    }

    if (buf != orig) {
        free(buf);
    }

    free(orig);
}

/* [cmd][klen][kfill][arg][vlen][value...] records */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int                           op, type, rc, forcible, flags, stale, vt, n;
    long                          exptime;
    char                         *err;
    size_t                        klen, vlen, blen, i;
    double                        num;
    u_char                       *key, *buf, *region;
    const u_char                 *val;
    ngx_shm_zone_t                zone;
    ngx_slab_pool_t              *sp;
    ngx_stream_lua_shdict_ctx_t   ctx;

    slnm_init();

    if (size < 5) {
        return -1;
    }

    region = aligned_alloc(4096, ZONE_SIZE);
    memset(region, 0, sizeof(ngx_slab_pool_t));

    ngx_pid = getpid();
    memset(&zone, 0, sizeof(zone));
    memset(&ctx, 0, sizeof(ctx));
    zone.shm.addr = region;
    zone.shm.size = ZONE_SIZE;
    zone.shm.name.data = (u_char *) "fuzz";
    zone.shm.name.len = 4;
    zone.data = &ctx;
    ctx.name = zone.shm.name;
    ctx.log = &slnm_log;

    sp = (ngx_slab_pool_t *) region;
    sp->end = region + ZONE_SIZE;
    sp->min_shift = 3;
    sp->addr = region;
    if (ngx_shmtx_create(&sp->mutex, &sp->lock, NULL) != NGX_OK) {
        abort();
    }

    ngx_slab_init(sp);

    if (ngx_stream_lua_shdict_init_zone(&zone, NULL) != NGX_OK) {
        abort();
    }

    for (n = 0; n < 32 && size >= 5; n++) {
        int       cmd = data[0] % 8, arg = data[3];
        unsigned  kcode = data[1];
        u_char    kfill = data[2];

        vlen = data[4];
        data += 5;
        size -= 5;
        if (vlen > size) {
            vlen = size;
        }

        val = data;
        data += vlen;
        size -= vlen;

        klen = key_length(kcode);
        key = malloc(klen ? klen : 1);
        memset(key, kfill, klen);
        if (klen) {
            key[klen - 1] = kfill + (arg >> 5);
        }

        type = (arg & 3) == 0 ? T_NUMBER : (arg & 3) == 1 ? T_BOOLEAN
                                                          : T_STRING;
        exptime = (arg & 4) ? 3600000 : 0;
        num = 0;
        if (vlen >= sizeof(double)) {
            memcpy(&num, val, sizeof(double));

        } else {
            num = (double) vlen;
        }

        switch (cmd) {

        case 0:
        case 1:
        case 2:
        case 3:
            op = cmd == 1 ? OP_ADD : cmd == 2 ? OP_REPLACE
                                    : cmd == 3 ? OP_SAFE : 0;
            err = NULL;
            forcible = 0;
            rc = ngx_stream_lua_ffi_shdict_store(&zone, op, key, klen, type,
                                                 val, vlen, num, exptime,
                                                 arg >> 3, &err, &forcible);
            if (rc == NGX_OK && exptime == 0) {
                check_roundtrip(&zone, key, klen, type, val, vlen, num);
            }

            break;

        case 4:
            blen = 64;
            buf = malloc(blen);
            vt = -1;
            ngx_stream_lua_ffi_shdict_get(&zone, key, klen, &vt, &buf, &blen,
                                          &num, &flags, arg & 1, &stale,
                                          &err);
            if (vt == T_STRING && blen > 64) {
                /* the module allocated a bigger buffer for us */
                for (i = 0; i < blen; i++) {
                    (void) buf[i];
                }
            }

            free(buf);
            break;

        case 5:
            num = (double) (int) (arg - 128);
            forcible = 0;
            err = NULL;
            rc = ngx_stream_lua_ffi_shdict_incr(&zone, key, klen, &num, &err,
                                                arg & 1, (double) vlen,
                                                (arg & 2) ? 3600 : 0,
                                                &forcible);
            (void) rc;
            break;

        case 6:
            err = NULL;
            forcible = 0;
            ngx_stream_lua_ffi_shdict_store(&zone, 0, key, klen, T_NIL, NULL,
                                            0, 0, 0, 0, &err, &forcible);
            break;

        case 7:
            switch (arg & 3) {
            case 0:
                ngx_stream_lua_ffi_shdict_flush_all(&zone);
                break;
            case 1:
                ngx_stream_lua_ffi_shdict_get_ttl(&zone, key, klen);
                break;
            case 2:
                ngx_stream_lua_ffi_shdict_set_expire(&zone, key, klen,
                                                     exptime);
                break;
            default:
                ngx_stream_lua_ffi_shdict_compare_expire(&zone, key, klen,
                                                         val, vlen, exptime);
                break;
            }

            ngx_stream_lua_ffi_shdict_free_space(&zone);
            break;
        }

        free(key);
    }

    ngx_shmtx_destroy(&sp->mutex);
    free(region);
    return 0;
}
