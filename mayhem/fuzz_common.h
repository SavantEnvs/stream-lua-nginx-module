/* Shared setup for the in-process harnesses: just enough of an nginx cycle for the module's FFI helpers. */
#ifndef SLNM_FUZZ_COMMON_H
#define SLNM_FUZZ_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_stream_lua_common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern ngx_uint_t ngx_max_module;

static ngx_log_t           slnm_log;
static ngx_cycle_t         slnm_cycle;
static ngx_stream_conf_ctx_t slnm_stream_ctx;

/* Copy into an exact-size, NUL-terminated heap block (Lua strings are NUL-terminated). */
static u_char *
slnm_dup(const uint8_t *p, size_t n)
{
    u_char *d = malloc(n + 1);

    if (n) {
        memcpy(d, p, n);
    }

    d[n] = '\0';
    return d;
}

static void
slnm_init(void)
{
    static int                 done;
    ngx_stream_lua_main_conf_t  *lmcf;

    if (done) {
        return;
    }

    done = 1;

    slnm_log.log_level = 0;
    /* ngx_os_init() also rewires argv/environ for setproctitle, which trips UBSan and is irrelevant here */
    ngx_pagesize = getpagesize();
    for (ngx_pagesize_shift = 0; (1U << ngx_pagesize_shift) < ngx_pagesize;
         ngx_pagesize_shift++) { /* void */ }
    ngx_cacheline_size = 64;
    ngx_ncpu = 1;
    ngx_time_init();
    ngx_time_update();

    ngx_cycle = &slnm_cycle;
    slnm_cycle.log = &slnm_log;
    slnm_cycle.new_log = slnm_log;

    ngx_preinit_modules();

    slnm_cycle.conf_ctx = calloc(ngx_max_module + 1, sizeof(void *));
    slnm_stream_ctx.main_conf = calloc(64, sizeof(void *));
    slnm_stream_ctx.srv_conf = calloc(64, sizeof(void *));

    lmcf = calloc(1, sizeof(ngx_stream_lua_main_conf_t));
    lmcf->regex_match_limit = 5000;
    lmcf->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &slnm_log);

    ngx_stream_lua_module.ctx_index = 0;
    slnm_stream_ctx.main_conf[0] = lmcf;
    slnm_cycle.conf_ctx[ngx_stream_module.index] = (void ***) &slnm_stream_ctx;
}

#endif
