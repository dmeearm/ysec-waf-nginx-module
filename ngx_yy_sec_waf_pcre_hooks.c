/*
** @file: ngx_yy_sec_waf_pcre_hooks.c
** @description: This is the pcre_malloc/pcre_free hooks for yy sec waf.
** - According to nginx regex subsystem, we must init a memory pool to use PCRE functions.
** - As PCRE still has memory-leaking problems,
** - and nginx overwrote pcre_malloc/pcre_free hooks with its own static functions,
** - so nobody else can reuse nginx regex subsystem.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.24
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

#if (NGX_PCRE)

static ngx_pool_t *ngx_http_yy_sec_waf_pcre_pool = NULL;

static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);

/*
** @description: This function is called to malloc memory from pool for pcre.
** @para: size_t size
** @return: static void *.
*/

static void *
ngx_http_yy_sec_waf_pcre_malloc(size_t size)
{
    if (ngx_http_yy_sec_waf_pcre_pool) {
        return ngx_palloc(ngx_http_yy_sec_waf_pcre_pool, size);
    }

    fprintf(stderr, "error: yy sec waf pcre malloc failed due to empty pcre pool");

    return NULL;
}

/*
** @description: This function is called to free memory from pool for pcre.
** @para: void *ptr
** @return: static void *.
*/

static void
ngx_http_yy_sec_waf_pcre_free(void *ptr)
{
    if (ngx_http_yy_sec_waf_pcre_pool) {
        ngx_pfree(ngx_http_yy_sec_waf_pcre_pool, ptr);
        return;
    }
}


/*
** @description: This function is called to init memory pool for pcre.
** @para: void *ptr
** @return: static void *.
*/

ngx_pool_t *
ngx_http_yy_sec_waf_pcre_malloc_init(ngx_pool_t *pool)
{
    ngx_pool_t          *old_pool;

    if (pcre_malloc != ngx_http_yy_sec_waf_pcre_malloc) {

        ngx_http_yy_sec_waf_pcre_pool = pool;

        old_pcre_malloc = pcre_malloc;
        old_pcre_free = pcre_free;

        pcre_malloc = ngx_http_yy_sec_waf_pcre_malloc;
        pcre_free = ngx_http_yy_sec_waf_pcre_free;

        return NULL;
    }

    old_pool = ngx_http_yy_sec_waf_pcre_pool;
    ngx_http_yy_sec_waf_pcre_pool = pool;

    return old_pool;
}


/*
** @description: This function is called to free memory pool for pcre.
** @para: ngx_pool_t *old_pool
** @return: void.
*/

void
ngx_http_yy_sec_waf_pcre_malloc_done(ngx_pool_t *old_pool)
{
    ngx_http_yy_sec_waf_pcre_pool = old_pool;

    if (old_pool == NULL) {
        pcre_malloc = old_pcre_malloc;
        pcre_free = old_pcre_free;
    }
}

#endif /* NGX_PCRE */

