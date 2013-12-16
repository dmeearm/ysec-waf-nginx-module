/*
** @file: ngx_yy_sec_waf_re_cache.c
** @description: This is the rule rule engine for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.12.12
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

typedef struct {
    ngx_str_node_t sn;
    ngx_array_t   *value;
} re_cache_node_t;

ngx_inline void
yy_sec_waf_re_cache_init_rbtree(ngx_rbtree_t *rbtree,
    ngx_rbtree_node_t *sentinel) 
{
    ngx_rbtree_init(rbtree, sentinel, ngx_str_rbtree_insert_value);
}

ngx_int_t
yy_sec_waf_re_cache_set_value(ngx_pool_t *pool,
    ngx_str_t *name, ngx_array_t *value, ngx_rbtree_t *rbtree)
{
    uint32_t         hash;
    ngx_str_t       *val;
    re_cache_node_t *cache_node;

    hash = ngx_crc32_long(name->data, name->len);

    cache_node = (re_cache_node_t *) ngx_str_rbtree_lookup(rbtree, name, hash);

    if (cache_node != NULL) {
        return NGX_OK;
    }

    cache_node = ngx_palloc(pool, sizeof(re_cache_node_t));

    if (cache_node == NULL) {
        return NGX_ERROR;
    }

    val = ngx_palloc(pool, sizeof(ngx_str_t));

    if (value == NULL) {
        return NGX_ERROR;
    }

    val->len = value->len;
    val->data = ngx_pstrdup(pool, value);
    if (val->data == NULL) {
        return NGX_ERROR;
    }

    cache_node->sn.node.key = hash;
    cache_node->sn.str.len = name->len;
    cache_node->sn.str.data = name->data;
    cache_node->value = value;

    ngx_rbtree_insert(rbtree, &cache_node->sn.node);

    return NGX_OK;
}

ngx_inline ngx_array_t *
yy_sec_waf_re_cache_get_value(ngx_rbtree_t *rbtree, ngx_str_t *name)
{
    uint32_t         hash;
    re_cache_node_t *cache_node;

    hash = ngx_crc32_long(name->data, name->len);

    cache_node = (re_cache_node_t *) ngx_str_rbtree_lookup(rbtree, name, hash);

    if (cache_node != NULL) {
        return cache_node->value;
    }

    return NULL;
}

