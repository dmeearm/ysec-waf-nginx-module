/*
** @file: ngx_yy_sec_waf_re_tfn.c
** @description: This is the rule engine's tfns for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.26
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf_re.h"

/*
** @description: This function is called to excute urldecode tfs.
** @para: ngx_http_variable_value_t *v
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

static ngx_int_t
yy_sec_waf_re_tfns_urldecode(ngx_http_variable_value_t *v)
{
    if (v == NULL) {
        return NGX_ERROR;
    }

    ngx_str_t str;
    str.data = v->data;
    str.len = v->len;

    ngx_yy_sec_waf_unescape(&str);

    return NGX_OK;
}

static re_tfns_metadata tfns_metadata[] = {
    { ngx_string("urldecode"), yy_sec_waf_re_tfns_urldecode },
    { ngx_null_string, NULL }
};

/*
** @description: This function is called to init tfns.
** @para: ngx_conf_t *cf
** @para: ngx_hash_t *actions_in_hash
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_init_tfns_in_hash(ngx_conf_t *cf,
    ngx_hash_t *tfns_in_hash)
{
    ngx_array_t         tfns;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    re_tfns_metadata     *metadata;

    if (ngx_array_init(&tfns, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (metadata = tfns_metadata; metadata->name.len; metadata++) {
        hk = ngx_array_push(&tfns);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = metadata->name;
        hk->key_hash = ngx_hash_key_lc(metadata->name.data, metadata->name.len);
        hk->value = metadata;
    }

    hash.hash = tfns_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "tfns_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, tfns.elts, tfns.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
 
