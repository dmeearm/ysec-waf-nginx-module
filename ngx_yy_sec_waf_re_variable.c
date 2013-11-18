/*
** @file: ngx_yy_sec_waf_re_variable.c
** @description: This is the rule engine's variables for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.08
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: This function is called to generate args.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
ngx_http_yy_sec_waf_generate_args(void *rule_p,
    void *ctx_p, ngx_array_t *var_array)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    ngx_str_t *var;

    if (rule == NULL || ctx == NULL || var_array == NULL) {
        return NGX_ERROR;
    }

    var = ngx_array_push(var_array);

    if (ctx->phase == REQUEST_HEADER_PHASE) {
        ngx_memcpy(var, ctx->args, sizeof(ngx_str_t));
    } else if (ctx->phase == REQUEST_BODY_PHASE) {
        ngx_memcpy(var, ctx->post_args, sizeof(ngx_str_t));
    }

    return NGX_OK;
}

/*
** @description: This function is called to generate process body error.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
ngx_http_yy_sec_waf_generate_process_body_error(void *rule_p,
    void *ctx_p, ngx_array_t *var_array)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    ngx_str_t *var;

    if (rule == NULL || ctx == NULL || var_array == NULL) {
        return NGX_ERROR;
    }

    var = ngx_array_push(var_array);

    if (ctx->process_body_error < 16 && ctx->process_body_error > 9) {
        ngx_str_set(var, "1");
    } else {
        ngx_str_set(var, "0");
    }

    return NGX_OK;
}

/*
** @description: This function is called to generate multipart name.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
ngx_http_yy_sec_waf_generate_multipart_name(void *rule_p,
    void *ctx_p, ngx_array_t *var_array)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || var_array == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(var_array, ctx->multipart_name, sizeof(ngx_array_t));

    return NGX_OK;
}

/*
** @description: This function is called to generate multipart filename.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
ngx_http_yy_sec_waf_generate_multipart_filename(void *rule_p,
    void *ctx_p, ngx_array_t *var_array)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || var_array == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(var_array, ctx->multipart_filename, sizeof(ngx_array_t));

    return NGX_OK;
}

/*
** @description: This function is called to generate inner variable.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
ngx_http_yy_sec_waf_generate_inner_var(void *rule_p,
    void *ctx_p, ngx_array_t *var_array)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    ngx_str_t *var;

    if (rule == NULL || ctx == NULL || var_array == NULL) {
        return NGX_ERROR;
    }

    ngx_http_variable_value_t *vv;
    
    if (rule->var_index != NGX_CONF_UNSET) {
        vv = ngx_http_get_indexed_variable(ctx->r, rule->var_index);
    
        if (vv == NULL || vv->not_found) {
            return RULE_NO_MATCH;
        }

        ngx_str_t tmp = {vv->len, vv->data};

        var = ngx_array_push(var_array);
        var->data = ngx_pstrdup(ctx->r->pool, &tmp);
        var->len = vv->len;
    }

    return NGX_OK;
}

static re_var_metadata var_metadata[] = {
    { ngx_string("ARGS"), ngx_http_yy_sec_waf_generate_args },
    { ngx_string("PROCESS_BODY_ERROR"), ngx_http_yy_sec_waf_generate_process_body_error },
    { ngx_string("MULTIPART_NAME"), ngx_http_yy_sec_waf_generate_multipart_name},
    { ngx_string("MULTIPART_FILENAME"), ngx_http_yy_sec_waf_generate_multipart_filename},
    { ngx_string("$"), ngx_http_yy_sec_waf_generate_inner_var },
    { ngx_null_string, NULL }
};

ngx_int_t
yy_sec_waf_init_variables_in_hash(ngx_conf_t *cf,
    ngx_hash_t *variables_in_hash)
{
    ngx_array_t         variables;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    re_var_metadata    *metadata;

    if (ngx_array_init(&variables, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (metadata = var_metadata; metadata->name.len; metadata++) {
        hk = ngx_array_push(&variables);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = metadata->name;
        hk->key_hash = ngx_hash_key_lc(metadata->name.data, metadata->name.len);
        hk->value = metadata;
    }

    hash.hash = variables_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "variables_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, variables.elts, variables.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

