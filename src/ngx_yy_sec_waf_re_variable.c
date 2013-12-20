/*
** @file: ngx_yy_sec_waf_re_variable.c
** @description: This is the rule engine's variables for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.08
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf_re.h"

static ngx_http_variable_value_t  yy_sec_waf_false_value = ngx_http_variable("0");

static ngx_http_variable_value_t  yy_sec_waf_true_value = ngx_http_variable("1");

/*
** @description: This function is called to generate args.
** @para: ngx_http_request_t *r
** @para: ngx_http_variable_value_t *v
** @para: uintptr_t data
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
yy_sec_waf_generate_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->phase & REQUEST_HEADER_PHASE) {
        v->data = ctx->args.data;
        v->len = ctx->args.len;
    } else if (ctx->phase & REQUEST_BODY_PHASE) {
        v->data = ctx->post_args.data;
        v->len = ctx->post_args.len;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;

    return NGX_OK;
}

/*
** @description: This function is called to generate post args count.
** @para: ngx_http_request_t *r
** @para: ngx_http_variable_value_t *v
** @para: uintptr_t data
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
yy_sec_waf_generate_post_args_count(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_yy_sec_waf_uitoa(r->pool, ctx->post_args_count);

    v->len = ngx_strlen(p);
    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

/*
** @description: This function is called to generate process body error.
** @para: ngx_http_request_t *r
** @para: ngx_http_variable_value_t *v
** @para: uintptr_t data
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
yy_sec_waf_generate_process_body_error(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->process_body_error == 1) {
        *v = yy_sec_waf_true_value;
    } else {
        *v = yy_sec_waf_false_value;
    }

    return NGX_OK;
}

/*
** @description: This function is called to generate multipart name.
** @para: ngx_http_request_t *r
** @para: ngx_http_variable_value_t *v
** @para: uintptr_t data
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
yy_sec_waf_generate_multipart_name(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t                 i;
    ngx_str_t                 *var;
    u_char                    *p;
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    var = ctx->multipart_name.elts;

    for (i = 0; i < ctx->multipart_name.nelts; i++) {
        v->len += var[i].len;
    }

    v->data = ngx_palloc(r->pool, v->len);

    p = v->data;

    for (i = 0; i < ctx->multipart_name.nelts; i++) {
        v->data = ngx_cpymem(v->data, var[i].data, var[i].len);
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

/*
** @description: This function is called to generate multipart filename.
** @para: ngx_http_request_t *r
** @para: ngx_http_variable_value_t *v
** @para: uintptr_t data
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
yy_sec_waf_generate_multipart_filename(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t                 i;
    ngx_str_t                 *var;
    u_char                    *p;
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    var = ctx->multipart_filename.elts;

    for (i = 0; i < ctx->multipart_filename.nelts; i++) {
        v->len += var[i].len;
    }

    v->data = ngx_palloc(r->pool, v->len);

    p = v->data;

    for (i = 0; i < ctx->multipart_filename.nelts; i++) {
        v->data = ngx_cpymem(v->data, var[i].data, var[i].len);
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

/*
** @description: This function is called to generate connection per ip.
** @para: ngx_http_request_t *r
** @para: ngx_http_variable_value_t *v
** @para: uintptr_t data
** @return: static ngx_int_t.
*/

static ngx_int_t
yy_sec_waf_generate_conn_per_ip(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_yy_sec_waf_uitoa(r->pool, ctx->conn_per_ip);

    v->len = ngx_strlen(p);
    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

/*
** @description: This function is called to generate inner variable.
** @para: ngx_http_request_t *r
** @para: ngx_http_variable_value_t *v
** @para: uintptr_t data
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
yy_sec_waf_generate_inner_var(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_variable_value_t *vv;
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if ((ngx_int_t)data != NGX_ERROR) {
        vv = ngx_http_get_indexed_variable(r, data);
    
        if (vv == NULL || vv->not_found) {
            return NGX_ERROR;
        }

        ngx_memcpy(v, vv, sizeof(ngx_http_variable_value_t));
    }

    return NGX_OK;
}

static ngx_http_variable_t var_metadata[] = {

    { ngx_string("ARGS"), NULL, yy_sec_waf_generate_args,
      0, 0, 0 },

    { ngx_string("POST_ARGS_COUNT"), NULL, yy_sec_waf_generate_post_args_count,
      0, 0, 0 },

    { ngx_string("PROCESS_BODY_ERROR"), NULL, yy_sec_waf_generate_process_body_error,
      0, 0, 0 },

    { ngx_string("MULTIPART_NAME"), NULL, yy_sec_waf_generate_multipart_name,
      offsetof(ngx_http_request_ctx_t, multipart_name), 0, 0 },

    { ngx_string("MULTIPART_FILENAME"), NULL, yy_sec_waf_generate_multipart_filename,
      offsetof(ngx_http_request_ctx_t, multipart_filename), 0, 0 },

    { ngx_string("CONN_PER_IP"), NULL, yy_sec_waf_generate_conn_per_ip,
      0, 0, 0 },

    { ngx_string("$"), NULL, yy_sec_waf_generate_inner_var,
      0, 0, 0 },

    { ngx_null_string, NULL, NULL,
      0, 0, 0 }
};

/*
** @description: This function is called to init variables.
** @para: ngx_conf_t *cf
** @para: ngx_hash_t *variables_in_hash
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_init_variables_in_hash(ngx_conf_t *cf,
    ngx_hash_t *variables_in_hash)
{
    ngx_array_t          variables;
    ngx_hash_key_t      *hk;
    ngx_hash_init_t      hash;
    ngx_http_variable_t *metadata;

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


