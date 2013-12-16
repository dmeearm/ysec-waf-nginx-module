/*
** @file: ngx_yy_sec_waf_re_variable.c
** @description: This is the rule engine's variables for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.08
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

static ngx_http_variable_value_t  yy_sec_waf_false_value = ngx_http_variable("0");

static ngx_http_variable_value_t  yy_sec_waf_true_value = ngx_http_variable("1");

/*
** @description: This function is called to generate args.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
yy_sec_waf_generate_args(void *rule_p,
    void *ctx_p, ngx_http_variable_value_t *v)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || v == NULL) {
        return NGX_ERROR;
    }

    if (ctx->phase & REQUEST_HEADER_PHASE) {
        v->data = ctx->args->data;
        v->len = ctx->args->len;
    } else if (ctx->phase & REQUEST_BODY_PHASE) {
        v->data = ctx->post_args->data;
        v->len = ctx->post_args->len;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;

    return NGX_OK;
}

/*
** @description: This function is called to generate post args count.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
yy_sec_waf_generate_post_args_count(void *rule_p,
    void *ctx_p, ngx_http_variable_value_t *v)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || v == NULL) {
        return NGX_ERROR;
    }

    u_char *tmp = ngx_yy_sec_waf_uitoa(ctx->pool, ctx->post_args_count);

    v->len = ngx_strlen(tmp);
    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = tmp;

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
yy_sec_waf_generate_process_body_error(void *rule_p,
    void *ctx_p, ngx_http_variable_value_t *v)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || v == NULL) {
        return NGX_ERROR;
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
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: NGX_OK or NGX_ERROR if failed.
*/

static int
yy_sec_waf_generate_multipart_name(void *rule_p,
    void *ctx_p, ngx_http_variable_value_t *v)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || v == NULL) {
        return NGX_ERROR;
    }

    ngx_uint_t i;
    ngx_str_t *var;
    u_char    *tmp;

    var = ctx->multipart_name->elts;

    for (i = 0; i < ctx->multipart_name->nelts; i++) {
        v->len += var[i].len;
    }

    v->data = ngx_palloc(ctx->pool, v->len);

    tmp = v->data;

    for (i = 0; i < ctx->multipart_name->nelts; i++) {
        v->data = ngx_cpymem(v->data, var[i].data, var[i].len);
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = tmp;

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
yy_sec_waf_generate_multipart_filename(void *rule_p,
    void *ctx_p, ngx_http_variable_value_t *v)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || v == NULL) {
        return NGX_ERROR;
    }

    ngx_uint_t i;
    ngx_str_t *var;
    u_char    *tmp;

    var = ctx->multipart_filename->elts;

    for (i = 0; i < ctx->multipart_filename->nelts; i++) {
        v->len += var[i].len;
    }

    v->data = ngx_palloc(ctx->pool, v->len);

    tmp = v->data;

    for (i = 0; i < ctx->multipart_filename->nelts; i++) {
        v->data = ngx_cpymem(v->data, var[i].data, var[i].len);
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = tmp;

    return NGX_OK;
}

/*
** @description: This function is called to generate connection per ip.
** @para: void *rule_p
** @para: void *ctx_p
** @para: ngx_str_t *var
** @return: static int.
*/

static int
yy_sec_waf_generate_conn_per_ip(void *rule_p,
    void *ctx_p, ngx_http_variable_value_t *v)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || v == NULL) {
        return NGX_ERROR;
    }

    u_char *tmp = ngx_yy_sec_waf_uitoa(ctx->pool, ctx->conn_per_ip);

    v->len = ngx_strlen(tmp);
    v->valid = 1;
    v->no_cacheable = 0;
    v->escape = 0;
    v->not_found = 0;
    v->data = tmp;

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
yy_sec_waf_generate_inner_var(void *rule_p,
    void *ctx_p, ngx_http_variable_value_t *v)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || v == NULL) {
        return NGX_ERROR;
    }

    ngx_http_variable_value_t *vv;
    
    if (rule->var_index != NGX_CONF_UNSET) {
        vv = ngx_http_get_indexed_variable(ctx->r, rule->var_index);
    
        if (vv == NULL || vv->not_found) {
            return NGX_ERROR;
        }

        ngx_memcpy(v, vv, sizeof(vv));
    }

    return NGX_OK;
}

static re_var_metadata var_metadata[] = {
    { ngx_string("ARGS"), yy_sec_waf_generate_args },
    { ngx_string("POST_ARGS_COUNT"), yy_sec_waf_generate_post_args_count },
    { ngx_string("PROCESS_BODY_ERROR"), yy_sec_waf_generate_process_body_error },
    { ngx_string("MULTIPART_NAME"), yy_sec_waf_generate_multipart_name},
    { ngx_string("MULTIPART_FILENAME"), yy_sec_waf_generate_multipart_filename},
    { ngx_string("CONN_PER_IP"), yy_sec_waf_generate_conn_per_ip },
    { ngx_string("$"), yy_sec_waf_generate_inner_var },
    { ngx_null_string, NULL }
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


