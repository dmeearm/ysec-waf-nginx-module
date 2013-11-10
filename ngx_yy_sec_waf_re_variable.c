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
    void *ctx_p, ngx_str_t *var)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || var == NULL) {
        return NGX_ERROR;
    }

    if (ctx->phase == REQUEST_HEADER_PHASE) {
        var->data = ngx_pstrdup(ctx->r->pool, &ctx->r->args);
        var->len = ctx->r->args.len;
    } else if (ctx->phase == REQUEST_BODY_PHASE) {
        var->data = ngx_pstrdup(ctx->r->pool, ctx->post_args_value);
        var->len = ctx->post_args_value->len;
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
    void *ctx_p, ngx_str_t *var)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || var == NULL) {
        return NGX_ERROR;
    }

    if (ctx->process_body_error < 16 && ctx->process_body_error > 9) {
        ngx_str_set(var, "1");
    } else {
        ngx_str_set(var, "0");
    }

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
    void *ctx_p, ngx_str_t *var)
{
    ngx_http_request_ctx_t *ctx = (ngx_http_request_ctx_t *)ctx_p;
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t *)rule_p;

    if (rule == NULL || ctx == NULL || var == NULL) {
        return NGX_ERROR;
    }

    ngx_http_variable_value_t *vv;
    
    if (rule->var_index != NGX_CONF_UNSET) {
        vv = ngx_http_get_indexed_variable(ctx->r, rule->var_index);
    
        if (vv == NULL || vv->not_found) {
            return RULE_NO_MATCH;
        }

        ngx_str_t tmp = {vv->len, vv->data};
        var->data = ngx_pstrdup(ctx->r->pool, &tmp);
        var->len = vv->len;
    }

    return NGX_OK;
}

re_var_metadata var_metadata[] = {
    { "ARGS", ngx_http_yy_sec_waf_generate_args },
    { "PROCESS_BODY_ERROR", ngx_http_yy_sec_waf_generate_process_body_error },
    { "$", ngx_http_yy_sec_waf_generate_inner_var },
    { NULL, NULL }
};

