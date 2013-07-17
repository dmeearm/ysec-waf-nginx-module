/*
** @file: ngx_yy_sec_waf_processor.c
** @description: This is the rule processor for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.17
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: This function is called to process common rule of the request.
** @para: ngx_http_request_t *r
** @para: ngx_str_t *str
** @para: ngx_array_t *rules
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_CONF_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_rules(ngx_http_request_t *r,
    ngx_str_t *str, ngx_array_t *rules, ngx_http_request_ctx_t *ctx)
{
    int *captures, rc;
    ngx_uint_t i, n;
    ngx_http_yy_sec_waf_rule_t *rule_p;

    rule_p = rules->elts;

    for (i = 0; i < rules->nelts; i++) {
        /* Simply match basic rule with the args.
             TODO: regx->low sec, string->medium sec, char->high sec. */
        if (rule_p[i].str != NULL) {
            /* STR */
            if (ngx_strnstr(str->data, (char*) rule_p[i].str->data, str->len)) {
    			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] rule matched");

                ctx->matched = 1;
                break;
            }
        }

        if (rule_p[i].rgc != NULL) {
            /* REGEX */
            n = (rule_p[i].rgc->captures + 1) * 3;
            
            captures = ngx_palloc(r->pool, n*sizeof(int));
    
            if (captures == NULL) {
                return NGX_ERROR;
            }
            
            rc = ngx_regex_exec(rule_p[i].rgc->regex, str, captures, n);
            
            if (rc < NGX_REGEX_NO_MATCHED) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                              rc, str, &rule_p[i].rgc->pattern);
                return NGX_ERROR;
            }
            
            if (rc == NGX_REGEX_NO_MATCHED) {
                return NGX_DECLINED;
            }
    
    		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] rule matched");
    
            ctx->matched = 1;
            break;
        }
    }

    return NGX_OK;
}

/*
** @description: This function is called to process the args of the request.
** @para: ngx_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_http_request_t *r
** @return: NGX_CONF_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_args(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
    ngx_str_t  tmp_args;

    tmp_args.len = r->args.len;
    tmp_args.data = ngx_pcalloc(r->pool, tmp_args.len);

    if (tmp_args.data == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpymem(tmp_args.data, r->args.data, tmp_args.len);

    /* Decode the args of the request to compare with basic rules.
      TODO: take some more complex situations into account. */
    ngx_yy_sec_waf_unescape(&tmp_args);

    return ngx_http_yy_sec_waf_process_rules(r, &tmp_args, cf->args_rules, ctx);
}

/*
** @description: This function is called to process the request.
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_http_request_t *r
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_process_request(ngx_http_request_t *r)
{
    int rc;
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_http_request_ctx_t         *ctx;

	cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] ngx_http_get_module_loc_conf failed.");
        return NGX_ERROR;
    }

    /* Simply parse args.
      TODO: parse header, uri and body later.*/
    if ((rc = ngx_http_yy_sec_waf_process_args(r, cf, ctx)) != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}

