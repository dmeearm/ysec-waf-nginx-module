/*
** @file: ngx_yy_sec_waf_processor.c
** @description: This is the rule processor for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.17
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: This function is called to process basic rule of the request.
** @para: ngx_http_request_t *r
** @para: ngx_str_t *str
** @para: ngx_array_t *rules
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_CONF_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_basic_rules(ngx_http_request_t *r,
    ngx_str_t *str, ngx_array_t *rules, ngx_http_request_ctx_t *ctx)
{
    int       *captures, rc;
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

            ngx_pfree(r->pool, captures);

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
** @description: This function is called to process the header of the request.
** @para: ngx_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_http_request_t *r
** @return: void.
*/

static void
ngx_http_yy_sec_waf_process_headers(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t       i;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; ;i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) 
                break;

            part = part->next;
            h = part->elts;
            i = 0;
        }

        ngx_http_yy_sec_waf_process_basic_rules(r, &h[i].value, cf->header_rules, ctx);
	}
}

/*
** @description: This function is called to process the uri of the request.
** @para: ngx_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_http_request_t *r
** @return: void.
*/

static void
ngx_http_yy_sec_waf_process_uri(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
    ngx_str_t  tmp;

    tmp.len = r->uri.len;
    tmp.data = ngx_pcalloc(r->pool, tmp.len);

    if (tmp.data == NULL) {
        return;
    }

    (void)ngx_memcpy(tmp.data, r->uri.data, tmp.len);

    ngx_http_yy_sec_waf_process_basic_rules(r, &tmp, cf->uri_rules, ctx);

    ngx_pfree(r->pool, tmp.data);
}

/*
** @description: This function is called to process the args of the request.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_loc_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @return: void.
*/

static void
ngx_http_yy_sec_waf_process_args(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
    ngx_str_t  tmp;

    if (r->args.len == 0)
        return;

    tmp.len = r->args.len;
    tmp.data = ngx_pcalloc(r->pool, tmp.len);

    if (tmp.data == NULL)
        return;

    (void)ngx_memcpy(tmp.data, r->args.data, tmp.len);

    ngx_yy_sec_waf_unescape(&tmp);

    ngx_http_yy_sec_waf_process_basic_rules(r, &tmp, cf->args_rules, ctx);

    ngx_pfree(r->pool, tmp.data);
}

/*
** @description: This function is called to process the request.
** @para: ngx_http_request_t *r
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_process_request(ngx_http_request_t *r)
{
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_http_request_ctx_t         *ctx;

	cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] ngx_http_get_module_loc_conf failed.");
        return NGX_ERROR;
    }

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] ngx_http_get_module_ctx failed.");
        return NGX_ERROR;
    }

    if (cf->header_rules != NULL)
        ngx_http_yy_sec_waf_process_headers(r, cf, ctx);

    if (cf->uri_rules != NULL)
        ngx_http_yy_sec_waf_process_uri(r, cf, ctx);

    if (cf->args_rules != NULL)
        ngx_http_yy_sec_waf_process_args(r, cf, ctx);

    /* TODO: process body, need test case for this situation. */

    return NGX_OK;
}

