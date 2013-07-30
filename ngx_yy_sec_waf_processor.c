/*
** @file: ngx_yy_sec_waf_processor.c
** @description: This is the rule processor for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.17
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

#define JSON "application/json"
#define FORM_DATA "multipart/form-data"
#define X_WWW_FORM_URLENCODED "application/x-www-form-urlencoded"

/*
** @description: This function is called to apply the matched rule of the waf.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_apply_matched_rule(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_rule_t *rule, ngx_http_request_ctx_t *ctx)
{
    (void) r;

	ctx->matched = 1;
	ctx->block = rule->block;
	ctx->log = rule->log;
	ctx->gids = rule->gids;
	ctx->msg = rule->msg;

    return NGX_OK;
}


/*
** @description: This function is called to process basic rule of the request.
** @para: ngx_http_request_t *r
** @para: ngx_str_t *str
** @para: ngx_array_t *rules
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_basic_rules(ngx_http_request_t *r,
    ngx_str_t *str, ngx_array_t *rules, ngx_http_request_ctx_t *ctx)
{
    int       *captures, rc;
    ngx_uint_t i, n;
    ngx_http_yy_sec_waf_rule_t *rule_p;

    if (rules == NULL)
        return NGX_ERROR;

    rule_p = rules->elts;

    for (i = 0; i < rules->nelts; i++) {
        /* Simply match basic rule with the args.
             TODO: regx->low sec, string->medium sec, char->high sec. */
        if (rule_p[i].rgc != NULL) {
            /* REGEX */
            n = (rule_p[i].rgc->captures + 1) * 3;
            
            captures = ngx_palloc(r->pool, n*sizeof(int));
    
            if (captures == NULL) {
                return NGX_ERROR;
            }
            
            rc = ngx_regex_exec(rule_p[i].rgc->regex, str, captures, n);

            ngx_pfree(r->pool, captures);

            if (rc == NGX_REGEX_NO_MATCHED) {
                continue;
            } else if (rc < NGX_REGEX_NO_MATCHED) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                              rc, str, &rule_p[i].rgc->pattern);
                return NGX_ERROR;
            } else {
                ctx->matched_rule = &rule_p[i].rgc->pattern;
                break;
            }
        } else if (rule_p[i].str != NULL) {
            /* STR */
            if (ngx_strnstr(str->data, (char*) rule_p[i].str->data, str->len)) {
                ctx->matched_rule = rule_p[i].str;
                break;
            }
        }
    }

    if (ctx->matched_rule != NULL) {
        ngx_http_yy_sec_waf_apply_matched_rule(r, rule_p, ctx);
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
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_headers entry");

    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t       i;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; !ctx->matched; i++) {
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
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_uri Entry");

    ngx_str_t  tmp;

    tmp.len = r->uri.len;
    tmp.data = ngx_pcalloc(r->pool, tmp.len);

    if (tmp.data == NULL) {
        return;
    }

    (void)ngx_memcpy(tmp.data, r->uri.data, tmp.len);

    ngx_http_yy_sec_waf_process_basic_rules(r, &tmp, cf->uri_rules, ctx);

    ngx_pfree(r->pool, tmp.data);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_uri Exit");
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
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_args Entry");

    ngx_str_t  tmp;

    tmp.len = r->args.len;
    tmp.data = ngx_pcalloc(r->pool, tmp.len);

    if (tmp.data == NULL)
        return;

    (void)ngx_memcpy(tmp.data, r->args.data, tmp.len);

    ngx_yy_sec_waf_unescape(&tmp);

    ngx_http_yy_sec_waf_process_basic_rules(r, &tmp, cf->args_rules, ctx);

    ngx_pfree(r->pool, tmp.data);
	
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_args Exit");
}

/*
** @description: This function is called to process the body of the request.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_loc_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @return: void.
*/

static void
ngx_http_yy_sec_waf_process_body(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_body Entry");

    u_char      *src;
    ngx_chain_t *bb;
    ngx_str_t    full_body;
	
    if (!r->request_body->bufs || !r->headers_in.content_type) {
        return;
    }

    if (r->request_body->temp_file) {
        return;
    }

    if (r->request_body->bufs->next == NULL) {
        full_body.len = (ngx_uint_t) (r->request_body->bufs->buf->last
            - r->request_body->bufs->buf->pos);

        full_body.data = ngx_pcalloc(r->pool, (ngx_uint_t) (full_body.len));

        ngx_memcpy(full_body.data, r->request_body->buf->pos, full_body.len);
    } else {
        for (full_body.len = 0, bb = r->request_body->bufs; bb; bb = bb->next)
            full_body.len += bb->buf->last - bb->buf->pos;

        full_body.data = ngx_pcalloc(r->pool, full_body.len);

        if (full_body.data == NULL)
            return;

        src = full_body.data;

        for (bb = r->request_body->bufs; bb; bb = bb->next)
            full_body.data = ngx_cpymem(full_body.data, bb->buf->pos,
                bb->buf->last - bb->buf->pos);

        full_body.data = src;
    }

    if (r->headers_in.content_length_n != (off_t)full_body.len) {
        return;
    }

    if (!ngx_strncasecmp(r->headers_in.content_type->value.data,
        (u_char*)X_WWW_FORM_URLENCODED, ngx_strlen(X_WWW_FORM_URLENCODED))) {
        /* X_WWW_FORM_URLENCODED */
    } else if (!ngx_strncasecmp(r->headers_in.content_type->value.data,
        (u_char*)FORM_DATA, ngx_strlen(FORM_DATA))) {
        /* FORM_DATA */
    } else if (!ngx_strncasecmp(r->headers_in.content_type->value.data,
        (u_char*)JSON, ngx_strlen(JSON))) {
        /* JSON */
    } else {
        /* unkown content type */
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_body Exit");
}

/*
** @description: This function is called to process the request.
** @para: ngx_http_request_t *r
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_process_request(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_request entry");
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_http_request_ctx_t         *ctx;

	cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[waf] ngx_http_get_module_loc_conf failed.");
        return NGX_ERROR;
    }

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[waf] ngx_http_get_module_ctx failed.");
        return NGX_ERROR;
    }

    if (cf->header_rules != NULL)
        ngx_http_yy_sec_waf_process_headers(r, cf, ctx);

    if (!ctx->matched && cf->uri_rules != NULL)
        ngx_http_yy_sec_waf_process_uri(r, cf, ctx);

    if (!ctx->matched && cf->args_rules != NULL)
        ngx_http_yy_sec_waf_process_args(r, cf, ctx);

    /* TODO: process body, need test case for this situation. */
    if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT)
        && r->request_body && !ctx->matched) {
        ngx_http_yy_sec_waf_process_body(r, cf, ctx);
    }

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] ngx_http_yy_sec_waf_process_request exit");

    return NGX_OK;
}


