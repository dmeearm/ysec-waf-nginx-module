/*
** @file: ngx_yy_sec_waf_processor.c
** @description: This is the rule processor for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.17
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

static ngx_http_yy_sec_waf_rule_t wired_request = {
    .mod = 0,
    .rule_id = 1,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t uncommon_hex_encoding = {
    .mod = 1,
    .rule_id = 2,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t uncommon_content_type = {
    .mod = 0,
    .rule_id = 3,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t uncommon_url = {
    .mod = 0,
    .rule_id = 4,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t uncommon_post_format = {
    .mod = 0,
    .rule_id = 5,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t uncommon_post_boundary = {
    .mod = 0,
    .rule_id = 6,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t big_request = {
    .mod = 0,
    .rule_id = 7,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t special_file_charactor = {
    .mod = 0,
    .rule_id = 8,
    .log = 1,
    .block =1,
};

static ngx_http_yy_sec_waf_rule_t uncommon_filename_postfix = {
    .mod = 1,
    .rule_id = 9,
    .log = 1,
    .block = 1,
};

static ngx_http_yy_sec_waf_rule_t uncommon_filename = {
    .mod = 1,
    .rule_id = 10,
    .log = 1,
    .block = 1,
};

/* For those unused mod rules, we just set mod flag as false. */
ngx_http_yy_sec_waf_rule_t *mod_rules[] = {
    &wired_request,
    &uncommon_hex_encoding,
    &uncommon_content_type,
    &uncommon_url,
    &uncommon_post_format,
    &uncommon_post_boundary,
    &big_request,
    &special_file_charactor,
    &uncommon_filename_postfix,
    &uncommon_filename,
    NULL
};

const ngx_uint_t mod_rules_num = sizeof(mod_rules)/sizeof(ngx_http_yy_sec_waf_rule_t*) - 1;

static ngx_int_t ngx_http_yy_sec_waf_process_multipart(ngx_http_request_t* r,
    ngx_str_t* str, ngx_http_request_ctx_t* ctx);
static ngx_int_t ngx_http_yy_sec_waf_process_basic_rule(ngx_http_request_t *r,
    ngx_str_t *str, ngx_http_yy_sec_waf_rule_t *rule, ngx_http_request_ctx_t *ctx);
static ngx_int_t ngx_http_yy_sec_waf_apply_mod_rule(ngx_http_request_t *r,
    ngx_str_t *str, ngx_http_yy_sec_waf_rule_t *rule, ngx_http_request_ctx_t *ctx);

#define yy_sec_waf_apply_mod_rule(r, str, rule, ctx) do {        \
    if (rule.mod) {                                              \
        ngx_http_yy_sec_waf_apply_mod_rule(r, str, &rule, ctx);  \
        if (ctx->matched) {                                      \
    		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,  \
                "[waf] mod rule(id:%d) matched in func:%s file:%s line:%d",      \
                 ctx->rule_id, __func__, __FILE__, __LINE__);    \
            return NGX_ERROR;                                    \
        }                                                        \
    }                                                            \
} while (0)

/*
** @description: This function is called to apply the mod rule of yy sec waf.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_apply_mod_rule(ngx_http_request_t *r,
    ngx_str_t *str, ngx_http_yy_sec_waf_rule_t *rule, ngx_http_request_ctx_t *ctx)
{
    if (rule == NULL || ctx == NULL)
        return NGX_ERROR;

    if (rule->mod) {
        ngx_http_yy_sec_waf_process_basic_rule(r, str, rule, ctx);

        if (ctx->matched) {
            ctx->rule_id = rule->rule_id;
            ctx->block = rule->block;
            ctx->log = rule->log;
            ctx->gids = rule->gids;
            ctx->msg = rule->msg;
        }
    }

    return NGX_OK;
}

/*
** @description: This function is called to process basic rule of the request.
** @para: ngx_str_t *str
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_basic_rule(ngx_http_request_t *r,
    ngx_str_t *str, ngx_http_yy_sec_waf_rule_t *rule, ngx_http_request_ctx_t *ctx)
{
    int       *captures, rc;
    ngx_uint_t n;

    if (str == NULL && rule->mod) {
        ctx->matched = 1;
        return NGX_OK;
    }

    if (str == NULL)
        return NGX_ERROR;

    /* Simply match basic rule with the args.
      TODO: regx->low sec, string->medium sec, char->high sec. */
    if (rule->rgc != NULL) {
        /* REGEX */
        n = (rule->rgc->captures + 1) * 3;
        
        captures = ngx_palloc(r->pool, n*sizeof(int));
        
        if (captures == NULL) {
            return NGX_ERROR;
        }
        
        rc = ngx_regex_exec(rule->rgc->regex, str, captures, n);
        
        ngx_pfree(r->pool, captures);
        
        if (rc == NGX_REGEX_NO_MATCHED) {
            return NGX_OK;
        } else if (rc < NGX_REGEX_NO_MATCHED) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                rc, str, &rule->rgc->pattern);
            return NGX_ERROR;
        } else {
            ctx->matched_rule = &rule->rgc->pattern;
            ctx->matched = 1;
            return NGX_OK;
        }
    } else if (rule->str != NULL) {
        /* STR */
        if (ngx_strnstr(str->data, (char*) rule->str->data, str->len)) {
            ctx->matched_rule = rule->str;
            ctx->matched = 1;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

/*
** @description: This function is called to process basic rules of the request.
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
    int        rc;
    ngx_uint_t i;
    ngx_http_yy_sec_waf_rule_t *rule_p;

    if (rules == NULL)
        return NGX_ERROR;

    rule_p = rules->elts;

    for (i = 0; i < rules->nelts; i++) {
        rc = ngx_http_yy_sec_waf_process_basic_rule(r, str, &rule_p[i], ctx);

        if (rc == NGX_ERROR)
            return rc;

        if (ctx->matched_rule)
            break;
    }

    if (ctx->matched_rule != NULL) {
		ctx->matched = 1;
		ctx->block = rule_p->block;
		ctx->log = rule_p->log;
		ctx->gids = rule_p->gids;
		ctx->msg = rule_p->msg;
    }

    return NGX_OK;
}

/*
** @description: This function is called to process the boundary of the request.
** @para: ngx_http_request_t *r
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_str_t full_body
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_boundary(ngx_http_request_t *r,
    u_char **boundary, ngx_uint_t *boundary_len)
{
    u_char *start;
    u_char *end;

    start = r->headers_in.content_type->value.data + ngx_strlen("multipart/form-data;");
    end = r->headers_in.content_type->value.data + r->headers_in.content_type->value.len;

    while (start < end && *start && (*start == ' ' || *start == '\t'))
        start++;

    if (ngx_strncmp(start, "boundary=", ngx_strlen("boundary=")))
        return NGX_ERROR;

    start += ngx_strlen("boundary=");

    *boundary_len = end - start;
    *boundary = start;

    if (*boundary_len > 70)
        return NGX_ERROR;

    return NGX_OK;
}

/*
** @description: This function is called to process the disposition of the request.
** @para: ngx_http_request_t *r
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_str_t full_body
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_disposition(ngx_http_request_t *r,
    u_char *str, u_char *line_end, ngx_str_t *name, ngx_str_t *filename)
{
    u_char *name_start, *name_end, *filename_start, *filename_end;

    while (str < line_end) {
        while(str < line_end && *str && (*str == ' ' || *str == '\t'))
            str++;
        if (str < line_end && *str && *str == ';')
            str++;
        while (str < line_end && *str && (*str == ' ' || *str == '\t'))
            str++;

        if (str >= line_end || !*str)
            break;

        if (!ngx_strncmp(str, "name=\"", ngx_strlen("name=\""))) {
            name_start = name_end = str + ngx_strlen("name=\"");
            do {
                name_end = (u_char*) ngx_strchr(name_end, '"');
                if (name_end && *(name_end - 1) != '\\')
                    break;
                name_end++;
            } while (name_end && name_end < line_end);

            if (!name_end || !*name_end)
                return NGX_ERROR;

            str = name_end;

			if (str < line_end + 1)
                str++;
            else
                return NGX_ERROR;

            name->data = name_start;
            name->len = name_end - name_start;
        } 
        else if (!ngx_strncmp(str, "filename=\"", ngx_strlen("filename=\""))) {
            filename_end = filename_start = str + ngx_strlen("filename=\"");
            do {
                /* ignore 0x00 for %00 injection situation */
                filename_end = (u_char*) ngx_strlchr(filename_end, line_end, '"');
                if (filename_end && *(filename_end - 1) != '\\')
                    break;
                filename_end++;
            } while (filename_end && filename_end < line_end);

            if (!filename_end)
                return NGX_ERROR;

            str = filename_end;
            if (str < line_end + 1)
                str++;
            else
                return NGX_ERROR;

            filename->data = filename_start;
            filename->len = filename_end - filename_start;
        }
        else if (str == line_end - 1)
            break;
		else {
            return NGX_ERROR;
		}
    }

    if (filename_end > line_end || name_end > line_end)
        return NGX_ERROR;

    return NGX_OK;
}

/*
** @description: This function is called to process the multipart of the request.
** @para: ngx_http_request_t *r
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_str_t full_body
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_multipart(ngx_http_request_t *r,
    ngx_str_t *full_body, ngx_http_request_ctx_t *ctx)
{
    u_char *boundary, *line_start, *line_end, *body_end;
    ngx_uint_t boundary_len, idx, nullbytes;
    ngx_str_t name, filename, content_type;

    boundary = NULL;
    boundary_len = 0;

	if (ngx_http_yy_sec_waf_process_boundary(r, &boundary, &boundary_len) != NGX_OK) {
        yy_sec_waf_apply_mod_rule(r, NULL, wired_request, ctx);
	}

    idx = 0;

    while (idx < full_body->len) {
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] request_body: %s", full_body->data+idx);

        if (idx+boundary_len+6 == full_body->len || idx+boundary_len+4 == full_body->len) {
            if (ngx_strncmp(full_body->data+idx, "--", 2) ||
                ngx_strncmp(full_body->data+idx+2, boundary, boundary_len) ||
                ngx_strncmp(full_body->data+idx+boundary_len+2, "--", 2)) {
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 1");
                yy_sec_waf_apply_mod_rule(r, NULL, uncommon_post_boundary, ctx);
            } else
                break;
        }

        if ((full_body->len-idx < 4+boundary_len)
            || full_body->data[idx] != '-'
            || full_body->data[idx+1] != '-'
            || ngx_strncmp(full_body->data+idx+2, boundary, boundary_len)
            || idx+boundary_len+2+2 >= full_body->len
            || full_body->data[idx+boundary_len+2] != '\r'
            || full_body->data[idx+boundary_len+2+1] != '\n') {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 2");
            yy_sec_waf_apply_mod_rule(r, NULL, uncommon_post_boundary, ctx);
        }

        /* plus with 4 for -- and \r\n*/
        idx += boundary_len + 4;
        if (ngx_strncasecmp(full_body->data+idx, (u_char*)"content-disposition: form-data;",
            ngx_strlen("content-disposition: form-data;"))) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 3");
            yy_sec_waf_apply_mod_rule(r, NULL, uncommon_post_format, ctx);
        }

        idx += ngx_strlen("content-disposition: form-data;");

        /* ignore 0x00 for %00 injection situation */
        line_end = (u_char*) ngx_strlchr(full_body->data+idx, full_body->data+full_body->len, '\n');
        if (!line_end) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 4");
            return NGX_ERROR;
        }
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] idx(%d), len(%d)", idx, full_body->len);

        ngx_memzero(&name, sizeof(ngx_str_t));
        ngx_memzero(&filename, sizeof(ngx_str_t));
        ngx_memzero(&content_type, sizeof(ngx_str_t));

        ngx_http_yy_sec_waf_process_disposition(r, full_body->data+idx, line_end, &name, &filename);
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] idx(%d), len(%d)", idx, full_body->len);

        if (filename.data) {
            line_start = line_end + 1;
            line_end = (u_char*) ngx_strchr(line_start, '\n');
            if (!line_end) {
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 5");
                yy_sec_waf_apply_mod_rule(r, NULL, uncommon_post_format, ctx);
            }

            content_type.data = line_start + ngx_strlen("content-type: ");
            content_type.len = (line_end - 1) - content_type.data;
        }
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] idx(%d), len(%d)", idx, full_body->len);

        idx += (u_char*)line_end - (full_body->data + idx) + 1;
        if (full_body->data[idx] != '\r' || full_body->data[idx+1] != '\n') {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 6");
            yy_sec_waf_apply_mod_rule(r, NULL, uncommon_post_format, ctx);
        }

        idx += 2;
        body_end = NULL;
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] idx(%d), len(%d)", idx, full_body->len);

        while (idx < full_body->len) {
            body_end = (u_char*) ngx_strstr(full_body->data+idx, "\r\n--");
            while(!body_end) {
                idx += ngx_strlen((const char*)full_body->data+idx);
                if (idx < full_body->len-2) {
                    idx++;
                    body_end = (u_char*) ngx_strstr(full_body->data+idx, "\r\n--");
                } else
                    break;
            }

            if (!body_end) {
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 7");
                yy_sec_waf_apply_mod_rule(r, NULL, uncommon_post_format, ctx);
            }

            if (!ngx_strncmp(body_end+4, boundary, boundary_len))
                break;
            else {
                idx += (u_char*)body_end - (full_body->data + idx) + 1;
                body_end = NULL;
            }
        }

        if (!body_end) {
            return NGX_ERROR;
        }

        if (filename.data) {
            nullbytes = ngx_yy_sec_waf_unescape(&filename);
            if (nullbytes > 0) {
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] 8");
                yy_sec_waf_apply_mod_rule(r, NULL, uncommon_hex_encoding, ctx);
            }

            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "[waf] checking filename [%V]", &filename);

            if (content_type.data) {
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"[waf] checking content_type [%V]", &content_type);

                if (!ngx_strnstr(filename.data, ".html", filename.len)
                    || !ngx_strnstr(filename.data, ".html", filename.len)) {
                    if (!ngx_strncmp(content_type.data, "text/html", content_type.len)) {
                        yy_sec_waf_apply_mod_rule(r, NULL, uncommon_filename, ctx);
                    }
                }
                else if (!ngx_strnstr(filename.data, ".php", filename.len)
                    || !ngx_strnstr(filename.data, ".jsp", filename.len)) {
                    if (!ngx_strncmp(content_type.data, "application/octet-stream", content_type.len)) {
                        yy_sec_waf_apply_mod_rule(r, NULL, uncommon_filename, ctx);
                    }
                }
            }

            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] rule(%V)", &special_file_charactor.rgc->pattern);
            yy_sec_waf_apply_mod_rule(r, &filename, special_file_charactor, ctx);
            
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] rule(%V)", &uncommon_filename_postfix.rgc->pattern);
            yy_sec_waf_apply_mod_rule(r, &filename, uncommon_filename_postfix, ctx);

            idx += (u_char*)body_end - (full_body->data + idx);
        } else if (name.data) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "[waf] checking name [%V]", &name);

            idx += (u_char*)body_end - (full_body->data + idx);
        }

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] idx(%d), len(%d)", idx, full_body->len);
        if (!ngx_strncmp(body_end, "\r\n", ngx_strlen("\r\n")))
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] idx(%d), len(%d)", idx, full_body->len);
            idx += ngx_strlen("\r\n");
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
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[waf] no contenty type");
        ngx_http_yy_sec_waf_apply_mod_rule(r, NULL, &uncommon_content_type, ctx);
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

    if (!ngx_strncasecmp(r->headers_in.content_type->value.data,
        (u_char*)"multipart/form-data", ngx_strlen("multipart/form-data"))) {
        /* MULTIPART */
        ngx_http_yy_sec_waf_process_multipart(r, &full_body, ctx);
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


