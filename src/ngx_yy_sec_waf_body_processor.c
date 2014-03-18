/*
** @file: ngx_yy_sec_waf_body_processor.c
** @description: This is the body processor for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.17
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: This function is called to process spliturl of the request.
** @para: ngx_http_request_t *r
** @para: ngx_str_t *str
** @para: ngx_array_t *rules
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_process_spliturl(ngx_http_request_t *r,
    ngx_str_t *str, ngx_http_request_ctx_t *ctx)
{
    u_char    *start, *buffer, *eq, *ev;
    ngx_uint_t len, arg_cnt, arg_len, nullbytes, buffer_size;
    ngx_str_t  value;

    buffer = start = str->data;
    len =  str->len;
    buffer_size = arg_len = 0;

    if (len != 0)
        arg_cnt = 1;

    while ((len != 0) && *start) {
        if (*start == '&') {
            buffer_size++;
            *buffer++ = '$';
            arg_cnt++;
            start++;
            continue;
        }

        eq = (u_char*)ngx_strchr((char*)start, '=');
        ev = (u_char*)ngx_strchr((char*)start, '&');

        if (eq) {
            if (!ev)
                ev = str->data + str->len;
            arg_len = ev - start;
            eq = ngx_strlchr(start, start+arg_len, '=');
            if (!eq)
                return NGX_ERROR;

            eq++;
            value.data = eq;
            value.len = ev - eq;
        } else {
            break;
        }

        nullbytes = ngx_yy_sec_waf_unescape(&value);

        if (nullbytes > 0) {
            ctx->process_body_error = 1;
            ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_HEX_ENCODING");
            return NGX_ERROR;
        }

        buffer = ngx_cpymem(buffer, value.data, value.len);
        buffer_size += value.len;

        start += arg_len;
    }

    str->len = buffer_size;

    /* convert \r\n to blank as '  ' to improve the format of error log */
    buffer = str->data;

    while (buffer_size-- > 0) {
        if (*buffer == '\n' || *buffer == '\r')
            *buffer = ' ';
        buffer++;
    }

    ctx->post_args.len = str->len;
    ctx->post_args.data = ngx_palloc(r->pool, str->len);
    if (ctx->post_args.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->post_args.data, str->data, str->len);
    ctx->post_args_count = arg_cnt;
    ctx->post_args_len = str->len;

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
    u_char *boundary, *line_start, *line_end, *body_end, *p;
    ngx_uint_t boundary_len, idx, nullbytes;
    ngx_str_t name, filename, content_type, *tmp;

    boundary = NULL;
    boundary_len = 0;

    if (r == NULL || full_body == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_yy_sec_waf_process_boundary(r, &boundary, &boundary_len) != NGX_OK) {
        ctx->process_body_error = 1;
        ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_CONTENT_TYPE");
        return NGX_ERROR;
    }

    ctx->boundary = boundary;
    ctx->boundary_len = boundary_len;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] boundary: %s", boundary);

    idx = 0;

    p = ngx_strlcasestrn(full_body->data, full_body->data+full_body->len, boundary, boundary_len-1);
    if (p == NULL)
        return NGX_ERROR;

    full_body->len = full_body->len - (p - full_body->data - 2);
    full_body->data = p - 2;

    while (idx < full_body->len) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] request_body: %s, len: %d", full_body->data+idx, full_body->len);

        if (idx+boundary_len+6 == full_body->len || idx+boundary_len+4 == full_body->len) {
            if (ngx_strncmp(full_body->data+idx, "--", 2)
                || ngx_strncmp(full_body->data+idx+2, boundary, boundary_len)
                || ngx_strncmp(full_body->data+idx+boundary_len+2, "--", 2)) {
                ctx->process_body_error = 1;
                ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_POST_FORMAT");
                return NGX_ERROR;
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
            ctx->process_body_error = 1;
            ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_POST_BOUNDARY");
            return NGX_ERROR;
        }

        /* plus with 4 for -- and \r\n*/
        idx += boundary_len + 4;
        if (ngx_strncasecmp(full_body->data+idx, (u_char*)"content-disposition: form-data;",
            ngx_strlen("content-disposition: form-data;"))) {
            ctx->process_body_error = 1;
            ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_POST_FORMAT");
            return NGX_ERROR;
        }

        idx += ngx_strlen("content-disposition: form-data;");

        /* ignore 0x00 for %00 injection situation */
        line_end = (u_char*) ngx_strlchr(full_body->data+idx, full_body->data+full_body->len, '\n');
        if (!line_end) {
            ctx->process_body_error = 1;
            ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_POST_FORMAT");
            return NGX_ERROR;
        }

        ngx_memzero(&name, sizeof(ngx_str_t));
        ngx_memzero(&filename, sizeof(ngx_str_t));
        ngx_memzero(&content_type, sizeof(ngx_str_t));

        ngx_http_yy_sec_waf_process_disposition(r, full_body->data+idx, line_end, &name, &filename);

        tmp = ngx_array_push(&ctx->multipart_filename);
        if (tmp == NULL)
            return NGX_ERROR;

        ngx_memcpy(tmp, &filename, sizeof(ngx_str_t));

        tmp = ngx_array_push(&ctx->multipart_name);
        if (tmp == NULL)
            return NGX_ERROR;

        ngx_memcpy(tmp, &name, sizeof(ngx_str_t));

        if (filename.data) {
            line_start = line_end + 1;
            line_end = (u_char*) ngx_strchr(line_start, '\n');
            if (!line_end) {
                ctx->process_body_error = 1;
                ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_POST_FORMAT");
                return NGX_ERROR;
            }

            content_type.data = line_start + ngx_strlen("content-type: ");
            content_type.len = (line_end - 1) - content_type.data;

            tmp = ngx_array_push(&ctx->content_type);
            if (tmp == NULL)
                return NGX_ERROR;

            ngx_memcpy(tmp, &content_type, sizeof(ngx_str_t));
        }

        idx += (u_char*)line_end - (full_body->data + idx) + 1;
        if (full_body->data[idx] != '\r' || full_body->data[idx+1] != '\n') {
            ctx->process_body_error = 1;
            ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_POST_FORMAT");
            return NGX_ERROR;
        }

        idx += 2;
        body_end = NULL;

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
                ctx->process_body_error = 1;
                ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_POST_FORMAT");
                return NGX_ERROR;
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
                ctx->process_body_error = 1;
                ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_HEX_ENCODING");
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[ysec_waf] checking filename [%V]", &filename);

            if (content_type.data) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "[ysec_waf] checking content_type [%V]", &content_type);

                if (!ngx_strnstr(filename.data, ".html", filename.len)
                    || !ngx_strnstr(filename.data, ".html", filename.len)) {
                    if (!ngx_strncmp(content_type.data, "text/html", content_type.len)) {
                        ctx->process_body_error = 1;
                        ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_FILENAME");
                        return NGX_ERROR;
                    }
                }
                else if (!ngx_strnstr(filename.data, ".php", filename.len)
                    || !ngx_strnstr(filename.data, ".jsp", filename.len)) {
                    if (!ngx_strncmp(content_type.data, "application/octet-stream", content_type.len)) {
                        ctx->process_body_error = 1;
                        ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_FILENAME");
                        return NGX_ERROR;
                    }
                }
            }

            idx += (u_char*)body_end - (full_body->data + idx);
        } else if (name.data) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[ysec_waf] checking name [%V]", &name);

            idx += (u_char*)body_end - (full_body->data + idx);
        }

        if (!ngx_strncmp(body_end, "\r\n", ngx_strlen("\r\n")))
            idx += ngx_strlen("\r\n");
    }

    return NGX_OK;
}

/*
** @description: This function is called to process the body of the request.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_loc_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_process_body(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
    u_char      *src;
    ngx_chain_t *bb;
    ngx_str_t   *full_body;

    if (!r->request_body->bufs || !r->headers_in.content_type) {
        ctx->process_body_error = 1;
        ngx_str_set(&ctx->process_body_error_msg, "UNCOMMON_CONTENT_TYPE");
        return NGX_ERROR;
    }

    if (r->request_body->temp_file) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] post body is stored in temp_file.");
        return NGX_ERROR;
    }

    full_body = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (full_body == NULL) {
        return NGX_ERROR;
    }

    if (r->request_body->bufs->next == NULL) {
        full_body->len = (ngx_uint_t) (r->request_body->bufs->buf->last
            - r->request_body->bufs->buf->pos);

        full_body->data = ngx_pcalloc(r->pool, full_body->len+1);

        ngx_memcpy(full_body->data, r->request_body->bufs->buf->pos, full_body->len);
    } else {
        for (full_body->len = 0, bb = r->request_body->bufs; bb; bb = bb->next)
            full_body->len += bb->buf->last - bb->buf->pos;

        full_body->data = ngx_pcalloc(r->pool, full_body->len+1);

        if (full_body->data == NULL)
            return NGX_ERROR;

        src = full_body->data;

        for (bb = r->request_body->bufs; bb; bb = bb->next)
            full_body->data = ngx_cpymem(full_body->data, bb->buf->pos,
                bb->buf->last - bb->buf->pos);

        full_body->data = src;
    }

    //ngx_yy_sec_waf_unescape(full_body);

    if (!ngx_strncasecmp(r->headers_in.content_type->value.data,
        (u_char*)"multipart/form-data", ngx_strlen("multipart/form-data"))) {
        /* MULTIPART */
        ngx_http_yy_sec_waf_process_multipart(r, full_body, ctx);
    } else if (!ngx_strncasecmp(r->headers_in.content_type->value.data,
        (u_char*)"application/x-www-form-urlencoded", ngx_strlen("application/x-www-form-urlencoded"))) {
        /* X-WWW-FORM-URLENCODED */
        ctx->post_args_len = full_body->len;

        ngx_http_yy_sec_waf_process_spliturl(r, full_body, ctx);
    }

    return NGX_OK;
}


