/*
** @file: ngx_yy_sec_waf_module.c
** @description: This is the core module for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.10
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

static ngx_int_t ngx_http_yy_sec_waf_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_yy_sec_waf_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_yy_sec_waf_output_forbidden_page(ngx_http_request_t *r,
    ngx_http_request_ctx_t *ctx);

static void ngx_http_yy_sec_waf_request_body_handler(ngx_http_request_t *r);
static void * ngx_http_yy_sec_waf_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_yy_sec_waf_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

extern char * ngx_http_yy_sec_waf_read_du_loc_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
extern char * ngx_http_yy_sec_waf_read_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
extern ngx_int_t ngx_http_yy_sec_waf_process_request(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx);

static ngx_conf_bitmask_t ngx_yy_sec_waf_method_bitmask[] = {
    { ngx_string("GET"), NGX_HTTP_GET },
    { ngx_string("HEAD"), NGX_HTTP_HEAD },
    { ngx_string("POST"), NGX_HTTP_POST },
    { ngx_string("PUT"), NGX_HTTP_PUT },
    { ngx_string("DELETE"), NGX_HTTP_DELETE },
    { ngx_string("MKCOL"), NGX_HTTP_MKCOL },
    { ngx_string("COPY"), NGX_HTTP_COPY },
    { ngx_string("MOVE"), NGX_HTTP_MOVE },
    { ngx_string("OPTIONS"), NGX_HTTP_OPTIONS },
    { ngx_string("PROPFIND"), NGX_HTTP_PROPFIND },
    { ngx_string("PROPPATCH"), NGX_HTTP_PROPPATCH },
    { ngx_string("LOCK"), NGX_HTTP_LOCK },
    { ngx_string("UNLOCK"), NGX_HTTP_UNLOCK },
    { ngx_string("PATCH"), NGX_HTTP_PATCH },
    { ngx_string("TRACE"), NGX_HTTP_TRACE },
    { ngx_null_string, 0 }
};

static ngx_command_t  ngx_http_yy_sec_waf_commands[] = {
    { ngx_string("yy_sec_waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_yy_sec_waf_loc_conf_t, enabled),
      NULL },

    { ngx_string("max_post_args_len"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_yy_sec_waf_loc_conf_t, max_post_args_len),
      NULL },

    { ngx_string("http_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_yy_sec_waf_loc_conf_t, http_method),
      &ngx_yy_sec_waf_method_bitmask },

    { ngx_string("basic_rule"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_yy_sec_waf_read_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("denied_url"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_yy_sec_waf_read_du_loc_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
      ngx_null_command
};


static ngx_http_module_t  ngx_http_yy_sec_waf_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_yy_sec_waf_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_yy_sec_waf_create_loc_conf,   /* create location configuration */
    ngx_http_yy_sec_waf_merge_loc_conf     /* merge location configuration */
};

ngx_module_t  ngx_http_yy_sec_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_yy_sec_waf_module_ctx,       /* module context */
    ngx_http_yy_sec_waf_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
** @description: This function is called to create the location configuration of yy sec waf.
** @para: ngx_conf_t *cf
** @return: conf or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_yy_sec_waf_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_yy_sec_waf_loc_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->max_post_args_len = NGX_CONF_UNSET_UINT;

    return conf;
}

/*
** @description: This function is called to merge the location configuration of yy sec waf.
** @para: ngx_conf_t *cf
** @para: void *parent
** @para: void *child
** @return: NGX_CONF_OK
*/

static char *
ngx_http_yy_sec_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    (void) cf;
    ngx_http_yy_sec_waf_loc_conf_t *prev = parent;
    ngx_http_yy_sec_waf_loc_conf_t *conf = child;

    if (conf->header_rules == NULL)
        conf->header_rules = prev->header_rules;
    if (conf->uri_rules == NULL)
        conf->uri_rules = prev->uri_rules;
    if (conf->args_rules == NULL)
        conf->args_rules = prev->args_rules;
    if (conf->variable_rules == NULL)
        conf->variable_rules = prev->variable_rules;
    if (conf->denied_url == NULL)
        conf->denied_url = prev->denied_url;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 1);

    ngx_conf_merge_bitmask_value(conf->http_method, prev->http_method, 0);

    ngx_conf_merge_uint_value(conf->max_post_args_len, prev->max_post_args_len, 2048);

    return NGX_CONF_OK;
}

/*
** @description: This function is called to init yy sec waf in process of postconfiguration.
** @para: ngx_conf_t *cf
** @return: NGX_CONF_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_yy_sec_waf_handler;

    return NGX_OK;
}

/*
** @description: This is the function called by nginx : 
** - Set up the context for the request
** - Check if the job is done and we're called again
** - if it's a POST/PUT request, setup hook for body data
** - call ngx_http_yy_sec_waf_data_parse
** - check if the request should be denied
** @para: ngx_http_request_t *r
** @return: this value should vary due to different situations.
*/

static ngx_int_t
ngx_http_yy_sec_waf_handler(ngx_http_request_t *r)
{
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_handler Enter");

    ngx_int_t                       rc;
    ngx_http_request_ctx_t         *ctx;
    ngx_http_yy_sec_waf_loc_conf_t *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_get_module_loc_conf failed.");
        return NGX_ERROR;
    }

    if (ctx != NULL) {
        if (ctx->process_done) {
            return NGX_DECLINED;
        }

        if (ctx->waiting_more_body) {
            return NGX_DONE;
        }
    }

    if (!cf->enabled) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] yy sec waf isn't enabled.");
        return NGX_DECLINED;
    }

    if (cf->http_method)
        if (!(r->method & cf->http_method)) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] http method isn't supported.");
            return NGX_HTTP_NOT_ALLOWED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_request_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_yy_sec_waf_module);

    /* This section is prepared for further considerations, such as checking the body of this request.*/
    if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) && !ctx->read_body_done) {
        rc = ngx_http_read_client_request_body(r, ngx_http_yy_sec_waf_request_body_handler);

        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        } else if (rc >= NGX_HTTP_SPECIAL_RESPONSE || rc == NGX_ERROR) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[ysec_waf] ngx_http_read_client_request_body failed.");
            return rc;
        }
    } else {
		ctx->read_body_done = 1;
	}

    if (ctx && ctx->read_body_done && !ctx->process_done) {
        rc = ngx_http_yy_sec_waf_process_request(r, cf, ctx);

        cf->request_processed++;

        if (rc != NGX_OK) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[ysec_waf] ngx_http_yy_sec_waf_process_request failed.");
            return rc;
        }

        ctx->process_done = 1;

        if (ctx->matched) {
            cf->request_matched++;
            
            if (!ctx->allow && ctx->block)
                cf->request_blocked++;
            
            if (ctx->log && ctx->matched_string) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[ysec_waf] rule matched, id=%d , total processed=%d, total matched=%d, total blocked=%d, matched string=%V",
                    ctx->rule_id, cf->request_processed, cf->request_matched, cf->request_blocked, ctx->matched_string);
            }

            if (ctx->allow)
                return NGX_DECLINED;

            return ngx_http_yy_sec_waf_output_forbidden_page(r, ctx);
        }

        return NGX_DECLINED;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_handler Exit");

    return NGX_DECLINED;
}

/*
** @description: This function is called to redirect request url to the denied url of yy sec waf.
** @para: ngx_http_request_t *r
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_HTTP_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_output_forbidden_page(ngx_http_request_t *r,
    ngx_http_request_ctx_t *ctx)
{
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_str_t  empty = ngx_string("");
    ngx_str_t *tmp_uri;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);

    if (cf->denied_url) {
        tmp_uri = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        if (!tmp_uri)
            return NGX_ERROR;
        
        tmp_uri->len = r->uri.len + (2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
            NGX_ESCAPE_ARGS));
        tmp_uri->data = ngx_pcalloc(r->pool, tmp_uri->len+1);
    
        ngx_escape_uri(tmp_uri->data, r->uri.data, r->uri.len, NGX_ESCAPE_ARGS);
        
        ngx_table_elt_t *h;
        
        if (r->headers_in.headers.last)	{
            h = ngx_list_push(&(r->headers_in.headers));
            h->key.len = ngx_strlen("orig_url");
            h->key.data = ngx_pcalloc(r->pool, ngx_strlen("orig_url")+1);
            ngx_memcpy(h->key.data, "orig_url", ngx_strlen("orig_url"));
            h->lowcase_key = ngx_pcalloc(r->pool, ngx_strlen("orig_url") + 1);
            ngx_memcpy(h->lowcase_key, "orig_url", ngx_strlen("orig_url"));
            h->value.len = tmp_uri->len;
            h->value.data = ngx_pcalloc(r->pool, tmp_uri->len+1);
            ngx_memcpy(h->value.data, tmp_uri->data, tmp_uri->len);
            
            h = ngx_list_push(&(r->headers_in.headers));
            h->key.len = ngx_strlen("orig_args");
            h->key.data = ngx_pcalloc(r->pool, ngx_strlen("orig_args")+1);
            ngx_memcpy(h->key.data, "orig_args", ngx_strlen("orig_args"));
            h->lowcase_key = ngx_pcalloc(r->pool, ngx_strlen("orig_args") + 1);
            ngx_memcpy(h->lowcase_key, "orig_args", ngx_strlen("orig_args"));
            h->value.len = r->args.len;
            h->value.data = ngx_pcalloc(r->pool, r->args.len+1);
            ngx_memcpy(h->value.data, r->args.data, r->args.len);
            
            h = ngx_list_push(&(r->headers_in.headers));
            h->key.len = ngx_strlen("yy_sec_waf");
            h->key.data = ngx_pcalloc(r->pool, ngx_strlen("yy_sec_waf")+1);
            ngx_memcpy(h->key.data, "yy_sec_waf", ngx_strlen("yy_sec_waf"));
            h->lowcase_key = ngx_pcalloc(r->pool, ngx_strlen("yy_sec_waf") + 1);
            ngx_memcpy(h->lowcase_key, "yy_sec_waf", ngx_strlen("yy_sec_waf"));
            h->value.len = empty.len;
            h->value.data = empty.data;
        }

        ngx_http_internal_redirect(r, cf->denied_url, &empty);

        return NGX_HTTP_OK;
    } else {
        return NGX_HTTP_PRECONDITION_FAILED;
    }
}

/*
** @description: This function is called when the body is read.
** - Will set-up flags to tell that parsing can be done,
** - and then run the core phases again
** @para: ngx_http_request_t *r
** @return: void
*/

static void 
ngx_http_yy_sec_waf_request_body_handler(ngx_http_request_t *r)
{
    ngx_http_request_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (ctx != NULL) {
        ctx->read_body_done = 1;
        r->main->count--;
    
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[ysec_waf] req body post read, c:%ud", r->main->count);
    
        if (ctx->waiting_more_body) {
            ctx->waiting_more_body = 0;
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_core_run_phases Entry");
            ngx_http_core_run_phases(r);
        }
    }
}


