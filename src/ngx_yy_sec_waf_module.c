/*
** @file: ngx_yy_sec_waf_module.c
** @description: This is the core module for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.10
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

static ngx_int_t ngx_http_yy_sec_waf_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_yy_sec_waf_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_yy_sec_waf_handler(ngx_http_request_t *r);
static void ngx_http_yy_sec_waf_request_body_handler(ngx_http_request_t *r);
static void * ngx_http_yy_sec_waf_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_yy_sec_waf_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_http_request_ctx_t* ngx_http_yy_sec_waf_create_ctx(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf);

extern char * ngx_http_yy_sec_waf_re_read_du_loc_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
extern char * ngx_http_yy_sec_waf_re_read_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
extern ngx_int_t ngx_http_yy_sec_waf_process_request(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx);

extern ngx_int_t ngx_http_yy_sec_waf_re_create(ngx_conf_t *cf);
extern ngx_int_t yy_sec_waf_re_process_normal_rules(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx, ngx_uint_t phase);
static ngx_int_t ngx_http_yy_sec_waf_module_init(ngx_cycle_t *cycle);

static ngx_atomic_t   request_matched0;
static ngx_atomic_t   request_blocked0;
static ngx_atomic_t   request_allowed0;
static ngx_atomic_t   request_logged0;

ngx_atomic_t   *request_matched = &request_matched0;
ngx_atomic_t   *request_blocked = &request_blocked0;
ngx_atomic_t   *request_allowed = &request_allowed0;
ngx_atomic_t   *request_logged  = &request_logged0;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

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

    { ngx_string("conn_processor"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_yy_sec_waf_loc_conf_t, conn_processor),
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
      ngx_http_yy_sec_waf_re_read_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("denied_url"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_yy_sec_waf_re_read_du_loc_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_yy_sec_waf_module_ctx = {
    ngx_http_yy_sec_waf_preconfiguration,  /* preconfiguration */
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
    ngx_http_yy_sec_waf_module_init,       /* init module */
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
    conf->conn_processor = NGX_CONF_UNSET;

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

    if (conf->request_header_rules == NULL)
        conf->request_header_rules = prev->request_header_rules;
    if (conf->request_body_rules == NULL)
        conf->request_body_rules = prev->request_body_rules;
    if (conf->response_header_rules == NULL)
        conf->response_header_rules = prev->response_header_rules;
    if (conf->response_body_rules == NULL)
        conf->response_body_rules = prev->response_body_rules;
    if (conf->denied_url == NULL)
        conf->denied_url = prev->denied_url;
    if (conf->shm_zone == NULL)
        conf->shm_zone = prev->shm_zone;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 1);

    ngx_conf_merge_value(conf->conn_processor, prev->conn_processor, 0);

    ngx_conf_merge_bitmask_value(conf->http_method, prev->http_method, 0);

    ngx_conf_merge_uint_value(conf->max_post_args_len, prev->max_post_args_len, 2048);

    return NGX_CONF_OK;
}

/*
** @description: This function is called before configuration of yy sec waf.
** @para: ngx_conf_t *cf
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_yy_sec_waf_re_create(cf);
}

/*
** @description: This function is called to filter header.
** @para: ngx_conf_t *cf
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_request_ctx_t         *ctx;
    ngx_http_yy_sec_waf_loc_conf_t *cf;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_header_filter Entry");

    cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ysec_waf] ngx_http_get_module_loc_conf failed.");
        return NGX_ERROR;
    }

    if (!cf->enabled) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] yy sec waf isn't enabled.");
        return NGX_DECLINED;
    }

    if (!ctx->process_done) {
        rc = yy_sec_waf_re_process_normal_rules(r, cf, ctx, RESPONSE_HEADER_PHASE);
        if (rc != NGX_DECLINED) {
            return ngx_http_filter_finalize_request(r, &ngx_http_yy_sec_waf_module, rc);
        }
    }

    return ngx_http_next_header_filter(r);
}

/*
** @description: This function is called to filter body.
** @para: ngx_conf_t *cf
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                       rc;
    ngx_http_request_ctx_t         *ctx;
    ngx_http_yy_sec_waf_loc_conf_t *cf;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_body_filter Entry");

    cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
        return NGX_ERROR;
    }

    if (!cf->enabled) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] yy sec waf isn't enabled.");
        return NGX_DECLINED;
    }

    if (!ctx->process_done) {
        rc = yy_sec_waf_re_process_normal_rules(r, cf, ctx, RESPONSE_BODY_PHASE);
        if (rc != NGX_DECLINED) {
            return ngx_http_filter_finalize_request(r, &ngx_http_yy_sec_waf_module, rc);
        }
    }

    return ngx_http_next_body_filter(r, in);
}

/*
** @description: This function is called to init yy sec waf in process of postconfiguration.
** @para: ngx_conf_t *cf
** @return: NGX_CONF_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt            *h;
    ngx_http_core_main_conf_t      *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_yy_sec_waf_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_yy_sec_waf_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_yy_sec_waf_body_filter;

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
    ngx_int_t                       rc;
    ngx_http_request_ctx_t         *ctx;
    ngx_http_yy_sec_waf_loc_conf_t *cf;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_handler Entry");

    cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
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

    ctx = ngx_http_yy_sec_waf_create_ctx(r, cf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_yy_sec_waf_module);

    if (cf->conn_processor) {
        rc = ngx_http_yy_sec_waf_process_conn(ctx);

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_process_conn failed");
            return rc;
        }
    }

    if (!ctx->process_done) {
        rc = yy_sec_waf_re_process_normal_rules(r, cf, ctx, REQUEST_HEADER_PHASE);
        if (ctx->matched || rc == NGX_ERROR) {
            return rc;
        }
    }

    /* This section is prepared for further considerations, such as checking the body of this request.*/
    if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) && !ctx->read_body_done) {
        rc = ngx_http_read_client_request_body(r, ngx_http_yy_sec_waf_request_body_handler);

        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        } else if (rc >= NGX_HTTP_SPECIAL_RESPONSE || rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"[ysec_waf] ngx_http_read_client_request_body failed");
            return rc;
        }
    } else {
        ctx->read_body_done = 1;
    }

    if (ctx && ctx->read_body_done && !ctx->process_done) {
        rc = NGX_DECLINED;

		if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT)
			&& r->request_body) {
			rc = ngx_http_yy_sec_waf_process_body(r, cf, ctx);
            if (rc == NGX_ERROR) {
                return rc;
            }

			rc = yy_sec_waf_re_process_normal_rules(r, cf, ctx, REQUEST_BODY_PHASE);
			if (ctx->matched || rc == NGX_ERROR) {
				return rc;
			}
		}

        return rc;
    }

    return NGX_DECLINED;
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

/*
** @description: This function is called to create ctx for this request.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_loc_conf_t *cf
** @return: static ngx_http_request_ctx_t*
*/

static ngx_http_request_ctx_t*
ngx_http_yy_sec_waf_create_ctx(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf)
{
    ngx_http_request_ctx_t *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_request_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->args = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (ctx->args == NULL) {
        return NULL;
    }

    ctx->args->len = r->args.len;
    ctx->args->data = ngx_pcalloc(r->pool, r->args.len+1);
    if (ctx->args->data == NULL) {
        return NULL;
    }

    ngx_memcpy(ctx->args->data, r->args.data, ctx->args->len);

    ngx_yy_sec_waf_unescape(ctx->args);

    if (r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) {
        ctx->post_args = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        if (ctx->post_args == NULL) {
            return NULL;
        }

        ctx->multipart_filename = ngx_array_create(r->pool, 1, sizeof(ngx_array_t));
        if (ctx->multipart_filename == NULL) {
            return NULL;
        }
        ctx->multipart_name = ngx_array_create(r->pool, 1, sizeof(ngx_array_t));
        if (ctx->multipart_name == NULL) {
            return NULL;
        }
        ctx->content_type = ngx_array_create(r->pool, 1, sizeof(ngx_array_t));
        if (ctx->content_type == NULL) {
            return NULL;
        }
    }

    ctx->process_body_error = 0;

    ctx->r = r;
    ctx->cf = cf;
    ctx->pool = r->pool;

    //yy_sec_waf_re_cache_init_rbtree(&ctx->cache_rbtree, &ctx->cache_sentinel);

    return ctx;
}

/*
** @description: This function is called to init yy_sec_waf_module.
** @para: ngx_cycle_t *cycle
** @return: static ngx_int_t
*/

static ngx_int_t
ngx_http_yy_sec_waf_module_init(ngx_cycle_t *cycle)
{
    u_char              *shared;
    size_t               size, cl;
    ngx_shm_t            shm;
    ngx_core_conf_t     *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->master == 0) {
        return NGX_OK;
    }

    /* cl should be equal to or greater than cache line size */

    cl = 128;

    size = cl            /* request_matched */
           + cl          /* request_blocked */
           + cl          /* request_allowed */
           + cl;         /* request_logged */

    shm.size = size;
    shm.name.len = sizeof("yy_sec_waf_shared_zone");
    shm.name.data = (u_char *) "yy_sec_waf_shared_zone";
    shm.log = cycle->log;

    if (ngx_shm_alloc(&shm) != NGX_OK) {
        return NGX_ERROR;
    }

    shared = shm.addr;

    request_matched = (ngx_atomic_t *) (shared + 0 * cl);
    request_blocked = (ngx_atomic_t *) (shared + 1 * cl);
    request_allowed = (ngx_atomic_t *) (shared + 2 * cl);
    request_logged  = (ngx_atomic_t *) (shared + 3 * cl);

    return NGX_OK;
}

