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
static void ngx_http_yy_sec_waf_request_body_handler(ngx_http_request_t *r);
static void * ngx_http_yy_sec_waf_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_yy_sec_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

typedef struct {
    ngx_str_t    basic_rule;
} ngx_http_yy_sec_waf_loc_conf_t;

typedef struct {
    ngx_flag_t    ready:1;
    ngx_flag_t    matched:1;
    ngx_flag_t    wait_for_body:1;
} ngx_http_request_ctx_t;

static ngx_command_t  ngx_http_yy_sec_waf_commands[] = {
    { ngx_string("basic_rule"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_yy_sec_waf_loc_conf_t, basic_rule),
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

    ngx_conf_merge_str_value(conf->basic_rule, prev->basic_rule, "");

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
** @description: This function is called to parse the args of the request.
** @para: ngx_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_http_request_t *r
** @return: NGX_CONF_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_args_parse(ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx, ngx_http_request_t *r)
{
    ngx_str_t args;

    args.len = (ngx_uint_t)(r->args.len);
    args.data = ngx_pcalloc(r->pool, args.len + 1);

    if (args.data == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpymem(args.data, r->args.data, args.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] args=%V", &args);

    /* Decode the args of the request to compare with basic rules.
      TODO: take some more complex situations into account. */
    ngx_yy_sec_waf_unescape(&args);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] unescaped args=%V", &args);

    /* Simply match basic rule with the args.
      TODO: regx->low sec, string->medium sec, char->high sec. */
    if (ngx_strnstr(args.data, (char*) cf->basic_rule.data, args.len)) {
        ctx->matched = 1;
    }

    return NGX_OK;
}

/*
** @description: This function is called to parse the data of the request.
** @para: ngx_http_request_ctx_t *ctx
** @para: ngx_http_request_t *r
** @return: NGX_OK or NGX_ERROR if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_data_parse(ngx_http_request_ctx_t *ctx, ngx_http_request_t *r)
{
    ngx_http_yy_sec_waf_loc_conf_t *cf;
	
	cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);

    if (cf == NULL) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] unable to parse data.");
        return NGX_ERROR;
    }

    /* Simply parse args.
      TODO: parse header, uri and body later.*/
    return ngx_http_yy_sec_waf_args_parse(cf, ctx, r);
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
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_http_request_ctx_t         *ctx;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_yy_sec_waf_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[waf] basic_rule=%V", &cf->basic_rule);

    ctx = ngx_http_get_module_ctx(r, ngx_http_yy_sec_waf_module);
    if (ctx != NULL) {
        if (ctx->ready) {
            return NGX_DECLINED;
        }
        return NGX_DONE;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_request_ctx_t));

    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_yy_sec_waf_module);

    /* This section is prepared for further considerations, such as checking the body of this request.*/
    if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) && !ctx->ready) {
        rc = ngx_http_read_client_request_body(r, ngx_http_yy_sec_waf_request_body_handler);

        if (rc == NGX_AGAIN) {
            ctx->wait_for_body = 1;
            return NGX_DONE;
        }
        else if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,"[waf] NGX_HTTP_SPECIAL_RESPONSE.");
            return rc;
        }
    }
	else {
		ctx->ready = 1;
	}

    if (ctx && ctx->ready) {
        rc = ngx_http_yy_sec_waf_data_parse(ctx, r);

        if (rc != NGX_OK) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return rc;
        }

    	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
    				   "[waf] this rule %s matched.", ctx->matched? "is": "isn't");
    
        if (!ctx->matched) {
    		return NGX_DECLINED;
        }

        /* Simply discard and finalize the request.
             TODO: redirect to other pages, such as 404.html. */
        ngx_http_discard_request_body(r);
        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);

        return NGX_DONE;
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

    r->count--;
    ctx->ready = 1;

    if (ctx->wait_for_body) {
        ctx->wait_for_body = 0;
        ngx_http_core_run_phases(r);
    }
}


