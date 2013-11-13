/*
** @file: ngx_yy_sec_waf_re.c
** @description: This is the rule rule engine for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.15
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: This function is called to read configuration of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_command_t *cmd
** @para: void *conf
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

char *
ngx_http_yy_sec_waf_read_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_yy_sec_waf_loc_conf_t  *p = conf;

    ngx_uint_t        i, n;
    ngx_str_t        *value;
    ngx_http_yy_sec_waf_rule_t rule, *rule_p;

    value = cf->args->elts;
    ngx_memset(&rule, 0, sizeof(ngx_http_yy_sec_waf_rule_t));

    for (n = 1; n < cf->args->nelts; n++) {
        for (i = 0; action_metadata[i].parse; i++) {
            if (!ngx_strncasecmp((u_char*)value[n].data,
                (u_char*)action_metadata[i].name.data, action_metadata[i].name.len)) {
                if (action_metadata[i].parse(cf, &value[n], &rule) != NGX_CONF_OK) {
                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed parsing '%s'", value[n].data);
                    return NGX_CONF_ERROR;
                }
    
                break;
            }
        }


        for (i = 1; op_metadata[i].name.len; i++) {
            if (!ngx_strncasecmp((u_char*)value[n].data,
                (u_char*)op_metadata[i].name.data, op_metadata[i].name.len)) {
                if (op_metadata[i].parse(cf, &value[n], &rule) != NGX_CONF_OK) {
                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed parsing '%s'", value[n].data);
                    return NGX_CONF_ERROR;
                }

                rule.op_metadata = &op_metadata[i];
                break;
            }
        }

    }

    if (rule.regex == NULL && rule.str == NULL && rule.eq == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] No operation for rule(id=%d)", rule.rule_id);
        return NGX_CONF_ERROR;
    }

    if (rule.phase == 1) {
        if (p->request_header_rules == NULL) {
            p->request_header_rules = ngx_array_create(cf->pool, 1, sizeof(ngx_http_yy_sec_waf_rule_t));
            
            if (p->request_header_rules == NULL)
                return NGX_CONF_ERROR;
        }
        
        rule_p = ngx_array_push(p->request_header_rules);
        
        if (rule_p == NULL)
            return NGX_CONF_ERROR;

        ngx_memcpy(rule_p, &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
    }

    if (rule.phase == 2) {
        if (p->request_body_rules == NULL) {
            p->request_body_rules = ngx_array_create(cf->pool, 1, sizeof(ngx_http_yy_sec_waf_rule_t));
            
            if (p->request_body_rules == NULL)
                return NGX_CONF_ERROR;
        }
        
        rule_p = ngx_array_push(p->request_body_rules);
        
        if (rule_p == NULL)
            return NGX_CONF_ERROR;
        
        ngx_memcpy(rule_p, &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
    }

    return NGX_CONF_OK;
}

/*
** @description: This function is called to read denied url of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

char *
ngx_http_yy_sec_waf_read_du_loc_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_yy_sec_waf_loc_conf_t *p = conf;
    ngx_str_t *value;

    value = cf->args->elts;
    if (value[1].len == 0)
        return NGX_CONF_ERROR;

    p->denied_url = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!p->denied_url)
        return NGX_CONF_ERROR;

    p->denied_url->data = ngx_pcalloc(cf->pool, value[1].len+1);
    if (!p->denied_url->data)
        return NGX_CONF_ERROR;

    ngx_memcpy(p->denied_url->data, value[1].data, value[1].len);
    p->denied_url->len = value[1].len;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to process normal rules for yy sec waf.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_loc_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

ngx_int_t
yy_sec_waf_re_process_normal_rules(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] yy_sec_waf_re_process_normal_rules Entry");

    ngx_http_yy_sec_waf_rule_t *header_rule, *body_rule;
    ngx_uint_t i, j;
	ngx_int_t rc;
    ngx_str_t *var;
	ngx_array_t *var_array;

    if (ctx->cf->request_header_rules != NULL) {
        header_rule = cf->request_header_rules->elts;

        ctx->phase = REQUEST_HEADER_PHASE;
        for (i=0; i < cf->request_header_rules->nelts; i++) {

            if (header_rule[i].var_metadata == NULL || header_rule[i].var_metadata->generate == NULL)
                continue;
			var_array = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));

            header_rule[i].var_metadata->generate(&header_rule[i], ctx, var_array);

            //ngx_yy_sec_waf_unescape(&var);
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] %d", header_rule[i].rule_id);

            var = var_array->elts;
            for (j = 0; j < var_array->nelts; j++) {

				ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] %d %V", header_rule[i].rule_id, &var[j]);
                rc = header_rule[i].op_metadata->execute(r, &var[j], &header_rule[i]);
    			
                if (rc == NGX_ERROR) {
                    return rc;
                } else if (rc == RULE_MATCH) {
                    ctx->matched = 1;
                } else if (rc == RULE_NO_MATCH) {
                    continue;
                }
                
                if (ctx->matched) {
                    ctx->rule_id = header_rule[i].rule_id;
                    ctx->allow = header_rule[i].allow;
                    ctx->block = header_rule[i].block;
                    ctx->log = header_rule[i].log;
                    ctx->gids = header_rule[i].gids;
                    ctx->msg = header_rule[i].msg;
                    ctx->matched_string = &var[j];
                    return NGX_OK;
                }
            }
        }
    }

    if (cf->request_body_rules && r->request_body 
        && (r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT)) {
        body_rule = cf->request_body_rules->elts;


        ctx->phase = REQUEST_BODY_PHASE;
        for (i=0; i < cf->request_body_rules->nelts; i++) {
			var_array = ngx_array_create(r->pool, 2, sizeof(ngx_str_t));

            body_rule[i].var_metadata->generate(&body_rule[i], ctx, var_array);

            var = var_array->elts;
            for (j = 0; j < var_array->nelts; j++) {

				ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] %d %V", body_rule[i].rule_id, &var[j]);

                rc = body_rule[i].op_metadata->execute(r, &var[j], &body_rule[i]);
                
                if (rc == NGX_ERROR) {
                    return rc;
                } else if (rc == RULE_MATCH) {
                    ctx->matched = 1;
                } else if (rc == RULE_NO_MATCH) {
                    continue;
                }
                
                if (ctx->matched) {
                    ctx->rule_id = body_rule[i].rule_id;
                    ctx->allow = body_rule[i].allow;
                    ctx->block = body_rule[i].block;
                    ctx->log = body_rule[i].log;
                    ctx->gids = body_rule[i].gids;
                    ctx->msg = body_rule[i].msg;
                    ctx->matched_string = &var[j];
                    return NGX_OK;
                }
            }

            ngx_array_destroy(var_array);
        }
    }

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] yy_sec_waf_re_process_normal_rules Exit");

    return NGX_OK;
}

