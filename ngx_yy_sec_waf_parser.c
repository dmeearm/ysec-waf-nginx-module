/*
** @file: ngx_yy_sec_waf_parser.c
** @description: This is the rule parser for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.15
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

extern ngx_http_yy_sec_waf_rule_t *mod_rules[];
extern ngx_uint_t mod_rules_num;

typedef struct {
    const char *type;
    void *(*parse)(ngx_conf_t *, ngx_str_t *, ngx_http_yy_sec_waf_rule_t *);
} ngx_http_yy_sec_waf_parser_t;

static void *ngx_http_yy_sec_waf_parse_mod(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_gids(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_rule_id(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_msg(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_pos(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_level(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_phase(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);


static ngx_http_yy_sec_waf_parser_t rule_parser[] = {
    { MOD, ngx_http_yy_sec_waf_parse_mod},
    { GIDS, ngx_http_yy_sec_waf_parse_gids},
    { ID, ngx_http_yy_sec_waf_parse_rule_id},
    { MSG, ngx_http_yy_sec_waf_parse_msg},
    { POS, ngx_http_yy_sec_waf_parse_pos},
    { LEVEL, ngx_http_yy_sec_waf_parse_level},
    { PHASE, ngx_http_yy_sec_waf_parse_phase},
    { NULL, NULL}
};

/*
** @description: This function is called to parse mod of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_mod(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t mod;

    if (!rule)
        return NGX_CONF_ERROR;

    mod.data = tmp->data + ngx_strlen(MOD);
    mod.len = tmp->len - ngx_strlen(MOD);

    if (!ngx_strncasecmp(mod.data, (u_char*)"off", mod.len)) {
        rule->mod = 0;
    } else if (!ngx_strncasecmp(mod.data, (u_char*)"on", mod.len)) {
        rule->mod = 1;
    } else {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse gids of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_gids(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *gids;

    if (!rule)
        return NGX_CONF_ERROR;

    gids = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!gids)
        return NGX_CONF_ERROR;

    gids->data = tmp->data + ngx_strlen(GIDS);
    gids->len = tmp->len - ngx_strlen(GIDS);

    rule->gids = gids;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse rule id of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_rule_id(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *rule_id;

    if (!rule)
        return NGX_CONF_ERROR;

    rule_id = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!rule_id)
        return NGX_CONF_ERROR;

    rule_id->data = tmp->data + ngx_strlen(ID);
    rule_id->len = tmp->len - ngx_strlen(ID);

    rule->rule_id = ngx_atoi(rule_id->data, rule_id->len);

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse msg of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_msg(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *msg;

    if (!rule)
        return NGX_CONF_ERROR;

    msg = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!msg)
        return NGX_CONF_ERROR;

    msg->data = tmp->data + ngx_strlen(MSG);
    msg->len = tmp->len - ngx_strlen(MSG);

    rule->msg = msg;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse pos of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_pos(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    char      *tmp_ptr;
    ngx_str_t  value;

    tmp_ptr = (char*)tmp->data + ngx_strlen(POS);

    while (*tmp_ptr) {
        if (tmp_ptr[0] == '|')
            tmp_ptr++;
        /* match global zones */
        if (!ngx_strncmp(tmp_ptr, BODY, ngx_strlen(BODY))) {
            rule->body = 1;
            tmp_ptr += ngx_strlen(BODY);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, HEADER, ngx_strlen(HEADER))) {
            rule->header = 1;
            tmp_ptr += ngx_strlen(HEADER);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, URI, ngx_strlen(URI))) {
            rule->uri = 1;
            tmp_ptr += ngx_strlen(URI);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, ARGS, ngx_strlen(ARGS))) {
            rule->args = 1;

            int i;
            for (i = 0; var_metadata[i].generate; i++) {
                if (!ngx_strncasecmp((u_char*)tmp_ptr,
                    (u_char*)var_metadata[i].name, ngx_strlen(var_metadata[i].name))) {
                    rule->var_metadata = &var_metadata[i];
                    break;
                }
            }

            tmp_ptr += ngx_strlen(ARGS);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, COOKIE, ngx_strlen(COOKIE))) {
            rule->cookie = 1;
            tmp_ptr += ngx_strlen(COOKIE);
            continue;
        } else if (tmp_ptr[0] == '$') {
            rule->variable = 1;
            value.len = tmp->len - ngx_strlen(POS) - 1;
            value.data = (u_char*)tmp_ptr+1;
            rule->var_index = ngx_http_get_variable_index(cf, &value);

            int i;
            for (i = 0; var_metadata[i].generate; i++) {
                if (!ngx_strncasecmp((u_char*)tmp_ptr,
                    (u_char*)var_metadata[i].name, ngx_strlen(var_metadata[i].name))) {
                    rule->var_metadata = &var_metadata[i];
                    break;
                }
            }

            break;
        } else {
            return (NGX_CONF_ERROR);
        }
    }

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse level of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_level(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    char *tmp_ptr;
    
    tmp_ptr = (char*)tmp->data + ngx_strlen(LEVEL);

    while (*tmp_ptr) {
        if (tmp_ptr[0] == '|')
            tmp_ptr++;
        /* match global zones */
        if (!ngx_strncmp(tmp_ptr, BLOCK, ngx_strlen(BLOCK))) {
            rule->block = 1;
            tmp_ptr += ngx_strlen(BLOCK);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, LOG, ngx_strlen(LOG))) {
            rule->log = 1;
            tmp_ptr += ngx_strlen(LOG);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, ALLOW, ngx_strlen(ALLOW))) {
            rule->allow = 1;
            tmp_ptr += ngx_strlen(ALLOW);
            continue;
        } else {
            return (NGX_CONF_ERROR);
        }
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_yy_sec_waf_parse_phase(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *phase;

    if (!rule)
        return NGX_CONF_ERROR;

    phase = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!phase)
        return NGX_CONF_ERROR;

    phase->data = tmp->data + ngx_strlen(PHASE);
    phase->len = tmp->len - ngx_strlen(PHASE);

    rule->phase |= ngx_atoi(phase->data, phase->len);

    return NGX_CONF_OK;
}

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
        for (i = 0; rule_parser[i].parse; i++) {
            if (!ngx_strncasecmp((u_char*)value[n].data,
                (u_char*)rule_parser[i].type, ngx_strlen(rule_parser[i].type))) {
                if (rule_parser[i].parse(cf, &value[n], &rule) != NGX_CONF_OK) {
                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed parsing '%s'", value[n].data);
                    return NGX_CONF_ERROR;
                }
    
                break;
            }
        }

        for (i = 1; op_metadata[i].parse; i++) {
            if (!ngx_strncasecmp((u_char*)value[n].data,
                (u_char*)op_metadata[i].name, ngx_strlen(op_metadata[i].name))) {
                if (op_metadata[i].parse(cf, &value[n], &rule) != NGX_CONF_OK) {
                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed parsing '%s'", value[n].data);
                    return NGX_CONF_ERROR;
                }

                rule.op_metadata = &op_metadata[i];
                break;
            }
        }
    }

    for (i = 0; i < mod_rules_num; i++) {
        if (rule.rule_id == mod_rules[i]->rule_id) {
            ngx_memcpy(mod_rules[i], &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
            break;
        }
    }


    if (rule.mod) {
        rule.op_metadata = &op_metadata[0];
        return NGX_CONF_OK;
    } else {
        if (rule.regex == NULL && rule.str == NULL && rule.eq == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] No operation for rule(id=%d)", rule.rule_id);
            return NGX_CONF_ERROR;
        }
    }        

    if (rule.phase & REQUEST_HEADER_PHASE) {
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

    if (rule.phase & REQUEST_BODY_PHASE) {
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
    ngx_uint_t i;
	ngx_int_t rc;
    ngx_str_t var;

    if (ctx->cf->request_header_rules != NULL) {
        header_rule = cf->request_header_rules->elts;
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] 1");

        ctx->phase = REQUEST_HEADER_PHASE;
        for (i=0; i < cf->request_header_rules->nelts; i++) {

            if (header_rule[i].var_metadata == NULL || header_rule[i].var_metadata->generate == NULL)
                continue;
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] 2");

            header_rule[i].var_metadata->generate(&header_rule[i], ctx, &var);
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] 3");

            //ngx_yy_sec_waf_unescape(&var);

            rc = header_rule[i].op_metadata->execute(r, &var, &header_rule[i]);
			
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] 4");
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
                ctx->matched_string = &var;
                return NGX_OK;
            }
        }
    }

    if (cf->request_body_rules && r->request_body 
        && (r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT)) {
        body_rule = cf->request_header_rules->elts;

        ctx->phase = REQUEST_BODY_PHASE;
        for (i=0; i < cf->request_header_rules->nelts; i++) {
            body_rule[i].var_metadata->generate(&body_rule[i], ctx, &var);

            rc = body_rule[i].op_metadata->execute(r, &var, &body_rule[i]);
            
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
                ctx->matched_string = &var;
                return NGX_OK;
            }
        }
    }

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] yy_sec_waf_re_process_normal_rules Exit");

    return NGX_OK;
}

