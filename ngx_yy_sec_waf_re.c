/*
** @file: ngx_yy_sec_waf_re.c
** @description: This is the rule rule engine for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.15
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

static yy_sec_waf_re_t *rule_engine;

extern ngx_int_t yy_sec_waf_init_variables_in_hash(ngx_conf_t *cf, ngx_hash_t *hash);

extern ngx_int_t yy_sec_waf_init_operators_in_hash(ngx_conf_t *cf, ngx_hash_t *hash);

extern ngx_int_t yy_sec_waf_init_actions_in_hash(ngx_conf_t *cf, ngx_hash_t *hash);

extern ngx_int_t yy_sec_waf_init_tfns_in_hash(ngx_conf_t *cf, ngx_hash_t *hash);

extern ngx_int_t ngx_http_yy_sec_waf_process_body(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx);

/*
** @description: This function is called to create rule engine for yy sec waf.
** @para: ngx_conf_t *cf
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_re_create(ngx_conf_t *cf)
{
    rule_engine = ngx_pcalloc(cf->pool, sizeof(yy_sec_waf_re_t));
    if (rule_engine == NULL) {
        return NGX_ERROR;
    }

    if (yy_sec_waf_init_variables_in_hash(cf, &rule_engine->variables_in_hash) == NGX_ERROR)
        return NGX_ERROR;

    if (yy_sec_waf_init_operators_in_hash(cf, &rule_engine->operators_in_hash) == NGX_ERROR)
        return NGX_ERROR;

    if (yy_sec_waf_init_actions_in_hash(cf, &rule_engine->actions_in_hash) == NGX_ERROR)
        return NGX_ERROR;

    if (yy_sec_waf_init_tfns_in_hash(cf, &rule_engine->tfns_in_hash) == NGX_ERROR)
        return NGX_ERROR;

    return NGX_OK;
}

/*
** @description: This function is called to resolve variables in hash.
** @para: ngx_str_t *variable
** @return: static re_var_metadata *
*/

re_var_metadata *
yy_sec_waf_re_resolve_variable_in_hash(ngx_str_t *variable)
{
    ngx_uint_t key;
    re_var_metadata *metadata;

    if (variable == NULL) {
        return NULL;
    }

    key = ngx_hash_key_lc(variable->data, variable->len);
    if (variable->data[0] != '$') {
        ngx_strlow(variable->data, variable->data, variable->len);
    }

    metadata = (re_var_metadata *)ngx_hash_find(
        &rule_engine->variables_in_hash, key, variable->data, variable->len);

    return metadata;
}

/*
** @description: This function is called to resolve tfns in hash.
** @para: ngx_str_t *action
** @return: static re_action_metadata *
*/

re_tfns_metadata *
yy_sec_waf_re_resolve_tfn_in_hash(ngx_str_t *tfn)
{
    ngx_uint_t key;
    re_tfns_metadata *metadata;

    if (tfn == NULL) {
        return NULL;
    }

    key = ngx_hash_key_lc(tfn->data, tfn->len);
    ngx_strlow(tfn->data, tfn->data, tfn->len);

    metadata = (re_tfns_metadata *)ngx_hash_find(
        &rule_engine->tfns_in_hash, key, tfn->data, tfn->len);

    return metadata;
}

/*
** @description: This function is called to resolve operators in hash.
** @para: ngx_str_t *operator
** @return: static re_op_metadata *
*/

re_op_metadata *
yy_sec_waf_re_resolve_operator_in_hash(ngx_str_t *operator)
{
    ngx_uint_t key;
    re_op_metadata *metadata;

    if (operator == NULL) {
        return NULL;
    }

    key = ngx_hash_key_lc(operator->data, operator->len);
    ngx_strlow(operator->data, operator->data, operator->len);

    metadata = (re_op_metadata *)ngx_hash_find(
        &rule_engine->operators_in_hash, key, operator->data, operator->len);

    return metadata;
}

/*
** @description: This function is called to resolve actions in hash.
** @para: ngx_str_t *action
** @return: static re_action_metadata *
*/

re_action_metadata *
yy_sec_waf_re_resolve_action_in_hash(ngx_str_t *action)
{
    ngx_uint_t key;
    re_action_metadata *metadata;

    if (action == NULL) {
        return NULL;
    }

    key = ngx_hash_key_lc(action->data, action->len);
    ngx_strlow(action->data, action->data, action->len);

    metadata = (re_action_metadata *)ngx_hash_find(
        &rule_engine->actions_in_hash, key, action->data, action->len);

    return metadata;
}

/*
** @description: This function is called to execute operator.
** @para: ngx_http_request_t *r
** @para: ngx_str_t *str
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @para: ngx_http_request_ctx_t *ctx
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

static ngx_int_t
yy_sec_waf_re_op_execute(ngx_http_request_t *r,
    ngx_str_t *str, ngx_http_yy_sec_waf_rule_t *rule, ngx_http_request_ctx_t *ctx)
{
    ngx_int_t rc;

    rc = rule->op_metadata->execute(r, str, rule);

    if ((rc == RULE_MATCH && !rule->op_negative)
        || (rc == RULE_NO_MATCH && rule->op_negative)) {
        ctx->matched = 1;
        ctx->rule_id = rule->rule_id;
        ctx->allow = rule->allow;
        ctx->block = rule->block;
        ctx->log = rule->log;
        ctx->gids = rule->gids;
        ctx->msg = rule->msg;
        ctx->matched_string = str;
        return RULE_MATCH;
    }

    return rc;
}

/*
** @description: This function is called to process normal rules for yy sec waf.
** @para: ngx_http_request_t *r
** @para: ngx_http_yy_sec_waf_loc_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

static ngx_int_t
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

            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf]1 %d", header_rule[i].rule_id);

            var = var_array->elts;
            if (var == NULL)
                continue;

            for (j = 0; j < var_array->nelts; j++) {

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf]2 %d %V", header_rule[i].rule_id, &var[j]);

                if (header_rule[i].tfn_metadata != NULL) {
                    rc = header_rule[i].tfn_metadata->execute(&var[j]);
                    if (rc == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] failed to execute header_rule tfns");
                        return NGX_ERROR;
                    }
                }

                rc = yy_sec_waf_re_op_execute(r, &var[j], &header_rule[i], ctx);

                if (rc == NGX_ERROR) {
                    return rc;
                } else if (rc == RULE_MATCH) {
                    return NGX_OK;
                } else if (rc == RULE_NO_MATCH) {
                    continue;
                }
            }

            ngx_array_destroy(var_array);
        }
    }

    if (cf->request_body_rules && r->request_body 
        && (r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT)) {
        body_rule = cf->request_body_rules->elts;


        ctx->phase = REQUEST_BODY_PHASE;
        for (i=0; i < cf->request_body_rules->nelts; i++) {
            var_array = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));

            body_rule[i].var_metadata->generate(&body_rule[i], ctx, var_array);

            var = var_array->elts;
            if (var == NULL || var->data == NULL)
                continue;

            for (j = 0; j < var_array->nelts; j++) {

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf]3 %d %V %p", body_rule[i].rule_id, &var[j], var[j].data);

                if (body_rule[i].tfn_metadata != NULL) {
                    rc = body_rule[i].tfn_metadata->execute(&var[j]);
                    if (rc == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] failed to execute body_rule tfns");
                        return NGX_ERROR;
                    }
                }

                rc = yy_sec_waf_re_op_execute(r, &var[j], &body_rule[i], ctx);

                if (rc == NGX_ERROR) {
                    return rc;
                } else if (rc == RULE_MATCH) {
                    return NGX_OK;
                } else if (rc == RULE_NO_MATCH) {
                    continue;
                }
            }

            ngx_array_destroy(var_array);
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] yy_sec_waf_re_process_normal_rules Exit");

    return NGX_OK;
}

/*
** @description: This function is called to process the request.
** @para: ngx_http_request_t *r
** @para: ngx_conf_t *cf
** @para: ngx_http_request_ctx_t *ctx
** @return: NGX_OK or NGX_ERROR if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_process_request(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_process_request Entry");

    /* TODO: process body, need test case for this situation. */
    if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT)
        && r->request_body) {
        ngx_http_yy_sec_waf_process_body(r, cf, ctx);
    }

    yy_sec_waf_re_process_normal_rules(r, cf, ctx);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ysec_waf] ngx_http_yy_sec_waf_process_request Exit");

    return NGX_OK;
}

/*
** @description: This function is called to read configuration of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_command_t *cmd
** @para: void *conf
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

char *
ngx_http_yy_sec_waf_re_read_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_yy_sec_waf_loc_conf_t  *p = conf;

    ngx_uint_t        n;
    u_char           *pos;
    ngx_str_t        *value, variable, operator, action;
    ngx_http_yy_sec_waf_rule_t rule, *rule_p;

    value = cf->args->elts;
    ngx_memset(&rule, 0, sizeof(ngx_http_yy_sec_waf_rule_t));

    /* variable */
    if (value[1].data[0] == '$') {
        ngx_memcpy(variable.data, &value[1].data[1], value[1].len);
        variable.len = value[1].len-1;
        rule.var_index = ngx_http_get_variable_index(cf, &variable);
        ngx_str_set(&variable, "$");
    } else {
        ngx_memcpy(&variable, &value[1], sizeof(ngx_str_t));
    }

    rule.var_metadata = yy_sec_waf_re_resolve_variable_in_hash(&variable); 

    if (rule.var_metadata == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed to resolve variable");
        return NGX_CONF_ERROR;
    }

    /* operator */
    ngx_memcpy(&operator, &value[2], sizeof(ngx_str_t));

    if (operator.data[0] == '!') {
        rule.op_negative = 1;
        operator.data++;
    }

    pos = ngx_strlchr(operator.data, operator.data+operator.len, ':');
    operator.len = pos-operator.data;

    rule.op_metadata = yy_sec_waf_re_resolve_operator_in_hash(&operator);

    if (rule.op_metadata == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed to resolve operator");
        return NGX_CONF_ERROR;
    }

    if (rule.op_metadata->parse(cf, &value[2], &rule) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed parsing '%V'", &operator);
        return NGX_CONF_ERROR;
    }

    /* action */
    for (n = 3; n < cf->args->nelts; n++) {
        ngx_memcpy(&action, &value[n], sizeof(ngx_str_t));
        u_char *pos = ngx_strlchr(action.data, action.data+action.len, ':');
        action.len = pos-action.data;

        rule.action_metadata = yy_sec_waf_re_resolve_action_in_hash(&action);

        if (rule.action_metadata == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed to resolve action");
            return NGX_CONF_ERROR;
        }

        if (rule.action_metadata->parse(cf, &value[n], &rule) != NGX_CONF_OK) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed parsing '%V'", &action);
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
ngx_http_yy_sec_waf_re_read_du_loc_conf(ngx_conf_t *cf,
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

