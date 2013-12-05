/*
** @file: ngx_yy_sec_waf_conn_processor.c
** @description: This is the connection processor for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.12.03
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

typedef struct {
    u_char              color;
    u_char              len;
    u_short             conn;
    u_char              data[1];
} yy_sec_waf_conn_node_t;


typedef struct {
    ngx_shm_zone_t     *shm_zone;
    ngx_rbtree_node_t  *node;
} yy_sec_waf_conn_cleanup_t;


typedef struct {
    ngx_rbtree_t       *rbtree;
    ngx_int_t           index;
    ngx_str_t           var;
} yy_sec_waf_conn_ctx_t;

/*
** @description: This function is called to cleanup connection.
** @para: void *data
** @return: static void.
*/

static void
yy_sec_waf_conn_cleanup(void *data)
{
    yy_sec_waf_conn_cleanup_t  *lccln = data;

    ngx_slab_pool_t         *shpool;
    ngx_rbtree_node_t       *node;
    yy_sec_waf_conn_ctx_t   *ctx;
    yy_sec_waf_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) lccln->shm_zone->shm.addr;
    node = lccln->node;
    lc = (yy_sec_waf_conn_node_t *) &node->color;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lccln->shm_zone->shm.log, 0,
                   "[ysec_waf] conn cleanup: %08XD %d", node->key, lc->conn);

    lc->conn--;

    if (lc->conn == 0) {
        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);
}

/*
** @description: This function is called to cleanup all connections.
** @para: gx_pool_t *pool
** @return: static ngx_inline void.
*/

static ngx_inline void
yy_sec_waf_conn_cleanup_all(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == yy_sec_waf_conn_cleanup) {
        yy_sec_waf_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}

/*
** @description: This function is called to insert value into rbtree.
** @para: ngx_rbtree_node_t *temp
** @para: ngx_rbtree_node_t *node
** @para: ngx_rbtree_node_t *sentinel
** @return: static void.
*/

static void
yy_sec_waf_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    yy_sec_waf_conn_node_t       *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (yy_sec_waf_conn_node_t *) &node->color;
            lcnt = (yy_sec_waf_conn_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

/*
** @description: This function is called to init shm zone.
** @para: ngx_shm_zone_t *shm_zone
** @para: void *data
** @return: static ngx_int_t.
*/

static ngx_int_t
yy_sec_waf_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    yy_sec_waf_conn_ctx_t  *octx = data;

    size_t                      len;
    ngx_slab_pool_t            *shpool;
    ngx_rbtree_node_t          *sentinel;
    yy_sec_waf_conn_ctx_t      *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->rbtree = octx->rbtree;

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;

        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    yy_sec_waf_conn_rbtree_insert_value);

    len = sizeof("[ysec_waf] in yy_sec_waf_conn_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, "[ysec_waf] in yy_sec_waf_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}

/*
** @description: This function is called to lookup conn node.
** @para: ngx_rbtree_t *rbtree
** @para: ngx_http_variable_value_t *vv
** @para: uint32_t hash
** @return: static ngx_rbtree_node_t *.
*/

static ngx_rbtree_node_t *
yy_sec_waf_conn_lookup(ngx_rbtree_t *rbtree, ngx_http_variable_value_t *vv,
    uint32_t hash)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    yy_sec_waf_conn_node_t      *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (yy_sec_waf_conn_node_t *) &node->color;

        rc = ngx_memn2cmp(vv->data, lcn->data,
                          (size_t) vv->len, (size_t) lcn->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

/*
** @description: This function is called to create shm zone.
** @para: ngx_conf_t *cf
** @return: ngx_shm_zone_t *.
*/

ngx_shm_zone_t *
ngx_http_yy_sec_waf_create_shm_zone(ngx_conf_t *cf)
{
    ssize_t                     n;
    ngx_str_t                   value, name;
    ngx_shm_zone_t             *shm_zone;
    yy_sec_waf_conn_ctx_t      *ctx;


    ctx = ngx_pcalloc(cf->pool, sizeof(yy_sec_waf_conn_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ngx_str_set(&name, "yy_sec_waf_conn");
    ngx_str_set(&value, "10m");
    ngx_str_set(&ctx->var, "binary_remote_addr");

    ctx->index = ngx_http_get_variable_index(cf, &ctx->var);
    if (ctx->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    n = ngx_parse_size(&value);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "[ysec_waf] invalid size of shm_zone \"%V\"", &value);
        return NULL;
    }

    if (n < (ssize_t) (8 * ngx_pagesize)) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "[ysec_waf] shm_zone \"%V\" is too small", &value);
		return NGX_CONF_ERROR;
	}

    shm_zone = ngx_shared_memory_add(cf, &name, n,
                                     &ngx_http_yy_sec_waf_module);
    if (shm_zone == NULL) {
        return NULL;
    }

    if (shm_zone->data) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                        "[ysec_waf] shm_zone \"%V\" is already bound to variable \"%Vs\"",
                        &name, &ctx->var);
        return NULL;
    }

    shm_zone->init = yy_sec_waf_conn_init_zone;
    shm_zone->data = ctx;

    return shm_zone;
}

/*
** @description: This function is called to process connection counter.
** @para: ngx_http_request_ctx_t *ctx
** @return: ngx_int_t.
*/

ngx_int_t
ngx_http_yy_sec_waf_process_conn(ngx_http_request_ctx_t *ctx)
{
    size_t                          len, n;
    uint32_t                        hash;
    ngx_slab_pool_t                *shpool;
    ngx_rbtree_node_t              *node;
    ngx_pool_cleanup_t             *cln;
    ngx_http_variable_value_t      *vv;
    yy_sec_waf_conn_ctx_t          *conn_ctx;
    yy_sec_waf_conn_node_t         *lc;
    yy_sec_waf_conn_cleanup_t      *lccln;


    if (ctx == NULL || ctx->cf == NULL
        || ctx->cf->shm_zone == NULL
        || ctx->cf->shm_zone->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0, "[ysec_waf] NULL pointer");
        return NGX_ERROR;
    }

    conn_ctx = ctx->cf->shm_zone->data;

	vv = ngx_http_get_indexed_variable(ctx->r, conn_ctx->index);
	
	if (vv == NULL || vv->not_found) {
		return NGX_ERROR;
	}
	
	len = vv->len;

    hash = ngx_crc32_short(vv->data, vv->len);

    shpool = (ngx_slab_pool_t *) ctx->cf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = yy_sec_waf_conn_lookup(conn_ctx->rbtree, vv, hash);

    if (node == NULL) {

        n = offsetof(ngx_rbtree_node_t, color)
            + offsetof(yy_sec_waf_conn_node_t, data)
            + len;

        node = ngx_slab_alloc_locked(shpool, n);

        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            yy_sec_waf_conn_cleanup_all(ctx->pool);
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        }

        lc = (yy_sec_waf_conn_node_t *) &node->color;

        node->key = hash;
        lc->len = (u_char) len;
        lc->conn = 1;
        ngx_memcpy(lc->data, vv->data, len);

        ngx_rbtree_insert(conn_ctx->rbtree, node);

    } else {

        lc = (yy_sec_waf_conn_node_t *) &node->color;

        lc->conn++;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
                   "[ysec_waf] conn: %08XD %d", node->key, lc->conn);

    // GET the connection counter.
    ctx->conn_perip = lc->conn;

    ngx_shmtx_unlock(&shpool->mutex);

    cln = ngx_pool_cleanup_add(ctx->pool,
                               sizeof(yy_sec_waf_conn_cleanup_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = yy_sec_waf_conn_cleanup;
    lccln = cln->data;

    lccln->shm_zone = ctx->cf->shm_zone;
    lccln->node = node;

    return NGX_OK;
}


