#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "ngx_pmap.h"
#include "ngx_pmap_client_module.h"

extern ngx_module_t ngx_pmap_client_module;

static char *ngx_pmap_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_pmap_core_create_conf(ngx_cycle_t *cycle);
static void *ngx_pmap_core_init_conf(ngx_cycle_t *cycle, void *conf);

static char *ngx_pmap_parse_client(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_pmap_parse_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_listening_t *
ngx_pmap_add_listening(ngx_conf_t *cf, ngx_pmap_listen_t *lscf, ngx_connection_handler_pt handler);

static ngx_uint_t ngx_pmap_max_module;


static ngx_command_t ngx_pmap_commands[] = {
    { ngx_string("port_map"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_pmap_block,
      0,
      0,
      NULL },

    ngx_null_command
};

static ngx_core_module_t ngx_pmap_module_ctx = {
    ngx_string("pmap"),
    NULL,
    NULL,
};

ngx_module_t ngx_pmap_module = {
    NGX_MODULE_V1,
    &ngx_pmap_module_ctx,
    ngx_pmap_commands,
    NGX_CORE_MODULE,
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t pmap_core_name = ngx_string("port_map");

static ngx_command_t ngx_pmap_core_commands[] = {
    { ngx_string("endpoint"),
      NGX_PMAP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_pmap_conf_t, endpoint),
      NULL },
    
    { ngx_string("client"),
      NGX_PMAP_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_pmap_parse_client,
      0,
      0,
      NULL },
    
    { ngx_string("server"),
      NGX_PMAP_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_pmap_parse_server,
      0,
      0,
      NULL },

    ngx_null_command
};

ngx_pmap_module_t ngx_pmap_core_module_ctx = {
    &pmap_core_name,

    ngx_pmap_core_create_conf,
    ngx_pmap_core_init_conf,
};

ngx_module_t ngx_pmap_core_module = {
    NGX_MODULE_V1,
    &ngx_pmap_core_module_ctx,
    ngx_pmap_core_commands,
    NGX_PMAP_MODULE,
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_pmap_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    ngx_int_t                 i, mi;
    void                   ***ctx;
    ngx_pmap_module_t        *m;
    ngx_conf_t                pcf;
    ngx_pmap_conf_t          *corecf;
    ngx_pmap_client_conf_t   *clientcf;
    
    if (*(void **)conf) {
        return "is duplicate";
    }

    /* count the number of the pmap modules and set up their indices */
    
    ngx_pmap_max_module = ngx_count_modules(cf->cycle, NGX_PMAP_MODULE);

    ctx = ngx_pcalloc(cf->pool, sizeof(void *));
    if (NULL == ctx) {
        return NGX_CONF_ERROR;
    }

    *ctx = ngx_pcalloc(cf->pool, ngx_pmap_max_module*sizeof(void *));
    if (NULL == *ctx) {
        return NGX_CONF_ERROR;
    }

    *(void **)conf = ctx;

    for (i = 0; cf->cycle->modules[i]; ++i) {
        if (cf->cycle->modules[i]->type != NGX_PMAP_MODULE) {
            continue;
        }
        
        m = cf->cycle->modules[i]->ctx;
        mi = cf->cycle->modules[i]->ctx_index;
        
        if (m->create_conf) {
            (*ctx)[mi] = m->create_conf(cf->cycle);
            if (NULL == (*ctx)[mi]) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_PMAP_MODULE;
    cf->cmd_type = NGX_PMAP_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    for (i = 0; cf->cycle->modules[i]; ++i) {
        if (cf->cycle->modules[i]->type != NGX_PMAP_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;
        mi = cf->cycle->modules[i]->ctx_index;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle, (*ctx)[mi]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }       
    }

    /* init listen */
    
    corecf = ngx_pmap_get_conf(cf->cycle->conf_ctx, ngx_pmap_core_module);
            
    if (!ngx_pmap_is_valid_endpt(corecf->endpoint)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid endpoint \"%d\"", corecf->endpoint);
        return NGX_CONF_ERROR;
    }

    if (NGX_PMAP_ENDPOINT_CLIENT == corecf->endpoint) { /* for client */
        clientcf = ngx_pmap_get_conf(cf->cycle->conf_ctx, ngx_pmap_client_module);
        
        ngx_pmap_add_listening(cf, &clientcf->listen, ngx_pmap_client_init_connection);
    } 

    return NGX_CONF_OK;
}

static void *
ngx_pmap_core_create_conf(ngx_cycle_t *cycle)
{
    ngx_pmap_conf_t *corecf;

    corecf = ngx_palloc(cycle->pool, sizeof(ngx_pmap_conf_t));
    if (NULL == corecf) {
        return NULL;
    }

    corecf->endpoint = NGX_CONF_UNSET;
    corecf->error_log = &cycle->new_log;

    return corecf;
}

static void *
ngx_pmap_core_init_conf(ngx_cycle_t *cycle, void *conf)
{
    return NGX_CONF_OK;
}

static char *
ngx_pmap_parse_client(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_conf_t   save;
    char        *rv;

    save = *cf;
    cf->cmd_type = NGX_PMAP_CLIENT_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;
    
    return rv;
}

static char *
ngx_pmap_parse_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{       
    return NGX_CONF_OK;
}

void *ngx_pmap_cache_alloc(void *ctx, size_t size)
{
    return ngx_palloc(ctx, size);
}

void ngx_pmap_cache_dealloc(void *ctx, void *p)
{
    ngx_pfree(ctx, p);
}

char *
ngx_pmap_parse_listen_addr(ngx_conf_t *cf, ngx_pmap_listen_t *ls)
{
    ngx_str_t  *value;
    ngx_url_t   u;
    ngx_uint_t  i;

    /* parse the inet address */
    
    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_pmap_listen_t));
    ngx_memcpy(&ls->u.sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->wildcard = u.wildcard;

    /* parse the left argument */

    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
        
        if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {
            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;
            } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;
            }

            ls->bind = 1;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}

char *
ngx_pmap_parse_addr(ngx_conf_t *cf, ngx_pmap_addr_t *addr)
{
    ngx_str_t  *value;
    ngx_url_t   u;

    /* parse the inet address */

    value = (ngx_str_t *)cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    if (u.no_port) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no port in \"%V\"", &u.url);
        return NGX_CONF_ERROR;
    }

    addr->name = u.url;
    ngx_memcpy(&addr->u.sockaddr, u.sockaddr, u.socklen);   
    addr->socklen = u.socklen;

    return NGX_CONF_OK;
}

static ngx_listening_t *
ngx_pmap_add_listening(ngx_conf_t *cf, ngx_pmap_listen_t *lscf, ngx_connection_handler_pt handler)
{
    ngx_listening_t    *ls;
    ngx_pmap_conf_t    *corecf;

    ls = ngx_create_listening(cf, &lscf->u.sockaddr, lscf->socklen);
    if (NULL == ls) {
        return NULL;
    }

    corecf = ngx_pmap_get_conf(cf->cycle->conf_ctx, ngx_pmap_core_module);
    
    ls->addr_ntop = 1;  
    ls->handler = handler;
    ls->pool_size = 256;

    ls->logp = corecf->error_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

    return ls;   
}

void
ngx_pmap_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    c->destroyed = 1;
    pool = c->pool;

    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}

void
ngx_pmap_empty_write_handler(ngx_event_t *wev)
{    
}
