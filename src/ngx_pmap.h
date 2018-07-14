#ifndef _NGX_PMAP_H_INCLUDED_
#define _NGX_PMAP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_PMAP_MODULE             0x50414D50  /* "PMAP" */
#define NGX_PMAP_CONF               0x02000000
#define NGX_PMAP_CLIENT_CONF        0x04000000
#define NGX_PMAP_SERVER_CONF        0x08000000

#define NGX_PMAP_ENDPOINT_CLIENT    1
#define NGX_PMAP_ENDPOINT_SERVER    2

#define ngx_pmap_get_conf(conf_ctx, module)                         \
    (*(ngx_get_conf(conf_ctx, ngx_pmap_module)))[module.ctx_index]

#define ngx_pmap_is_valid_endpt(endpt)                                  \
    (NGX_PMAP_ENDPOINT_CLIENT == endpt || NGX_PMAP_ENDPOINT_SERVER == endpt)


/* the listening structure */
typedef struct {
    union {
        struct sockaddr     sockaddr;
        struct sockaddr_in  sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6 sockaddr_in6;
#endif
        u_char              sockaddr_data[NGX_SOCKADDRLEN];
    } u;
    socklen_t               socklen;
    
    unsigned                bind:1;
    unsigned                wildcard:1;
    unsigned                so_keepalive:2;
    int                     backlog;
} ngx_pmap_listen_t;


/* inet address */
typedef struct {
    union {
        struct sockaddr     sockaddr;
        struct sockaddr_in  sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6 sockaddr_in6;
#endif
        u_char              sockaddr_data[NGX_SOCKADDRLEN];
    } u;
    socklen_t               socklen;
    ngx_str_t               name;
} ngx_pmap_addr_t;


/* pmap module */
typedef struct {
    ngx_str_t    *name;

    void        *(*create_conf)(ngx_cycle_t *cycle);
    void        *(*init_conf)(ngx_cycle_t *cycle, void *conf);
} ngx_pmap_module_t;


/* conf structure of ngx_pmap_core_module */
typedef struct {
    ngx_int_t    endpoint;
    ngx_log_t   *error_log;
} ngx_pmap_conf_t;


extern ngx_module_t ngx_pmap_module;
extern ngx_module_t ngx_pmap_core_module;


void *ngx_pmap_cache_alloc(void *ctx, size_t size);
void ngx_pmap_cache_dealloc(void *ctx, void *p);

char *ngx_pmap_parse_listen_addr(ngx_conf_t *cf, ngx_pmap_listen_t *ls);
char *ngx_pmap_parse_addr(ngx_conf_t *cf, ngx_pmap_addr_t *addr);

void ngx_pmap_close_connection(ngx_connection_t *c);
void ngx_pmap_empty_write_handler(ngx_event_t *wev);


#endif /* _NGX_PMAP_H_INCLUDED_ */
