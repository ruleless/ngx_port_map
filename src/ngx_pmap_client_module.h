#ifndef _NGX_PMAP_CLIENT_MODULE_H_INCLUDED_
#define _NGX_PMAP_CLIENT_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_pmap.h"


/* conf structure of ngx_pmap_client_module */
typedef struct {
    ngx_pmap_listen_t    listen;
    ngx_pmap_addr_t      server_addr;
    
    ngx_flag_t           use_kcp;
    ngx_pmap_addr_t      kcp_addr;
} ngx_pmap_client_conf_t;


/* a hub for proxied client */
typedef struct {
    ngx_connection_t  *c;
} ngx_pmap_client_hub_t;


void ngx_pmap_client_init_connection(ngx_connection_t *c);

#endif /* _NGX_PMAP_CLIENT_MODULE_H_INCLUDED_ */
