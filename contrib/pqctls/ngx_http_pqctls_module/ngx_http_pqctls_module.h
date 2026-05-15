#ifndef _NGX_HTTP_PQCTLS_MODULE_H_INCLUDED_
#define _NGX_HTTP_PQCTLS_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <pqctls_capi.h>

#define NGX_HTTP_PQCTLS 1

#define NGX_HTTP_PQCTLS_ALG_ECDSA_KYBER  PQCTLS_ALG_ECDSA_KYBER
#define NGX_HTTP_PQCTLS_ALG_SM2_KYBER    PQCTLS_ALG_SM2_KYBER

typedef struct {
    ngx_str_t       certificate;
    ngx_str_t       certificate_key;
    ngx_str_t       client_certificate;

    ngx_str_t       certificate_data;
    ngx_str_t       certificate_key_data;
    ngx_str_t       client_certificate_data;

    ngx_msec_t      handshake_timeout;
    ngx_uint_t      algorithm;

    pqctls_ctx_t   *runtime_ctx;
} ngx_http_pqctls_srv_conf_t;


typedef struct {
    pqctls_session_t                 *session;
    ngx_http_connection_t            *http;
    ngx_http_pqctls_srv_conf_t       *srv_conf;
    u_char                           *send_buffer;
    size_t                            send_buffer_size;
} ngx_http_pqctls_connection_t;


extern ngx_module_t  ngx_http_pqctls_module;

void ngx_http_pqctls_handshake(ngx_event_t *rev);
ssize_t ngx_http_pqctls_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_http_pqctls_send(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t *ngx_http_pqctls_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

#endif /* _NGX_HTTP_PQCTLS_MODULE_H_INCLUDED_ */
