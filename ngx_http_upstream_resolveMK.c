#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#define RESOLVE_STATS_DONE 0
#define RESOLVE_STATS_WAIT 1

typedef struct {
	struct sockaddr sockaddr;
	struct sockaddr_in6 padding;

	socklen_t socklen;

	ngx_str_t name;
	u_char ipstr[NGX_SOCKADDR_STRLEN + 1];

#if (NGX_HTTP_SSL)
	/* local to a process */
	ngx_ssl_session_t *ssl_session;
#endif
} ngx_http_upstream_resolveMK_peer_t;

typedef struct {
	ngx_http_upstream_resolveMK_peer_t *peers;

	ngx_uint_t resolver_max_ip;
	ngx_uint_t resolved_num;
	ngx_str_t resolver_domain;
	ngx_int_t resolver_stats;
	ngx_uint_t resolved_index;

	time_t resolved_access;
	time_t resolver_interval;
	ngx_str_t resolver_service;

	ngx_uint_t upstream_retry;
} ngx_http_upstream_resolveMK_srv_conf_t;

typedef struct {
	ngx_http_upstream_resolveMK_srv_conf_t *conf;
	ngx_http_core_loc_conf_t *clcf;

	ngx_int_t current;

} ngx_http_upstream_resolveMK_peer_data_t;

#if (NGX_HTTP_SSL)
ngx_int_t ngx_http_upstream_set_resolveMK_peer_session(ngx_peer_connection_t
    *pc, void *data);
void ngx_http_upstream_save_resolveMK_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static char *ngx_http_upstream_resolveMK(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void * ngx_http_upstream_resolveMK_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_resolveMK_init(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_resolveMK_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_resolveMK_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_resolveMK_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static void ngx_http_upstream_resolveMK_handler(ngx_resolver_ctx_t *ctx);

static ngx_command_t  ngx_http_upstream_resolveMK_commands[] = {
	{
		ngx_string("resolveMK"),
		NGX_HTTP_UPS_CONF | NGX_CONF_1MORE,
		ngx_http_upstream_resolveMK,
		0,
		0,
		NULL
	},
	ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_resolveMK_module_ctx = {
	NULL,           /* preconfiguration */
	NULL,           /* postconfiguration */

	NULL,           /* create main configuration */
	NULL,           /* init main configuration */

	/* create server configuration */
	ngx_http_upstream_resolveMK_create_conf,

	NULL,           /* merge server configuration */

	NULL,           /* create location configuration */
	NULL            /* merge location configuration */
};

ngx_module_t  ngx_http_upstream_resolveMK_module = {
	NGX_MODULE_V1,

	/* module context */
	&ngx_http_upstream_resolveMK_module_ctx,

	/* module directives */
	ngx_http_upstream_resolveMK_commands,

	/* module type */
	NGX_HTTP_MODULE,

	NULL,           /* init master */
	NULL,           /* init module */
	NULL,           /* init process */
	NULL,           /* init thread */
	NULL,           /* exit thread */
	NULL,           /* exit process */
	NULL,           /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_upstream_resolveMK_init(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_upstream_resolveMK_srv_conf_t *urcf;
	us->peer.init = ngx_http_upstream_resolveMK_init_peer;
	urcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_resolveMK_module);
	urcf->resolver_stats = RESOLVE_STATS_DONE;

	return NGX_OK;
}

static ngx_int_t ngx_http_upstream_resolveMK_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_upstream_resolveMK_peer_data_t *urpd;
	ngx_http_upstream_resolveMK_srv_conf_t *urcf;
	urcf = ngx_http_conf_upstream_srv_conf(us,
	                                       ngx_http_upstream_resolveMK_module);
	urpd = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolveMK_peer_data_t));

	if (urpd == NULL) {
		return NGX_ERROR;
	}

	urpd->conf = urcf;
	urpd->clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	urpd->current = -1;

	r->upstream->peer.data = urpd;
	r->upstream->peer.free = ngx_http_upstream_resolveMK_free_peer;
	r->upstream->peer.get = ngx_http_upstream_resolveMK_get_peer;

	if (urcf->upstream_retry) {
		r->upstream->peer.tries = (urcf->resolved_num != 1) ? urcf->resolved_num : 2;
	} else {
		r->upstream->peer.tries = 1;
	}

#if (NGX_HTTP_SSL)
	r->upstream->peer.set_session = ngx_http_upstream_set_resolveMK_peer_session;
	r->upstream->peer.save_session = ngx_http_upstream_save_resolveMK_peer_session;
#endif

	return NGX_OK;
}

static ngx_int_t ngx_http_upstream_resolveMK_get_peer(ngx_peer_connection_t *pc,
    void *data)
{
	ngx_http_upstream_resolveMK_peer_data_t *urpd = data;
	ngx_http_upstream_resolveMK_srv_conf_t *urcf = urpd->conf;
	ngx_resolver_ctx_t *ctx;
	ngx_http_upstream_resolveMK_peer_t *peer;

	pc->cached = 0;
	pc->connection = NULL;

	if (urcf->resolver_stats == RESOLVE_STATS_WAIT) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "upstream_resolveMK: resolving");
		goto assign;
	}

	if (ngx_time() <= urcf->resolved_access + urcf->resolver_interval) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
			       "upstream_resolveMK: update from DNS cache");
		goto assign;
	}
	ctx = ngx_resolve_start(urpd->clcf->resolver, NULL);

	if (ctx == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		               "upstream_resolveMK: resolve_start fail");
		goto assign;
	}

	if (ctx == NGX_NO_RESOLVER) {
		ngx_log_error(NGX_LOG_ALERT, pc->log, 0, "upstream_resolveMK: no resolver");
		goto assign;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	               "upstream_resolveMK: resolve_start ok");
	ctx->name = urcf->resolver_domain;
	ctx->service = urcf->resolver_service;
	ctx->handler = ngx_http_upstream_resolveMK_handler;
	ctx->data = urcf;
	ctx->timeout = urpd->clcf->resolver_timeout;
	urcf->resolver_stats = RESOLVE_STATS_WAIT;

	if (ngx_resolve_name(ctx) != NGX_OK) {
		ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
		              "upstream_resolveMK: resolve name \"%V\" fail", &ctx->name);
	}

assign:
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	               "upstream_resolveMK: resolved_num=%ud", urcf->resolved_num);

	if (urpd->current == -1) {
		urcf->resolved_index = (urcf->resolved_index + 1) % urcf->resolved_num;
		urpd->current = urcf->resolved_index;
	} else {
		urpd->current = (urpd->current + 1) % urcf->resolved_num;
	}

	peer = &(urcf->peers[urpd->current]);
	pc->sockaddr = &peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	               "upstream_resolveMK: upstream to DNS peer (%s:%ud)",
	               inet_ntoa(((struct sockaddr_in*)(pc->sockaddr))->sin_addr),
	               ntohs((unsigned short)((struct sockaddr_in*)(pc->sockaddr))->sin_port));

	return NGX_OK;
}

static void ngx_http_upstream_resolveMK_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
	if (pc->tries > 0) {
		pc->tries--;
	}
}

static char *ngx_http_upstream_resolveMK(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
	ngx_http_upstream_srv_conf_t *uscf;
	ngx_http_upstream_resolveMK_srv_conf_t *urcf;
	ngx_http_upstream_server_t *us;

	time_t interval;
	ngx_str_t *value, domain, s;
	ngx_int_t max_ip;
	ngx_uint_t retry;
	ngx_http_upstream_resolveMK_peer_t *paddr;
	ngx_url_t u;
	ngx_uint_t i;

	interval = 10;
	max_ip = 20;
	retry = 1;
	domain.data = NULL;
	domain.len = 0;
	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	/* Just For Padding, upstream { } need it */
	if (uscf->servers == NULL) {
		uscf->servers = ngx_array_create(cf->pool, 1,
		                                 sizeof(ngx_http_upstream_server_t));

		if (uscf->servers == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	us = ngx_array_push(uscf->servers);

	if (us == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(us, sizeof(ngx_http_upstream_server_t));
	urcf = ngx_http_conf_upstream_srv_conf(uscf,
	                                       ngx_http_upstream_resolveMK_module);
	uscf->peer.init_upstream = ngx_http_upstream_resolveMK_init;
	value = cf->args->elts;

	if (value[1].len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "domain is not given");

		return NGX_CONF_ERROR;
	}

	domain.data = value[1].data;
	domain.len  = value[1].len;

	us->addrs = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
	us->addrs->name = domain;
	
	if (ngx_strncmp(value[2].data, "service=", 8) != 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "service is not given");

		return NGX_CONF_ERROR;
	}

	urcf->resolver_service.len = value[2].len - 8;
	urcf->resolver_service.data = &value[2].data[8];

	for (i = 3; i < cf->args->nelts; i++) {

		if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
			s.len = value[i].len - 9;
			s.data = &value[i].data[9];
			interval = ngx_parse_time(&s, 1);

			if (interval == (time_t) NGX_ERROR) {
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "max_ip=", 7) == 0) {
			max_ip = ngx_atoi(value[i].data + 7, value[i].len - 7);

			if (max_ip == NGX_ERROR || max_ip < 1) {
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "retry_off", 9) == 0) {
			retry = 0;
			continue;
		}

		goto invalid;
	}

	urcf->peers = ngx_pcalloc(cf->pool,
	                          max_ip * sizeof(ngx_http_upstream_resolveMK_peer_t));

	if (urcf->peers == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "ngx_palloc peers fail");
		return NGX_CONF_ERROR;
	}

	urcf->resolver_interval = interval;
	urcf->resolver_domain = domain;
	urcf->resolver_max_ip = max_ip;
	urcf->upstream_retry = retry;
	ngx_memzero(&u, sizeof(ngx_url_t));
	u.url = value[1];

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			                   "%s in upstream \"%V\"", u.err, &u.url);
		}

		return NGX_CONF_ERROR;
	}

	urcf->resolved_num = 0;

	for (i = 0; i < u.naddrs ; i++) {
		paddr = &urcf->peers[urcf->resolved_num];
		paddr->sockaddr = *(struct sockaddr*)u.addrs[i].sockaddr;
		paddr->socklen = u.addrs[i].socklen;
		paddr->name = u.addrs[i].name;
		urcf->resolved_num++;

		if (urcf->resolved_num >= urcf->resolver_max_ip) {
			break;
		}
	}

	/* urcf->resolved_index = 0 */
        urcf->resolved_access = ngx_time() - urcf->resolver_interval;

	return NGX_CONF_OK;
invalid:
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
	                   "invalid parameter \"%V\"", &value[i]);

	return NGX_CONF_ERROR;
}

static void *
ngx_http_upstream_resolveMK_create_conf(ngx_conf_t *cf)
{
	ngx_http_upstream_resolveMK_srv_conf_t  *conf;
	conf = ngx_pcalloc(cf->pool,
	                   sizeof(ngx_http_upstream_resolveMK_srv_conf_t));

	if (conf == NULL) {
		return NULL;
	}

	return conf;
}

static void
ngx_http_upstream_resolveMK_handler(ngx_resolver_ctx_t *ctx)
{
	ngx_resolver_t *r;
	ngx_http_upstream_resolveMK_peer_t *peer;
	ngx_http_upstream_resolveMK_srv_conf_t *urcf;

	struct sockaddr *addr;
	ngx_uint_t i;

	r = ctx->resolver;
	urcf = (ngx_http_upstream_resolveMK_srv_conf_t *)ctx->data;
	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->log, 0,
	               "upstream_resolveMK: \"%V\" resolved state(%i: %s)",
	               &ctx->name, ctx->state,
	               ngx_resolver_strerror(ctx->state));

	if (ctx->state || ctx->naddrs == 0) {
		ngx_log_error(NGX_LOG_ERR, r->log, 0,
		              "upstream_resolveMK: resolver failed ,\"%V\" (%i: %s))",
		              &ctx->name, ctx->state,
		              ngx_resolver_strerror(ctx->state));
		goto end;
	}

	urcf->resolved_num = 0;

	for (i = 0; i < ctx->nsrvs; i++) {
		peer = &urcf->peers[urcf->resolved_num];
		addr = &peer->sockaddr;
		peer->socklen = ctx->srvs[i].addrs[0].socklen;
		ngx_memcpy(addr, ctx->srvs[i].addrs[0].sockaddr, peer->socklen);

		switch (addr->sa_family) {
		case AF_INET6:
			((struct sockaddr_in6*)addr)->sin6_port = htons(ctx->srvs[i].port);
			break;

		default:
			((struct sockaddr_in*)addr)->sin_port = htons(ctx->srvs[i].port);
		}

		peer->name.data = peer->ipstr;
		peer->name.len = ngx_sock_ntop(addr, peer->socklen, peer->ipstr,
		                               NGX_SOCKADDR_STRLEN, 1);
		urcf->resolved_num++;

		if (urcf->resolved_num >= urcf->resolver_max_ip) {
			break;
		}
	}

end:
	ngx_resolve_name_done(ctx);
	urcf->resolved_access = ngx_time();
	urcf->resolver_stats = RESOLVE_STATS_DONE;
}

#if (NGX_HTTP_SSL)

ngx_int_t
ngx_http_upstream_set_resolveMK_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
	ngx_http_upstream_resolveMK_peer_data_t *urpd = data;
	ngx_int_t rc;
	ngx_ssl_session_t *ssl_session;
	ngx_http_upstream_resolveMK_peer_t *peer;

	peer = &urpd->conf->peers[urpd->current];
	ssl_session = peer->ssl_session;
	rc = ngx_ssl_set_session(pc->connection, ssl_session);
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	               "set session: %p:%d",
	               ssl_session, ssl_session ? ssl_session->references : 0);
	return rc;
}


void
ngx_http_upstream_save_resolveMK_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
	ngx_http_upstream_resolveMK_peer_data_t *urpd = data;
	ngx_ssl_session_t *old_ssl_session, *ssl_session;
	ngx_http_upstream_resolveMK_peer_t *peer;

	ssl_session = ngx_ssl_get_session(pc->connection);

	if (ssl_session == NULL) {
		return;
	}

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
	               "save session: %p:%d", ssl_session, ssl_session->references);
	peer = &urpd->conf->peers[urpd->current];
	old_ssl_session = peer->ssl_session;
	peer->ssl_session = ssl_session;

	if (old_ssl_session) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		               "old session: %p:%d",
		               old_ssl_session, old_ssl_session->references);
		ngx_ssl_free_session(old_ssl_session);
	}
}

#endif
