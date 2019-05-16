#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef USE_EVENT2
#include <event2/event.h>
#else
#include <event.h>
#endif

#ifndef USE_ACCEPT4
#define accept4(s, addr, addrlen, flags)	accept(s, addr, addrlen)
#endif

/*
1 file descriptor for stderr
3 file descriptors for listen
8 file descriptors for client connections
8 file descriptors for socks connections
total = 20 file descriptors
*/
#define MAXLISTENERS	3
#define MAXPEERS	8
#define BUFSIZE		4096
#define HOSTSIZE	256
#define PORTSIZE	16
#define ADDRFORMAT	"%255[^:]:%15s"

struct peer {
	int		 listener_s;
	int		 inbuf_size;
	int		 outbuf_size;
	struct peer	*next;
	struct event	 ev1r, ev1w;
	struct event	 ev2r, ev2w;
	uint8_t		 inbuf[BUFSIZE];
	uint8_t		 outbuf[BUFSIZE];
};
struct peer	 peers[MAXPEERS];
struct peer	*peers_free;

struct event	 listeners[MAXLISTENERS];
int		 listeners_count;

struct addrinfo	*socks_ai;
uint8_t		 socks_hdr[HOSTSIZE + 10];
int		 socks_hdrlen;

void		 init_listeners(const char *);
void		 init_targetaddr(const char *);
void		 init_socksaddr(const char *);
void		 listener_fn(int, short, void *);
void		 peer_conr(int, short, void *);
void		 peer_conw(int, short, void *);
void		 peer_fn1r(int, short, void *);
void		 peer_fn1w(int, short, void *);
void		 peer_fn2r(int, short, void *);
void		 peer_fn2w(int, short, void *);
void		 shutdown_early(struct peer *, int);
void		 shutdown_local(struct peer *, int);
void		 shutdown_target(struct peer *, int);

int
main(const int argc, const char *const *const argv)
{
#ifdef USE_PLEDGE
	if (pledge("stdio inet dns", NULL) < 0)
		return 1;
#endif
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	if (argc != 4)
		errx(1, "invalid usage\n"
		    "%s listenaddr socksaddr targetaddr\n\n"
		    "addr = host:port", argv[0]);

	for (int i = 1; i <= MAXPEERS; ++i)
		peers[i - 1].next = i < MAXPEERS ? &peers[i] : NULL;
	peers_free = &peers[0];
	event_init();
	init_listeners(argv[1]);
	init_targetaddr(argv[3]);
	init_socksaddr(argv[2]);
	for (int i = 0; i < listeners_count; ++i)
		event_add(&listeners[i], NULL);
	event_dispatch();
	return 0;
}

void
init_listeners(const char *const addr)
{
	char		 host[HOSTSIZE];
	char		 port[PORTSIZE];
	struct addrinfo	 hints, *res, *res0;
	int		 error, save_errno;
	int		 n;
	const char	*cause = NULL;

	if (sscanf(addr, ADDRFORMAT, host, port) != 2)
		errx(1, "invalid address '%s'", addr);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "getaddrinfo:%s", gai_strerror(error));
	n = 0;
	for (res = res0; res && n < MAXLISTENERS; res = res->ai_next) {
		int		 s;
		struct event	*listener = &listeners[n];

		if ((s = socket(res->ai_family, res->ai_socktype
		    | SOCK_NONBLOCK, res->ai_protocol)) == -1) {
			cause = "socket";
			save_errno = errno;
			continue;
		}

		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
			save_errno = errno;
			close(s);
			continue;
		}

		if (listen(s, 5) == -1) {
			cause = "bind";
			save_errno = errno;
			close(s);
			continue;
		}

		event_set(listener, s, EV_READ, listener_fn, listener);
		++n;
	}
	if (n == 0) {
		errno = save_errno;
		err(1, "%s", cause);
	}
	listeners_count = n;
	freeaddrinfo(res0);
}

void
init_targetaddr(const char *const addr)
{
	char		 host[HOSTSIZE];
	char		 port[PORTSIZE];
	struct addrinfo	 hints, *res;
	int		 error;
	in_port_t	 host_port;
	int		 n;

	if (sscanf(addr, ADDRFORMAT, host, port) != 2)
		errx(1, "invalid address '%s'", addr);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(NULL, port, &hints, &res);
	if (error || !res)
		errx(1, "getaddrinfo:%s", gai_strerror(error));
	host_port = ntohs(
	    ((const struct sockaddr_in *)res->ai_addr)->sin_port);
	freeaddrinfo(res);

	n = 0;
	socks_hdr[n++] = (uint8_t)5;		/* SOCKS version */
	socks_hdr[n++] = (uint8_t)1;		/* number of auth */
	socks_hdr[n++] = (uint8_t)0;		/* no auth */
	socks_hdr[n++] = (uint8_t)5;		/* SOCKS version */
	socks_hdr[n++] = (uint8_t)1;		/* TCP stream */
	socks_hdr[n++] = (uint8_t)0;		/* reserved */
	socks_hdr[n++] = (uint8_t)3;		/* domain name addr */
	socks_hdr[n++] = (uint8_t)strlen(host);	/* name len */
	memcpy(socks_hdr + n, host, strlen(host));
	n += strlen(host);
	socks_hdr[n++] = (uint8_t)((host_port >> 8) & 255);
	socks_hdr[n++] = (uint8_t)(host_port & 255);
	socks_hdrlen = n;
}

void
init_socksaddr(const char *const addr)
{
	char		 host[HOSTSIZE];
	char		 port[PORTSIZE];
	struct addrinfo	 hints;
	int		 error;

	if (sscanf(addr, ADDRFORMAT, host, port) != 2)
		errx(1, "invalid address '%s'", addr);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &socks_ai);
	if (error)
		errx(1, "getaddrinfo:%s", gai_strerror(error));
}

void
listener_fn(const int fd, const short events, void *const arg)
{
	struct event	*const ev = arg;
	int		 s;
	const int	 on = 1;
	struct addrinfo	*ai;
	struct peer	*p;

	if ((events & EV_READ) != EV_READ) {
		warnx("bad event");
		event_add(ev, NULL);
		return;
	}

	if ((s = socket(socks_ai->ai_family, socks_ai->ai_socktype
	    | SOCK_NONBLOCK, socks_ai->ai_protocol)) == -1) {
		warn("socket");
		event_add(ev, NULL);
		return;
	}

	for (ai = socks_ai; ai != NULL; ai = ai->ai_next) {
		if (connect(s, ai->ai_addr, ai->ai_addrlen) != -1
		    || errno == EINTR || errno == EINPROGRESS)
			break;
	}
	if (ai == NULL) {
		warn("connect");
		close(s);
		event_add(ev, NULL);
		return;
	}

	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on) < 0)
		warn("setsockopt");

	if ((p = peers_free) == NULL)
		errx(1, "FATAL");
	peers_free = p->next;
	p->listener_s = fd;
	p->inbuf_size = 0;
	p->outbuf_size = socks_hdrlen;
	event_set(&p->ev2r, s, EV_READ  | EV_PERSIST, peer_conr, p);
	event_set(&p->ev2w, s, EV_WRITE | EV_PERSIST, peer_conw, p);
	event_add(&p->ev2r, NULL);
	event_add(&p->ev2w, NULL);
	for (int i = 0; i < listeners_count; ++i)
		if (&listeners[i] != ev)
			event_del(&listeners[i]);
}

void
peer_conr(const int fd, const short events, void *const arg)
{
	struct peer	*const p = arg;
	int		 res;
	int		 hdr_len;
	int		 s;
	struct sockaddr_in sa;
	socklen_t	 sa_size = sizeof sa;
	const int	 on = 1;

	if ((events & EV_READ) != EV_READ) {
		warnx("bad event");
		return;
	}

	res = (int)recv(fd,
	    p->inbuf + p->inbuf_size,
	    sizeof(p->inbuf) - p->inbuf_size,
	    MSG_DONTWAIT);
	if (res == 0 || (res < 0 && errno != EAGAIN)) {
		warn("recv");
		shutdown_early(p, fd);
		return;
	} else if (res <= 0)
		return;

	p->inbuf_size += res;
	if (p->inbuf_size < 2)
		return;
	if (p->inbuf[0] != 5 ||		/* SOCKS version */
	    p->inbuf[1] != 0) {		/* auth method (no auth) */
		warnx("bad SOCKS 5 greeting");
		shutdown_early(p, fd);
		return;
	}
	if (p->inbuf_size < 7)
		return;
	if (p->inbuf[2] != 5 ||		/* SOCKS version */
	    p->inbuf[4] != 0) {		/* reserved */
		warnx("bad SOCKS 5 response");
		shutdown_early(p, fd);
		return;
	}
	if (p->inbuf[3] != 0) {		/* status (granted) */
		warnx("SOCKS5: could not connect (code: %d)",
		    p->inbuf[3]);
		shutdown_early(p, fd);
		return;
	}

	if (p->inbuf[5] == 1)		/* IPv4 address */
		hdr_len = 8 + 4;
	else if (p->inbuf[5] == 3)	/* IPv4 address */
		hdr_len = 9 + p->inbuf[6];
	else if (p->inbuf[5] == 4)	/* IPv4 address */
		hdr_len = 8 + 16;
	else {
		warnx("bad SOCKS 5 response");
		shutdown_early(p, fd);
		return;
	}

	if (p->inbuf_size < hdr_len)
		return;
	if (p->outbuf_size != 0) {
		warnx("unexpected response before request");
		shutdown_early(p, fd);
		return;
	}
	s = accept4(p->listener_s, (struct sockaddr *)&sa, &sa_size,
	    SOCK_NONBLOCK);
	if (s < 0) {
		warn("accept4");
		shutdown_early(p, fd);
		return;
	}

	if (peers_free != NULL)
		for (int i = 0; i < listeners_count; ++i)
			event_add(&listeners[i], NULL);
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on) < 0)
		warn("setsockopt");
	p->inbuf_size -= hdr_len;
	memmove(p->inbuf, p->inbuf + hdr_len, p->inbuf_size);
	event_del(&p->ev2r);
	event_del(&p->ev2w);
	event_set(&p->ev1r, s,  EV_READ  | EV_PERSIST, peer_fn1r, p);
	event_set(&p->ev1w, s,  EV_WRITE | EV_PERSIST, peer_fn1w, p);
	event_set(&p->ev2r, fd, EV_READ  | EV_PERSIST, peer_fn2r, p);
	event_set(&p->ev2w, fd, EV_WRITE | EV_PERSIST, peer_fn2w, p);
	/*
		add	ev1r	if	outbuf_size < MAX (TRUE)
		add	ev1w	if	 inbuf_size > 0
		add	ev2r	if	 inbuf_size < MAX (TRUE)
		add	ev2w	if	outbuf_size > 0   (FALSE)
	*/
	event_add(&p->ev1r, NULL);
	if (p->inbuf_size > 0)
		event_add(&p->ev1w, NULL);
	event_add(&p->ev2r, NULL);
}

void
peer_conw(const int fd, const short events, void *const arg)
{
	struct peer	*const p = arg;
	int		 res;

	if ((events & EV_WRITE) != EV_WRITE) {
		warnx("bad event");
		return;
	}

	res = (int)send(fd,
	    socks_hdr + socks_hdrlen - p->outbuf_size,
	    p->outbuf_size,
	    MSG_DONTWAIT);
	if (res == 0 || (res < 0 && errno != EAGAIN)) {
		if (res < 0)
			warn("send");
		shutdown_early(p, fd);
		return;
	} else if (res <= 0)
		return;

	p->outbuf_size -= res;
	if (p->outbuf_size <= 0)
		event_del(&p->ev2w);
}

void
peer_fn1r(const int fd, const short events, void *const arg)
{
	struct peer	*const p = arg;
	int		 res;

	if ((events & EV_READ) != EV_READ) {
		warnx("bad event");
		return;
	} else if (p->outbuf_size < 0) {
		shutdown_local(p, fd);
		return;
	}

	res = (int)recv(fd,
	    p->outbuf + p->outbuf_size,
	    sizeof(p->outbuf) - p->outbuf_size,
	    MSG_DONTWAIT);
	if (res == 0 || (res < 0 && errno != EAGAIN)) {
		if (res < 0)
			warn("recv");
		shutdown_local(p, fd);
		return;
	} else if (res <= 0)
		return;

	if (p->outbuf_size <= 0)
		event_add(&p->ev2w, NULL);
	p->outbuf_size += res;
	if (p->outbuf_size >= (int)sizeof p->outbuf)
		event_del(&p->ev1r);
}

void
peer_fn1w(const int fd, const short events, void *const arg)
{
	struct peer	*const p = arg;
	int		 res;

	if ((events & EV_WRITE) != EV_WRITE) {
		warnx("bad event");
		return;
	}

	res = (int)send(fd, p->inbuf, p->inbuf_size, MSG_DONTWAIT);
	if (res == 0 || (res < 0 && errno != EAGAIN)) {
		if (res < 0)
			warn("send");
		shutdown_local(p, fd);
		return;
	} else if (res <= 0)
		return;

	if (p->inbuf_size >= (int)sizeof p->inbuf)
		event_add(&p->ev2r, NULL);
	p->inbuf_size -= res;
	memmove(p->inbuf, p->inbuf + res, p->inbuf_size);
	if (p->inbuf_size <= 0) {
		if (p->outbuf_size < 0)
			shutdown_local(p, fd);
		else
			event_del(&p->ev1w);
	}
}

void
peer_fn2r(const int fd, const short events, void *const arg)
{
	struct peer	*const p = arg;
	int		 res;

	if ((events & EV_READ) != EV_READ) {
		warnx("bad event");
		return;
	} else if (p->inbuf_size < 0) {
		shutdown_target(p, fd);
		return;
	}

	res = (int)recv(fd,
	    p->inbuf + p->inbuf_size,
	    sizeof(p->inbuf) - p->inbuf_size,
	    MSG_DONTWAIT);
	if (res == 0 || (res < 0 && errno != EAGAIN)) {
		if (res < 0)
			warn("recv");
		shutdown_target(p, fd);
		return;
	} else if (res <= 0)
		return;

	if (p->inbuf_size <= 0)
		event_add(&p->ev1w, NULL);
	p->inbuf_size += res;
	if (p->inbuf_size >= (int)sizeof p->inbuf)
		event_del(&p->ev2r);
}

void
peer_fn2w(const int fd, const short events, void *const arg)
{
	struct peer	*const p = arg;
	int		 res;

	if ((events & EV_WRITE) != EV_WRITE) {
		warnx("bad event");
		return;
	}

	res = (int)send(fd, p->outbuf, p->outbuf_size, MSG_DONTWAIT);
	if (res == 0 || (res < 0 && errno != EAGAIN)) {
		warn("send");
		shutdown_target(p, fd);
		return;
	} else if (res <= 0)
		return;

	if (p->outbuf_size >= (int)sizeof p->outbuf)
		event_add(&p->ev1r, NULL);
	p->outbuf_size -= res;
	memmove(p->outbuf, p->outbuf + res, p->outbuf_size);
	if (p->outbuf_size <= 0) {
		if (p->inbuf_size < 0)
			shutdown_target(p, fd);
		else
			event_del(&p->ev2w);
	}
}

void
shutdown_early(struct peer *const p, const int s)
{
	event_del(&p->ev2r);
	event_del(&p->ev2w);
	close(s);
	p->next = peers_free;
	peers_free = p;
	for (int i = 0; i < listeners_count; ++i)
		event_add(&listeners[i], NULL);
}

void
shutdown_local(struct peer *const p, const int s)
{
	if (p->inbuf_size > 0)
		warnx("local is broken: could not deliver %d bytes",
		    p->inbuf_size);
	event_del(&p->ev1r);
	event_del(&p->ev1w);
	close(s);
	if (p->outbuf_size < 0) {
		if (peers_free == NULL)
			for (int i = 0; i < listeners_count; ++i)
				event_add(&listeners[i], NULL);
		p->next = peers_free;
		peers_free = p;
	} else {
		if (p->inbuf_size >= (int)sizeof p->inbuf)
			event_add(&p->ev2r, NULL);
		p->inbuf_size = -1;
	}
}

void
shutdown_target(struct peer *const p, const int s)
{
	if (p->outbuf_size > 0)
		warnx("target is broken: could not send %d bytes",
		    p->outbuf_size);
	event_del(&p->ev2r);
	event_del(&p->ev2w);
	close(s);
	if (p->inbuf_size < 0) {
		if (peers_free == NULL)
			for (int i = 0; i < listeners_count; ++i)
				event_add(&listeners[i], NULL);
		p->next = peers_free;
		peers_free = p;
	} else {
		if (p->outbuf_size >= (int)sizeof p->outbuf)
			event_add(&p->ev1r, NULL);
		p->outbuf_size = -1;
	}
}
