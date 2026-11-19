/*
 * mayhem/netshim.c — a mock network for running the iputils tools' real main() on a file.
 *
 * Every socket call the tools make is linked to a __wrap_* here (-Wl,--wrap=<sym>, see build.sh).
 * Sockets are eventfd descriptors nobody signals; what they "receive" comes from the input file, so the bytes the
 * fuzzer writes are exactly what the tool would read from the network. Sending succeeds and keeps a
 * copy of the last packet sent. Time is virtual (it moves only when the tool waits), the pid, uid and
 * random bytes are fixed: the same input always produces the same run and the same output.
 *
 * Only libc / kernel interfaces are mocked; no iputils function is replaced.
 *
 * Input records (after the per-tool prefix fuzz_main.c consumes):
 *   u8 flags, u16 len (little endian), len bytes
 * The bytes are consumed in this order, each part only when its flag is set:
 *   NS_TS    4 bytes: u32 (little endian) arrival delay in microseconds. The virtual clock moves on
 *            by it and the SOL_SOCKET/SO_TIMESTAMP cmsg carries the new virtual time, as the kernel
 *            stamps it with its own clock (a remote host cannot choose the receive time).
 *   NS_ERR   16 bytes: u32 errno, u8 origin, u8 ICMP type, u8 ICMP code, u8 unused, u32 info,
 *            u8 ICMP length field (RFC 4884), 3 unused; then 16 bytes offender address (4 used for
 *            IPv4) -> IP_RECVERR / IPV6_RECVERR cmsg; the record is only returned to MSG_ERRQUEUE reads.
 *            The struct sock_extended_err is shaped as the kernel writes it (see make_ee()): only what
 *            a remote host controls (type, code, the IPv6 Packet Too Big MTU, the ICMP length field and
 *            the quoted datagram) is free; errno, origin, ee_pad and the 16-bit IPv4 ee_info are kept
 *            in the kernel's range, and ee_rfc4884 is computed from the length field and the datagram.
 *   NS_HOPS  1 byte: the received TTL / hop limit (0..255) -> IP_TTL / IPV6_HOPLIMIT cmsg (an int,
 *            as the kernel delivers it)
 *   NS_PORT  2 bytes: source port (network order) of the sender address
 *   NS_LL    20 bytes: struct sockaddr_ll of the sender (AF_PACKET sockets)
 *   the rest: the datagram itself
 *   NS_COPYID: after copying, bytes 4..8 of the last packet sent (ICMP identifier and sequence) are
 *            copied over the same offsets of the reply, past the IPv4 header on raw IPv4 sockets;
 *   NS_COPYNONCE: the same for bytes 4..16 (identifier, sequence, ICMPv6 node-information nonce).
 *   NS_ANYTIME: the record is unsolicited (a duplicate, a redirect): it may arrive while no request
 *            is outstanding. Other records arrive only after the request they answer was sent.
 * Sending on an IP socket fails with EMSGSIZE, before the buffer is touched, when the datagram is
 * longer than 65535 bytes (the kernel's limit), like a real send would.
 * When the records run out, the tool sees what it would see on a silent network: reads return
 * EAGAIN and waits time out. If the tool's run declares NETSHIM_EOF_SIGINT, the user presses Ctrl-C
 * once instead (ping's documented way to stop and print statistics).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "netshim.h"

#define NS_TS     0x01
#define NS_ERR    0x02
#define NS_HOPS   0x04
#define NS_PORT   0x08
#define NS_LL     0x10
#define NS_COPYID 0x20
#define NS_ANYTIME 0x40
#define NS_COPYNONCE 0x80
#define STALL_MAX 64

#define MAXFD 1024
#define REALTIME_BASE 1700000000LL

static const uint8_t *in_buf;
static size_t in_len, in_pos;
static int eof_mode;
static int eof_signalled;
static int refused;
static unsigned long sent_count, delivered_count, stall;

static int64_t vt_ns;			/* virtual time since start */

static uint8_t last_sent[4096];
static size_t last_sent_len;
static uint32_t rnd_state = 0x12345678;

struct fake {
	int used;
	int family, type, proto;
	struct sockaddr_storage peer;
	socklen_t peerlen;
	int timerfd;
	int64_t timer_due, timer_interval;
	int64_t rcvtimeo_ms;	/* SO_RCVTIMEO, -1 = block forever */
	int rfc4884;		/* IP_RECVERR_RFC4884 / IPV6_RECVERR_RFC4884 enabled */
};

#ifndef IP_RECVERR_RFC4884
#define IP_RECVERR_RFC4884 26
#endif
#ifndef IPV6_RECVERR_RFC4884
#define IPV6_RECVERR_RFC4884 31
#endif
#ifndef SO_EE_RFC4884_FLAG_INVALID
#define SO_EE_RFC4884_FLAG_INVALID 1
#endif
#define IP_MAX_DGRAM 65535
static struct fake fakes[MAXFD];

void netshim_init(const uint8_t *data, size_t len, int mode)
{
	in_buf = data;
	in_len = len;
	in_pos = 0;
	eof_mode = mode;
}

static struct fake *fake_of(int fd)
{
	if (fd < 0 || fd >= MAXFD || !fakes[fd].used)
		return NULL;
	return &fakes[fd];
}

/* ---- time ---- */
static void advance_ms(int64_t ms)
{
	if (ms > 0)
		vt_ns += ms * 1000000LL;
}

int __wrap_gettimeofday(struct timeval *tv, void *tz)
{
	(void)tz;
	if (tv) {
		tv->tv_sec = REALTIME_BASE + vt_ns / 1000000000LL;
		tv->tv_usec = (vt_ns % 1000000000LL) / 1000;
	}
	return 0;
}

int __wrap_clock_gettime(clockid_t clk, struct timespec *ts)
{
	int64_t base = (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE) ? REALTIME_BASE : 1000;
	ts->tv_sec = base + vt_ns / 1000000000LL;
	ts->tv_nsec = vt_ns % 1000000000LL;
	return 0;
}

time_t __wrap_time(time_t *t)
{
	time_t now = REALTIME_BASE + vt_ns / 1000000000LL;
	if (t)
		*t = now;
	return now;
}

/* Interval timers are accepted and never fire: a run ends when its packets do (see the header),
 * not on a timer. */
int __wrap_setitimer(int which, const struct itimerval *nv, struct itimerval *ov)
{
	(void)which; (void)nv;
	if (ov)
		memset(ov, 0, sizeof(*ov));
	return 0;
}

unsigned int __wrap_alarm(unsigned int s)
{
	(void)s;
	return 0;
}

int __wrap_nanosleep(const struct timespec *req, struct timespec *rem)
{
	if (req)
		vt_ns += req->tv_sec * 1000000000LL + req->tv_nsec;
	if (rem)
		memset(rem, 0, sizeof(*rem));
	return 0;
}

int __wrap_usleep(useconds_t us)
{
	vt_ns += (int64_t)us * 1000;
	return 0;
}

unsigned int __wrap_sleep(unsigned int s)
{
	vt_ns += (int64_t)s * 1000000000LL;
	return 0;
}

/* ---- identity / randomness ---- */
pid_t __wrap_getpid(void) { return 4242; }
uid_t __wrap_getuid(void) { return 0; }
uid_t __wrap_geteuid(void) { return 0; }
int __wrap_setuid(uid_t u) { (void)u; return 0; }
int __wrap_seteuid(uid_t u) { (void)u; return 0; }
int __wrap_nice(int inc) { (void)inc; return 0; }

ssize_t __wrap_getrandom(void *buf, size_t n, unsigned int flags)
{
	(void)flags;
	for (size_t i = 0; i < n; i++) {
		rnd_state = rnd_state * 1103515245u + 12345u;
		((uint8_t *)buf)[i] = rnd_state >> 24;
	}
	return n;
}

/* ---- name resolution: numeric only, nothing leaves the process ---- */
int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int __wrap_getaddrinfo(const char *node, const char *svc, const struct addrinfo *hints,
		       struct addrinfo **res)
{
	struct addrinfo h;

	if (hints)
		h = *hints;
	else {
		memset(&h, 0, sizeof(h));
		h.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
	}
	h.ai_flags |= AI_NUMERICHOST;
	h.ai_flags &= ~(AI_ADDRCONFIG
#ifdef AI_IDN
			| AI_IDN
#endif
			);
	return __real_getaddrinfo(node, svc, &h, res);
}

int __real_getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
int __wrap_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen,
		       char *serv, socklen_t servlen, int flags)
{
	return __real_getnameinfo(sa, salen, host, hostlen, serv, servlen,
				  (flags & ~NI_NAMEREQD) | NI_NUMERICHOST | NI_NUMERICSERV);
}

/* ---- sockets ---- */
int __real_close(int);

static int new_fake(int family, int type, int proto)
{
	int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

	if (fd < 0)
		return -1;
	if (fd >= MAXFD) {
		__real_close(fd);
		errno = EMFILE;
		return -1;
	}
	memset(&fakes[fd], 0, sizeof(fakes[fd]));
	fakes[fd].used = 1;
	fakes[fd].family = family;
	fakes[fd].type = type & 0xf;
	fakes[fd].proto = proto;
	fakes[fd].rcvtimeo_ms = -1;
	return fd;
}

int __wrap_socket(int family, int type, int proto)
{
	int t = type & 0xf;

	/* No unprivileged ICMP "ping sockets" here: ping falls back to a raw socket, the path that
	 * receives (and parses) the whole IP packet. */
	if (t == SOCK_DGRAM && (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)) {
		errno = EACCES;
		return -1;
	}
	if (family == AF_NETLINK) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	return new_fake(family, type, proto);
}

int __wrap_close(int fd)
{
	if (fd >= 0 && fd < MAXFD)
		fakes[fd].used = 0;
	return __real_close(fd);
}

int __real_setsockopt(int, int, int, const void *, socklen_t);
int __wrap_setsockopt(int fd, int lvl, int name, const void *v, socklen_t l)
{
	struct fake *f = fake_of(fd);

	if (!f)
		return __real_setsockopt(fd, lvl, name, v, l);
	if (lvl == SOL_SOCKET && name == SO_RCVTIMEO && v && l >= sizeof(struct timeval)) {
		const struct timeval *tv = v;
		f->rcvtimeo_ms = tv->tv_sec * 1000 + tv->tv_usec / 1000;
		if (f->rcvtimeo_ms == 0)
			f->rcvtimeo_ms = -1;
	}
	if (((lvl == SOL_IP && name == IP_RECVERR_RFC4884) ||
	     (lvl == SOL_IPV6 && name == IPV6_RECVERR_RFC4884)) && v && l >= sizeof(int))
		f->rfc4884 = *(const int *)v != 0;
	return 0;
}

int __real_getsockopt(int, int, int, void *, socklen_t *);
int __wrap_getsockopt(int fd, int lvl, int name, void *v, socklen_t *l)
{
	if (!fake_of(fd))
		return __real_getsockopt(fd, lvl, name, v, l);
	if (v && l)
		memset(v, 0, *l);
	if (v && l && *l >= sizeof(int))
		*(int *)v = (lvl == SOL_SOCKET && (name == SO_RCVBUF || name == SO_SNDBUF)) ? 212992 : 0;
	return 0;
}

int __real_bind(int, const struct sockaddr *, socklen_t);
int __wrap_bind(int fd, const struct sockaddr *a, socklen_t l)
{
	struct fake *f = fake_of(fd);

	if (!f)
		return __real_bind(fd, a, l);
	if (f->family == AF_PACKET && a && l <= sizeof(f->peer)) {
		memcpy(&f->peer, a, l);
		f->peerlen = l;
	}
	return 0;
}

int __real_connect(int, const struct sockaddr *, socklen_t);
int __wrap_connect(int fd, const struct sockaddr *a, socklen_t l)
{
	struct fake *f = fake_of(fd);

	if (!f)
		return __real_connect(fd, a, l);
	if (a && l <= sizeof(f->peer)) {
		memcpy(&f->peer, a, l);
		f->peerlen = l;
	}
	return 0;
}

static socklen_t local_addr(struct fake *f, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof(*ss));
	if (f->family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(40000);
		s6->sin6_addr = in6addr_loopback;
		return sizeof(*s6);
	}
	if (f->family == AF_PACKET) {
		struct sockaddr_ll *ll = (struct sockaddr_ll *)ss;
		ll->sll_family = AF_PACKET;
		ll->sll_ifindex = 1;
		ll->sll_hatype = 1;	/* ARPHRD_ETHER */
		ll->sll_halen = 6;
		memcpy(ll->sll_addr, "\x02\x00\x00\x00\x00\x01", 6);
		if (f->peerlen >= sizeof(struct sockaddr_ll)) {
			const struct sockaddr_ll *b = (const struct sockaddr_ll *)&f->peer;
			ll->sll_protocol = b->sll_protocol;
			ll->sll_ifindex = b->sll_ifindex;
		}
		return sizeof(*ll);
	}
	struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
	s4->sin_family = AF_INET;
	s4->sin_port = htons(40000);
	s4->sin_addr.s_addr = htonl(0x7f000001);
	if (f->peerlen >= sizeof(*s4) && f->peer.ss_family == AF_INET &&
	    (ntohl(((struct sockaddr_in *)&f->peer)->sin_addr.s_addr) >> 24) != 127)
		s4->sin_addr.s_addr = htonl(0x0a000002);	/* 10.0.0.2 on eth0 */
	return sizeof(*s4);
}

int __real_getsockname(int, struct sockaddr *, socklen_t *);
int __wrap_getsockname(int fd, struct sockaddr *a, socklen_t *l)
{
	struct fake *f = fake_of(fd);
	struct sockaddr_storage ss;
	socklen_t n;

	if (!f)
		return __real_getsockname(fd, a, l);
	n = local_addr(f, &ss);
	memcpy(a, &ss, *l < n ? *l : n);
	*l = n;
	return 0;
}

int __real_ioctl(int, unsigned long, void *);
int __wrap_ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (!fake_of(fd))
		return __real_ioctl(fd, req, arg);
	errno = ENOTTY;
	return -1;
}

/* The kernel refuses a datagram over 65535 bytes on an IP socket (EMSGSIZE) without reading it. */
static int too_big(struct fake *f, const struct iovec *iov, size_t n)
{
	size_t total = 0;

	if (f->family != AF_INET && f->family != AF_INET6)
		return 0;
	for (size_t i = 0; i < n; i++) {
		if (iov[i].iov_len > IP_MAX_DGRAM - total) {
			errno = EMSGSIZE;
			return 1;
		}
		total += iov[i].iov_len;
	}
	return 0;
}

static void note_sent(struct fake *f, const struct iovec *iov, size_t n, const void *to, socklen_t tolen)
{
	size_t off = 0;

	for (size_t i = 0; i < n && off < sizeof(last_sent); i++) {
		size_t c = iov[i].iov_len;
		if (c > sizeof(last_sent) - off)
			c = sizeof(last_sent) - off;
		memcpy(last_sent + off, iov[i].iov_base, c);
		off += c;
	}
	last_sent_len = off;
	sent_count++;
	if (to && tolen && tolen <= sizeof(f->peer) && f->peerlen == 0) {
		memcpy(&f->peer, to, tolen);
		f->peerlen = tolen;
	}
}

ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *b, size_t n, int fl, const struct sockaddr *to, socklen_t tl)
{
	struct fake *f = fake_of(fd);
	struct iovec iov = { (void *)b, n };

	if (!f)
		return __real_sendto(fd, b, n, fl, to, tl);
	if (too_big(f, &iov, 1))
		return -1;
	note_sent(f, &iov, 1, to, tl);
	return n;
}

ssize_t __real_send(int, const void *, size_t, int);
ssize_t __wrap_send(int fd, const void *b, size_t n, int fl)
{
	struct fake *f = fake_of(fd);
	struct iovec iov = { (void *)b, n };

	if (!f)
		return __real_send(fd, b, n, fl);
	if (too_big(f, &iov, 1))
		return -1;
	note_sent(f, &iov, 1, NULL, 0);
	return n;
}

ssize_t __real_sendmsg(int, const struct msghdr *, int);
ssize_t __wrap_sendmsg(int fd, const struct msghdr *m, int fl)
{
	struct fake *f = fake_of(fd);
	size_t total = 0;

	if (!f)
		return __real_sendmsg(fd, m, fl);
	if (too_big(f, m->msg_iov, m->msg_iovlen))
		return -1;
	note_sent(f, m->msg_iov, m->msg_iovlen, m->msg_name, m->msg_namelen);
	for (size_t i = 0; i < m->msg_iovlen; i++)
		total += m->msg_iov[i].iov_len;
	return total;
}

/* ---- input records ---- */
struct rec {
	int flags;
	const uint8_t *data;
	size_t len;
	size_t next;	/* in_pos after this record */
};

static int peek(struct rec *r)
{
	size_t len;

	if (in_pos + 3 > in_len)
		return 0;
	r->flags = in_buf[in_pos];
	len = in_buf[in_pos + 1] | (in_buf[in_pos + 2] << 8);
	if (len > in_len - in_pos - 3)
		len = in_len - in_pos - 3;
	r->data = in_buf + in_pos + 3;
	r->len = len;
	r->next = in_pos + 3 + len;
	return 1;
}

/* A reply arrives after a request: a record is due only while fewer records were delivered than
 * packets sent, unless it is flagged NS_ANYTIME (unsolicited, duplicate) or the tool has waited
 * STALL_MAX times for it (it arrives late). */
static int deliverable(void)
{
	struct rec r;

	if (!peek(&r))
		return 0;
	return (r.flags & NS_ANYTIME) || delivered_count < sent_count || stall >= STALL_MAX;
}

static const uint8_t *take(struct rec *r, size_t n, uint8_t *tmp)
{
	size_t c = r->len < n ? r->len : n;

	memset(tmp, 0, n);
	memcpy(tmp, r->data, c);
	r->data += c;
	r->len -= c;
	return tmp;
}

/* Nothing (left) to receive. */
static ssize_t no_data(void)
{
	if (eof_mode == NETSHIM_EOF_SIGINT && !eof_signalled) {
		eof_signalled = 1;
		raise(SIGINT);
		errno = EINTR;
		return -1;
	}
	errno = EAGAIN;
	return -1;
}

static void *add_cmsg(struct msghdr *m, size_t *used, int lvl, int type, const void *d, size_t n)
{
	struct cmsghdr *c;

	if (!m->msg_control || *used + CMSG_SPACE(n) > m->msg_controllen)
		return NULL;
	c = (struct cmsghdr *)((char *)m->msg_control + *used);
	memset(c, 0, CMSG_SPACE(n));
	c->cmsg_level = lvl;
	c->cmsg_type = type;
	c->cmsg_len = CMSG_LEN(n);
	memcpy(CMSG_DATA(c), d, n);
	*used += CMSG_SPACE(n);
	return CMSG_DATA(c);
}

static socklen_t fill_addr(struct fake *f, struct sockaddr_storage *ss, const uint8_t *addr16, int port)
{
	memset(ss, 0, sizeof(*ss));
	if (f->family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		if (f->peerlen >= sizeof(*s6))
			memcpy(s6, &f->peer, sizeof(*s6));
		s6->sin6_family = AF_INET6;
		if (!f->peerlen)
			s6->sin6_addr = in6addr_loopback;
		if (addr16)
			memcpy(&s6->sin6_addr, addr16, 16);
		if (port >= 0)
			s6->sin6_port = htons(port);
		return sizeof(*s6);
	}
	struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
	if (f->peerlen >= sizeof(*s4))
		memcpy(s4, &f->peer, sizeof(*s4));
	s4->sin_family = AF_INET;
	if (!f->peerlen)
		s4->sin_addr.s_addr = htonl(0x7f000001);
	if (addr16)
		memcpy(&s4->sin_addr, addr16, 4);
	if (port >= 0)
		s4->sin_port = htons(port);
	return sizeof(*s4);
}

static int wait_for_data(int64_t timeout_ms);

/* RFC 4884 extension validation as the kernel does it (ip_icmp_error_rfc4884_validate()): a
 * non-version-2 header is not checked; a version-2 one needs a valid (or zero) checksum and object
 * lengths of at least 4 that fit the datagram. */
static int rfc4884_valid(const uint8_t *d, size_t len, size_t off)
{
	uint32_t sum = 0;

	if ((d[off] >> 4) != 2)
		return 1;
	if (d[off + 2] | d[off + 3]) {
		for (size_t i = off; i < len; i += 2)
			sum += (uint32_t)(d[i] << 8) | (i + 1 < len ? d[i + 1] : 0);
		while (sum >> 16)
			sum = (sum & 0xffff) + (sum >> 16);
		if (sum != 0xffff)
			return 0;
	}
	for (off += 4; off < len;) {
		size_t olen;
		if (off + 4 > len)
			return 0;
		olen = (d[off] << 8) | d[off + 1];
		if (olen < 4)
			return 0;
		off += olen;
		if (off > len)
			return 0;
	}
	return 1;
}

/* struct sock_extended_err as ip_icmp_error()/ipv6_icmp_error()/ip(v6)_local_error() fill it in,
 * from the record's 16 bytes; dgram/dlen is the quoted datagram the error-queue read returns. */
static void make_ee(struct fake *f, const uint8_t *in, const uint8_t *dgram, size_t dlen,
		    struct sock_extended_err *e)
{
	int v6 = f->family == AF_INET6;
	uint32_t err, info;

	memset(e, 0, sizeof(*e));
	memcpy(&err, in, 4);
	memcpy(&info, in + 8, 4);
	e->ee_errno = err % 134;	/* a kernel errno (EHWPOISON = 133 is the largest) */
	e->ee_origin = in[4];
	if (e->ee_origin != SO_EE_ORIGIN_LOCAL && e->ee_origin != SO_EE_ORIGIN_ICMP &&
	    !(v6 && e->ee_origin == SO_EE_ORIGIN_ICMP6))
		e->ee_origin = v6 ? SO_EE_ORIGIN_ICMP6 : SO_EE_ORIGIN_ICMP;
	if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
		/* a local error: the path MTU, a 16-bit value; no ICMP type/code */
		e->ee_info = info & 0xffff;
		return;
	}
	e->ee_type = in[5];
	e->ee_code = in[6];
	/* IPv4: the 16-bit frag-needed MTU or the 8-bit parameter-problem pointer; IPv6: the 32-bit
	 * Packet Too Big MTU or parameter-problem pointer, straight from the ICMPv6 header. */
	e->ee_info = v6 ? info : (info & 0xffff);
	if (!f->rfc4884)
		return;
	if (v6 ? !(e->ee_origin == SO_EE_ORIGIN_ICMP6 &&
		   (e->ee_type == 1 /* DEST_UNREACH */ || e->ee_type == 3 /* TIME_EXCEED */))
	       : !(e->ee_type == 3 /* DEST_UNREACH */ || e->ee_type == 11 /* TIME_EXCEEDED */ ||
		   e->ee_type == 12 /* PARAMETERPROB */))
		return;
	{
		/* ip_icmp_error_rfc4884(): the ICMP length field counts 32-bit (IPv4) / 64-bit (IPv6)
		 * words of the original datagram, whose IP and transport headers the kernel strips. */
		size_t off = (size_t)in[12] * (v6 ? 8 : 4);
		size_t hlen = (v6 ? 40 : 20) + (f->type == SOCK_RAW ? 0 : 8);
		if (off < 128 || off < hlen)
			return;
		off -= hlen;
		if (off + 4 > dlen)
			return;
		e->ee_rfc4884.len = off;
		if (!rfc4884_valid(dgram, dlen, off))
			e->ee_rfc4884.flags |= SO_EE_RFC4884_FLAG_INVALID;
	}
}

static ssize_t deliver(struct fake *f, struct msghdr *m, int flags)
{
	struct rec r;
	uint8_t tmp[32];
	size_t used = 0, copied = 0, avail;
	struct sockaddr_storage from;
	socklen_t fromlen;
	int port = -1;
	int v6 = f->family == AF_INET6;
	uint8_t ee_raw[16];
	void *ee = NULL;

	if (!peek(&r))
		return no_data();
	if (!deliverable()) {
		/* A blocking read waits (up to SO_RCVTIMEO) like poll() would. */
		if (flags & MSG_DONTWAIT) {
			stall++;
			errno = EAGAIN;
			return -1;
		}
		int w = wait_for_data(f->rcvtimeo_ms);
		if (w < 0)
			return -1;
		if (w == 0) {
			errno = EAGAIN;
			return -1;
		}
		peek(&r);
	}
	if ((r.flags & NS_ERR) && !(flags & MSG_ERRQUEUE)) {
		/* An ICMP error is pending: a plain read reports it as errno, the data stays on the
		 * error queue. A tool that never reads the queue sees the error once more, then it is gone. */
		if (++refused > 2) {
			in_pos = r.next;
			refused = 0;
		}
		errno = EHOSTUNREACH;
		return -1;
	}
	if (!(r.flags & NS_ERR) && (flags & MSG_ERRQUEUE)) {
		errno = EAGAIN;
		return -1;
	}
	refused = 0;
	stall = 0;
	if (!(r.flags & NS_ANYTIME))
		delivered_count++;
	in_pos = r.next;

	if (r.flags & NS_TS) {
		/* The kernel stamps SO_TIMESTAMP with its own clock when the packet arrives; a remote
		 * host cannot set it. The record only chooses how long after now the packet arrives
		 * (u32 microseconds): the virtual clock moves on by that much and the cmsg carries
		 * the new virtual time, normalised like the kernel's (tv_usec in 0..999999). */
		const uint8_t *p = take(&r, 4, tmp);
		uint32_t delay_us;
		struct timeval tv;
		memcpy(&delay_us, p, 4);
		vt_ns += (int64_t)delay_us * 1000;
		__wrap_gettimeofday(&tv, NULL);
		add_cmsg(m, &used, SOL_SOCKET, SO_TIMESTAMP, &tv, sizeof(tv));
	}
	if (r.flags & NS_ERR) {
		uint8_t buf[sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in6)];
		uint8_t raw[16];
		struct sockaddr_storage off;
		socklen_t offlen;
		memcpy(raw, take(&r, 16, tmp), 16);
		offlen = fill_addr(f, &off, take(&r, 16, tmp), 0);
		memcpy(buf + 16, &off, offlen);
		memcpy(ee_raw, raw, 16);
		memset(buf, 0, 16);	/* filled in by make_ee() once the datagram is known */
		ee = add_cmsg(m, &used, v6 ? SOL_IPV6 : SOL_IP, v6 ? IPV6_RECVERR : IP_RECVERR, buf, 16 + offlen);
	}
	if (r.flags & NS_HOPS) {
		int h = *take(&r, 1, tmp);
		add_cmsg(m, &used, v6 ? SOL_IPV6 : SOL_IP, v6 ? IPV6_HOPLIMIT : IP_TTL, &h, sizeof(h));
	}
	if (r.flags & NS_PORT) {
		const uint8_t *p = take(&r, 2, tmp);
		port = (p[0] << 8) | p[1];
	}
	if (f->family == AF_PACKET) {
		struct sockaddr_ll ll;
		memset(&from, 0, sizeof(from));
		local_addr(f, &from);
		if (r.flags & NS_LL) {
			memcpy(&ll, take(&r, sizeof(ll), tmp), sizeof(ll));
			ll.sll_family = AF_PACKET;
			memcpy(&from, &ll, sizeof(ll));
		}
		fromlen = sizeof(struct sockaddr_ll);
	} else {
		fromlen = fill_addr(f, &from, NULL, port);
	}

	if (ee) {
		struct sock_extended_err e;
		make_ee(f, ee_raw, r.data, r.len, &e);
		memcpy(ee, &e, sizeof(e));
	}
	for (size_t i = 0; i < m->msg_iovlen && r.len; i++) {
		size_t c = m->msg_iov[i].iov_len < r.len ? m->msg_iov[i].iov_len : r.len;
		memcpy(m->msg_iov[i].iov_base, r.data, c);
		r.data += c;
		r.len -= c;
		copied += c;
	}
	if ((r.flags & (NS_COPYID | NS_COPYNONCE)) && m->msg_iovlen && last_sent_len > 4) {
		uint8_t *pkt = m->msg_iov[0].iov_base;
		size_t off = 0;
		avail = m->msg_iov[0].iov_len < copied ? m->msg_iov[0].iov_len : copied;
		if (f->family == AF_INET && f->type == SOCK_RAW && avail >= 20)
			off = (pkt[0] & 0xf) * 4;
		size_t from = 4, to = 8;
		if (r.flags & NS_COPYNONCE)
			to = 16;
		for (size_t i = from; i < to && i < last_sent_len && off + i < avail; i++)
			pkt[off + i] = last_sent[i];
	}
	if (m->msg_name) {
		socklen_t n = m->msg_namelen < fromlen ? m->msg_namelen : fromlen;
		memcpy(m->msg_name, &from, n);
		m->msg_namelen = fromlen;
	}
	m->msg_controllen = used;
	m->msg_flags = (r.flags & NS_ERR) ? MSG_ERRQUEUE : 0;
	return copied;
}

ssize_t __real_recvmsg(int, struct msghdr *, int);
ssize_t __wrap_recvmsg(int fd, struct msghdr *m, int fl)
{
	struct fake *f = fake_of(fd);

	if (!f)
		return __real_recvmsg(fd, m, fl);
	return deliver(f, m, fl);
}

ssize_t __real_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t __wrap_recvfrom(int fd, void *b, size_t n, int fl, struct sockaddr *a, socklen_t *al)
{
	struct fake *f = fake_of(fd);
	struct iovec iov = { b, n };
	struct msghdr m;
	ssize_t r;

	if (!f)
		return __real_recvfrom(fd, b, n, fl, a, al);
	memset(&m, 0, sizeof(m));
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_name = a;
	m.msg_namelen = al ? *al : 0;
	r = deliver(f, &m, fl);
	if (r >= 0 && al)
		*al = m.msg_namelen;
	return r;
}

ssize_t __real_recv(int, void *, size_t, int);
ssize_t __wrap_recv(int fd, void *b, size_t n, int fl)
{
	if (!fake_of(fd))
		return __real_recv(fd, b, n, fl);
	return __wrap_recvfrom(fd, b, n, fl, NULL, NULL);
}

/* ---- waiting ---- */
static int pending_err(void)
{
	struct rec r;
	return peek(&r) && (r.flags & NS_ERR);
}

static int have_data(void)
{
	struct rec r;
	return peek(&r);
}

/* A wait of timeout_ms (-1 = forever) on fake sockets: returns 1 when a record is ready, else 0 after
 * moving virtual time; -1/EINTR when an alarm or the end-of-input Ctrl-C interrupts it. */
static int wait_for_data(int64_t timeout_ms)
{
	int ready = deliverable();
	int64_t step;

	if (ready) {
		step = timeout_ms != 0;	/* the packet arrives right away */
	} else if (!have_data() && eof_mode == NETSHIM_EOF_SIGINT && !eof_signalled) {
		eof_signalled = 1;
		raise(SIGINT);
		errno = EINTR;
		return -1;
	} else {
		if (have_data())
			stall++;
		step = timeout_ms < 0 ? 1000 : timeout_ms;
	}
	advance_ms(step);
	return ready;
}

int __real_poll(struct pollfd *, nfds_t, int);
int __wrap_poll(struct pollfd *p, nfds_t n, int timeout)
{
	int any = 0, ready = 0, w;
	int64_t due = -1;

	for (nfds_t i = 0; i < n; i++) {
		struct fake *f = fake_of(p[i].fd);
		if (!f)
			continue;
		any = 1;
		if (f->timerfd == 1 && f->timer_due > 0 && (due < 0 || f->timer_due < due))
			due = f->timer_due;
	}
	if (!any)
		return __real_poll(p, n, timeout);
	/* A timer that expires during the wait ends it. */
	if (due >= 0 && !deliverable()) {
		int64_t left = due > vt_ns ? (due - vt_ns + 999999) / 1000000 : 0;
		if (timeout < 0 || left < timeout)
			timeout = left;
	}
	w = wait_for_data(timeout);
	if (w < 0)
		return -1;
	for (nfds_t i = 0; i < n; i++) {
		struct fake *f = fake_of(p[i].fd);
		p[i].revents = 0;
		if (f && f->timerfd) {
			if (f->timerfd == 1 && f->timer_due > 0 && vt_ns >= f->timer_due)
				p[i].revents = POLLIN;
		} else if (f && w > 0) {
			p[i].revents = (p[i].events & POLLIN) | (pending_err() ? POLLERR : 0);
		}
		if (p[i].revents)
			ready++;
	}
	return ready;
}

int __wrap_ppoll(struct pollfd *p, nfds_t n, const struct timespec *t, const sigset_t *s)
{
	(void)s;
	return __wrap_poll(p, n, t ? (int)(t->tv_sec * 1000 + t->tv_nsec / 1000000) : -1);
}

int __real_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int __wrap_select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
{
	int any = 0, ready = 0, res;

	for (int fd = 0; fd < nfds && fd < MAXFD; fd++)
		if (r && FD_ISSET(fd, r) && fake_of(fd))
			any = 1;
	if (!any)
		return __real_select(nfds, r, w, e, tv);
	res = wait_for_data(tv ? tv->tv_sec * 1000 + tv->tv_usec / 1000 : -1);
	if (res < 0)
		return -1;
	for (int fd = 0; fd < nfds && fd < MAXFD; fd++) {
		if (!r || !FD_ISSET(fd, r))
			continue;
		if (fake_of(fd) && res > 0)
			ready++;
		else
			FD_CLR(fd, r);
	}
	if (w)
		FD_ZERO(w);
	if (e)
		FD_ZERO(e);
	return ready;
}

/* ---- arping: one Ethernet interface, timerfd/signalfd on virtual time ---- */
int __wrap_timerfd_create(int clk, int fl)
{
	(void)clk; (void)fl;
	int fd = new_fake(AF_UNSPEC, 0, 0);
	if (fd >= 0)
		fakes[fd].timerfd = 1;
	return fd;
}

int __wrap_timerfd_settime(int fd, int fl, const struct itimerspec *nv, struct itimerspec *ov)
{
	struct fake *f = fake_of(fd);
	(void)fl;
	if (!f || !f->timerfd) {
		errno = EINVAL;
		return -1;
	}
	if (ov)
		memset(ov, 0, sizeof(*ov));
	int64_t v = nv->it_value.tv_sec * 1000000000LL + nv->it_value.tv_nsec;
	f->timer_due = v ? vt_ns + v : 0;
	f->timer_interval = nv->it_interval.tv_sec * 1000000000LL + nv->it_interval.tv_nsec;
	return 0;
}

int __wrap_signalfd(int fd, const sigset_t *mask, int fl)
{
	(void)mask; (void)fl;
	if (fd != -1)
		return fd;
	fd = new_fake(AF_UNSPEC, 0, 0);
	if (fd >= 0)
		fakes[fd].timerfd = 2;	/* never readable: nobody sends a signal */
	return fd;
}

ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *b, size_t n)
{
	struct fake *f = fake_of(fd);
	uint64_t exp;

	if (!f)
		return __real_read(fd, b, n);
	if (f->timerfd != 1 || f->timer_due <= 0 || vt_ns < f->timer_due || n < sizeof(exp)) {
		errno = EAGAIN;
		return -1;
	}
	exp = 1;
	if (f->timer_interval > 0) {
		exp += (vt_ns - f->timer_due) / f->timer_interval;
		f->timer_due += exp * f->timer_interval;
	} else {
		f->timer_due = 0;
	}
	memcpy(b, &exp, sizeof(exp));
	return sizeof(exp);
}

static struct sockaddr_ll ll_addr[2], ll_brd[2];
static struct ifaddrs ifas[2];

int __wrap_getifaddrs(struct ifaddrs **res)
{
	static const char *const names[2] = { "lo", "eth0" };

	memset(ifas, 0, sizeof(ifas));
	for (int i = 0; i < 2; i++) {
		memset(&ll_addr[i], 0, sizeof(ll_addr[i]));
		ll_addr[i].sll_family = AF_PACKET;
		ll_addr[i].sll_ifindex = i + 1;
		ll_addr[i].sll_hatype = i ? 1 : 772;	/* ARPHRD_ETHER / ARPHRD_LOOPBACK */
		ll_addr[i].sll_halen = 6;
		ll_brd[i] = ll_addr[i];
		if (i) {
			memcpy(ll_addr[i].sll_addr, "\x02\x00\x00\x00\x00\x01", 6);
			memset(ll_brd[i].sll_addr, 0xff, 6);
		}
		ifas[i].ifa_name = (char *)names[i];
		ifas[i].ifa_flags = i ? (IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST)
				      : (IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
		ifas[i].ifa_addr = (struct sockaddr *)&ll_addr[i];
		ifas[i].ifa_broadaddr = (struct sockaddr *)&ll_brd[i];
		ifas[i].ifa_next = i ? NULL : &ifas[1];
	}
	*res = ifas;
	return 0;
}

void __wrap_freeifaddrs(struct ifaddrs *ifa)
{
	(void)ifa;	/* static */
}

unsigned int __wrap_if_nametoindex(const char *name)
{
	if (!strcmp(name, "lo"))
		return 1;
	if (!strcmp(name, "eth0"))
		return 2;
	errno = ENODEV;
	return 0;
}
