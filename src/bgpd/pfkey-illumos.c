/*	$OpenBSD: pfkey.c,v 1.62 2022/02/06 09:51:19 claudio Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2003, 2004 Markus Friedl <markus@openbsd.org>
 * Copyright 2024, the University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "bgpd.h"
#include "session.h"
#include "log.h"

extern struct bgpd_sysdep sysdep;

#define	PFKEY2_CHUNK sizeof(uint64_t)
#define	ROUNDUP(x) roundup((x), PFKEY2_CHUNK)
#define	IOV_CNT	20

static uint32_t	sadb_mseq = 0;
static uint32_t	pid = 0; /* should pid_t but pfkey needs uint32_t */
static int		pfkey_fd;

int	pfkey_reply(int, uint32_t *);
int	pfkey_send(int, uint8_t, uint8_t, uint8_t,
	    struct bgpd_addr *, struct bgpd_addr *,
	    uint32_t, uint8_t, int, char *, uint8_t, int, char *,
	    uint16_t, uint16_t);

#define pfkey_flow(fd, satype, cmd, dir, from, to, sport, dport) \
	pfkey_send(fd, satype, cmd, dir, from, to, \
	    0, 0, 0, NULL, 0, 0, NULL, sport, dport)

static struct bgpd_addr *
pfkey_localaddr(struct peer *p)
{
	switch (p->conf.remote_addr.aid) {
	case AID_INET:
		return &p->conf.local_addr_v4;
	case AID_INET6:
		return &p->conf.local_addr_v6;
	}
	fatalx("Unknown AID in pfkey_localaddr");
}

int
pfkey_send(int sd, uint8_t satype, uint8_t mtype, uint8_t dir,
    struct bgpd_addr *src, struct bgpd_addr *dst, uint32_t spi,
    uint8_t aalg, int alen, char *akey, uint8_t ealg, int elen, char *ekey,
    uint16_t sport, uint16_t dport)
{
	struct sadb_msg		smsg;
	struct sadb_sa		sa;
	struct sadb_address	sa_src, sa_dst;
	struct sockaddr_storage	ssrc, sdst;
	struct sadb_key		sa_akey;
	struct sadb_spirange	sa_spirange;
	struct iovec		iov[IOV_CNT];
	ssize_t			n;
	int			len = 0;
	int			iov_cnt;
	struct sockaddr		*saptr;
	socklen_t		 salen, srclen = 0, dstlen = 0;

	if (!pid)
		pid = getpid();

	/* we need clean sockaddr... no ports set */
	bzero(&ssrc, sizeof(ssrc));
	if ((saptr = addr2sa(src, 0, &salen))) {
		memcpy(&ssrc, saptr, salen);
		srclen = salen;
	} else {
		srclen = sizeof (struct sockaddr);
	}

	bzero(&sdst, sizeof(sdst));
	if ((saptr = addr2sa(dst, 0, &salen))) {
		memcpy(&sdst, saptr, salen);
		dstlen = salen;
	} else {
		dstlen = sizeof (struct sockaddr);
	}

	bzero(&smsg, sizeof(smsg));
	smsg.sadb_msg_version = PF_KEY_V2;
	smsg.sadb_msg_seq = ++sadb_mseq;
	smsg.sadb_msg_pid = pid;
	smsg.sadb_msg_len = SADB_8TO64(sizeof(smsg));
	smsg.sadb_msg_type = mtype;
	smsg.sadb_msg_satype = satype;

	switch (mtype) {
	case SADB_GETSPI:
		bzero(&sa_spirange, sizeof(sa_spirange));
		sa_spirange.sadb_spirange_exttype = SADB_EXT_SPIRANGE;
		sa_spirange.sadb_spirange_len = SADB_8TO64(sizeof(sa_spirange));
		sa_spirange.sadb_spirange_min = 0x0;
		sa_spirange.sadb_spirange_max = 0xffffffff;
		sa_spirange.sadb_spirange_reserved = 0;
		break;
	case SADB_ADD:
	case SADB_UPDATE:
	case SADB_DELETE:
		bzero(&sa, sizeof(sa));
		sa.sadb_sa_exttype = SADB_EXT_SA;
		sa.sadb_sa_len = SADB_8TO64(sizeof(sa));
		sa.sadb_sa_replay = 0;
		sa.sadb_sa_spi = htonl(spi);
		sa.sadb_sa_state = SADB_SASTATE_MATURE;
		break;
	}

	bzero(&sa_src, sizeof(sa_src));
	sa_src.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	sa_src.sadb_address_len = SADB_8TO64(sizeof(sa_src) + ROUNDUP(srclen));

	bzero(&sa_dst, sizeof(sa_dst));
	sa_dst.sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	sa_dst.sadb_address_len = SADB_8TO64(sizeof(sa_dst) + ROUNDUP(dstlen));

	sa.sadb_sa_auth = aalg;
	sa.sadb_sa_encrypt = ealg;

	switch (mtype) {
	case SADB_ADD:
	case SADB_UPDATE:
		bzero(&sa_akey, sizeof(sa_akey));
		sa_akey.sadb_key_exttype = SADB_X_EXT_STR_AUTH;
		sa_akey.sadb_key_len = SADB_8TO64(sizeof(sa_akey) + ROUNDUP(alen));
		sa_akey.sadb_key_bits = 8 * alen;
		break;
	}

	iov_cnt = 0;

	/* msghdr */
	iov[iov_cnt].iov_base = &smsg;
	iov[iov_cnt].iov_len = sizeof(smsg);
	iov_cnt++;

	switch (mtype) {
	case SADB_ADD:
	case SADB_UPDATE:
	case SADB_DELETE:
		/* SA hdr */
		iov[iov_cnt].iov_base = &sa;
		iov[iov_cnt].iov_len = sizeof(sa);
		smsg.sadb_msg_len += sa.sadb_sa_len;
		iov_cnt++;
		break;
	case SADB_GETSPI:
		/* SPI range */
		iov[iov_cnt].iov_base = &sa_spirange;
		iov[iov_cnt].iov_len = sizeof(sa_spirange);
		smsg.sadb_msg_len += sa_spirange.sadb_spirange_len;
		iov_cnt++;
		break;
	}

	/* dest addr */
	iov[iov_cnt].iov_base = &sa_dst;
	iov[iov_cnt].iov_len = sizeof(sa_dst);
	iov_cnt++;
	iov[iov_cnt].iov_base = &sdst;
	iov[iov_cnt].iov_len = ROUNDUP(dstlen);
	smsg.sadb_msg_len += sa_dst.sadb_address_len;
	iov_cnt++;

	/* src addr */
	iov[iov_cnt].iov_base = &sa_src;
	iov[iov_cnt].iov_len = sizeof(sa_src);
	iov_cnt++;
	iov[iov_cnt].iov_base = &ssrc;
	iov[iov_cnt].iov_len = ROUNDUP(srclen);
	smsg.sadb_msg_len += sa_src.sadb_address_len;
	iov_cnt++;

	switch (mtype) {
	case SADB_ADD:
	case SADB_UPDATE:
		if (alen) {
			/* auth key */
			iov[iov_cnt].iov_base = &sa_akey;
			iov[iov_cnt].iov_len = sizeof(sa_akey);
			iov_cnt++;
			iov[iov_cnt].iov_base = akey;
			iov[iov_cnt].iov_len = ROUNDUP(alen);
			smsg.sadb_msg_len += sa_akey.sadb_key_len;
			iov_cnt++;
		}
		break;
	}

	len = smsg.sadb_msg_len * 8;
	do {
		n = writev(sd, iov, iov_cnt);
	} while (n == -1 && (errno == EAGAIN || errno == EINTR));

	if (n == -1) {
		log_warn("%s: writev (%d/%d)", __func__, iov_cnt, len);
		return (-1);
	}

	return (0);
}

int
pfkey_read(int sd, struct sadb_msg *h)
{
	struct sadb_msg hdr;

	if (recv(sd, &hdr, sizeof(hdr), MSG_PEEK) != sizeof(hdr)) {
		if (errno == EAGAIN || errno == EINTR)
			return (0);
		log_warn("pfkey peek");
		return (-1);
	}

	/* XXX: Only one message can be outstanding. */
	if (hdr.sadb_msg_seq == sadb_mseq &&
	    hdr.sadb_msg_pid == pid) {
		if (h)
			bcopy(&hdr, h, sizeof(hdr));
		return (0);
	}

	/* not ours, discard */
	if (read(sd, &hdr, sizeof(hdr)) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return (0);
		log_warn("pfkey read");
		return (-1);
	}

	return (1);
}

int
pfkey_reply(int sd, uint32_t *spi)
{
	struct sadb_msg hdr, *msg;
	struct sadb_ext *ext;
	struct sadb_sa *sa;
	uint8_t *data;
	ssize_t len;
	int rv;

	do {
		rv = pfkey_read(sd, &hdr);
		if (rv == -1)
			return (-1);
	} while (rv);

	if (hdr.sadb_msg_errno != 0) {
		errno = hdr.sadb_msg_errno;
		if (errno == ESRCH || errno == EEXIST)
			return (0);
		else {
			log_warn("pfkey");
			/* discard error message */
			if (read(sd, &hdr, sizeof(hdr)) == -1)
				log_warn("pfkey read");
			return (-1);
		}
	}
	if ((data = reallocarray(NULL, hdr.sadb_msg_len, PFKEY2_CHUNK))
	    == NULL) {
		log_warn("pfkey malloc");
		return (-1);
	}
	len = hdr.sadb_msg_len * PFKEY2_CHUNK;
	if (read(sd, data, len) != len) {
		log_warn("pfkey read");
		freezero(data, len);
		return (-1);
	}

	if (hdr.sadb_msg_type == SADB_GETSPI) {
		if (spi == NULL) {
			freezero(data, len);
			return (0);
		}

		msg = (struct sadb_msg *)data;
		for (ext = (struct sadb_ext *)(msg + 1);
		    (size_t)((uint8_t *)ext - (uint8_t *)msg) <
		    msg->sadb_msg_len * PFKEY2_CHUNK;
		    ext = (struct sadb_ext *)((uint8_t *)ext +
		    ext->sadb_ext_len * PFKEY2_CHUNK)) {
			if (ext->sadb_ext_type == SADB_EXT_SA) {
				sa = (struct sadb_sa *) ext;
				*spi = ntohl(sa->sadb_sa_spi);
				break;
			}
		}
	}
	freezero(data, len);
	return (0);
}

static int
pfkey_sa_add(struct bgpd_addr *src, struct bgpd_addr *dst, uint8_t keylen,
    char *key, uint32_t *spi)
{
	/* SPI is always 0 for md5sig SAs */
	*spi = 0;

	if (pfkey_send(pfkey_fd, SADB_X_SATYPE_TCPSIG, SADB_ADD, 0,
	    src, dst, *spi, SADB_AALG_MD5, keylen, key,
	    SADB_EALG_NONE, 0, NULL, 0, 0) == -1)
		return (-1);
	if (pfkey_reply(pfkey_fd, NULL) == -1)
		return (-1);
	return (0);
}

static int
pfkey_sa_remove(struct bgpd_addr *src, struct bgpd_addr *dst, uint32_t *spi)
{
	if (pfkey_send(pfkey_fd, SADB_X_SATYPE_TCPSIG, SADB_DELETE, 0,
	    src, dst, *spi, SADB_AALG_MD5, 0, NULL,
	    0, 0, NULL, 0, 0) == -1)
		return (-1);
	if (pfkey_reply(pfkey_fd, NULL) == -1)
		return (-1);
	*spi = 0;
	return (0);
}

static int
pfkey_md5sig_establish(struct peer *p)
{
	uint32_t spi_out = 0;
	uint32_t spi_in = 0;

	/* cleanup old flow if one was present */
	if (p->auth.established) {
		if (pfkey_remove(p) == -1)
			return (-1);
	}

	if (pfkey_sa_add(pfkey_localaddr(p), &p->conf.remote_addr,
	    p->conf.auth.md5key_len, p->conf.auth.md5key,
	    &spi_out) == -1)
		goto fail;

	if (pfkey_sa_add(&p->conf.remote_addr, pfkey_localaddr(p),
	    p->conf.auth.md5key_len, p->conf.auth.md5key,
	    &spi_in) == -1)
		goto fail;

	p->auth.established = 1;
	p->auth.spi_out = spi_out;
	p->auth.spi_in = spi_in;
	return (0);

fail:
	log_peer_warn(&p->conf, "%s: failed to insert md5sig", __func__);
	return (-1);
}

static int
pfkey_md5sig_remove(struct peer *p)
{
	if (p->auth.spi_out)
		if (pfkey_sa_remove(&p->auth.local_addr, &p->conf.remote_addr,
		    &p->auth.spi_out) == -1)
			goto fail;
	if (p->auth.spi_in)
		if (pfkey_sa_remove(&p->conf.remote_addr, &p->auth.local_addr,
		    &p->auth.spi_in) == -1)
			goto fail;

	p->auth.established = 0;
	p->auth.spi_out = 0;
	p->auth.spi_in = 0;
	return (0);

fail:
	log_peer_warn(&p->conf, "%s: failed to remove md5sig", __func__);
	return (-1);
}

int
pfkey_establish(struct peer *p)
{
	int rv;

	switch (p->conf.auth.method) {
	case AUTH_NONE:
		rv = 0;
		if (p->auth.established)
			rv = pfkey_remove(p);
		break;
	case AUTH_MD5SIG:
		rv = pfkey_md5sig_establish(p);
		break;
	default:
		rv = -1;
		break;
	}
	/*
	 * make sure we keep copies of everything we need to
	 * remove SAs and flows later again, even if the
	 * info in p->conf changed due to reload.
	 * We need: SPIs, method, local_addr, remote_addr.
	 * remote_addr cannot change, so no copy, SPI are
	 * handled by the method specific functions.
	 */
	memcpy(&p->auth.local_addr, pfkey_localaddr(p),
	    sizeof(p->auth.local_addr));
	p->auth.method = p->conf.auth.method;

	return (rv);
}

int
pfkey_remove(struct peer *p)
{
	if (p->auth.established == 0)
		return (0);

	switch (p->auth.method) {
	case AUTH_NONE:
		return (0);
	case AUTH_MD5SIG:
		return (pfkey_md5sig_remove(p));
	default:
		return (-1);
	}
}

int
pfkey_init(void)
{
	if ((pfkey_fd = socket(PF_KEY, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_KEY_V2)) == -1) {
		if (errno == EPROTONOSUPPORT) {
			log_warnx("PF_KEY not available, disabling ipsec");
			return (-1);
		} else
			fatal("pfkey setup failed");
	}
	return (pfkey_fd);
}

/* verify that connection is using TCP MD5UM if required by config */
int
tcp_md5_check(int fd, struct peer *p)
{
	socklen_t len;
	int opt;

	if (p->conf.auth.method == AUTH_MD5SIG) {
		if (sysdep.no_md5sig) {
			log_peer_warnx(&p->conf,
			    "md5sig configured but not available");
			return -1;
		}
		len = sizeof(opt);
		if (getsockopt(fd, IPPROTO_TCP, TCP_MD5SIG,
		    &opt, &len) == -1)
			fatal("getsockopt TCP_MD5SIG");
		if (!opt) {     /* non-md5'd connection! */
			log_peer_warnx(&p->conf,
			    "connection attempt without md5 signature");
			return -1;
		}
	}
	return 0;
}

/* enable or set TCP MD5SIG on a new client connection */
int
tcp_md5_set(int fd, struct peer *p)
{
	int opt = 1;

	if (p->conf.auth.method == AUTH_MD5SIG) {
		if (sysdep.no_md5sig) {
			log_peer_warnx(&p->conf,
			    "md5sig configured but not available");
			return -1;
		}
		if (setsockopt(fd, IPPROTO_TCP, TCP_MD5SIG,
		    &opt, sizeof(opt)) == -1) {
			log_peer_warn(&p->conf, "setsockopt md5sig");
			return -1;
		}
	}
	return 0;
}

/* enable or prepare a new listening socket for TCP MD5SIG usage */
int
tcp_md5_prep_listener(struct listen_addr *la, struct peer_head *p)
{
	int opt = 1;

	if (setsockopt(la->fd, IPPROTO_TCP, TCP_MD5SIG,
	    &opt, sizeof(opt)) == -1) {
		if (errno == ENOPROTOOPT) {	/* system w/o md5sig */
			log_warnx("md5sig not available, disabling");
			sysdep.no_md5sig = 1;
			return 0;
		}
		return -1;
	}
	return 0;
}

/* add md5 key to all listening sockets, dummy function for portable */
void
tcp_md5_add_listener(struct bgpd_config *conf, struct peer *p)
{
}

/* delete md5 key form all listening sockets, dummy function for portable */
void
tcp_md5_del_listener(struct bgpd_config *conf, struct peer *p)
{
}
