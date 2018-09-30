 /*
  *  Copyright (c) 2010 Andrea Bittau <bittau@cs.stanford.edu>
  *
  *  OS dependent API for using card via a pcap file.
  *
  *  This program is free software; you can redistribute it and/or modify
  *  it under the terms of the GNU General Public License as published by
  *  the Free Software Foundation; either version 2 of the License, or
  *  (at your option) any later version.
  *
  *  This program is distributed in the hope that it will be useful,
  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *  GNU General Public License for more details.
  *
  *  You should have received a copy of the GNU General Public License
  *  along with this program; if not, write to the Free Software
  *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <err.h>

#include "osdep.h"
#include "pcap.h"
#include "radiotap/radiotap_iter.h"

struct priv_file {
	int		pf_fd;
	int		pf_chan;
	int		pf_rate;
	int		pf_dtl;
	unsigned char	pf_mac[6];
};

static int file_get_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_file *pn = wi_priv(wi);

	memcpy(mac, pn->pf_mac, sizeof(pn->pf_mac));

	return 0;
}

static int file_write(struct wif *wi, unsigned char *h80211, int len,
		     struct tx_info *ti)
{
	struct priv_file *pn = wi_priv(wi);

	if (h80211 && ti && pn) {}

	return len;
}

static int file_set_channel(struct wif *wi, int chan)
{
	struct priv_file *pf = wi_priv(wi);

	pf->pf_chan = chan;

	return 0;
}

static int file_get_channel(struct wif *wi)
{
	struct priv_file *pf = wi_priv(wi);

	return pf->pf_chan;
}

static int file_set_rate(struct wif *wi, int rate)
{
	struct priv_file *pf = wi_priv(wi);

	pf->pf_rate = rate;

	return 0;
}

static int file_get_rate(struct wif *wi)
{
	struct priv_file *pf = wi_priv(wi);

	return pf->pf_rate;
}

static int file_get_monitor(struct wif *wi)
{
	if (wi) {}

	return 1;
}

static void file_close(struct wif *wi)
{
	struct priv_file *pn = wi_priv(wi);

	if (pn->pf_fd)
		close(pn->pf_fd);

	free(wi);
}

static int file_fd(struct wif *wi)
{
	struct priv_file *pf = wi_priv(wi);

	return pf->pf_fd;
}

struct wif *file_open(char *iface)
{
	struct wif *wi;
	struct priv_file *pf;
	int fd;
        struct pcap_file_header pfh;
	int rc;

	if (strncmp(iface, "file://", 7) != 0)
		return NULL;

	/* setup wi struct */
	wi = wi_alloc(sizeof(*pf));
	if (!wi)
		return NULL;

	wi->wi_write		= file_write;
	wi->wi_set_channel	= file_set_channel;
	wi->wi_get_channel	= file_get_channel;
        wi->wi_set_rate    	= file_set_rate;
	wi->wi_get_rate    	= file_get_rate;
	wi->wi_close		= file_close;
	wi->wi_fd		= file_fd;
	wi->wi_get_mac		= file_get_mac;
	wi->wi_get_monitor	= file_get_monitor;

        pf = wi_priv(wi);

	fd = open(iface + 7, O_RDONLY);
	if (fd == -1)
		err(1, "open()");

	pf->pf_fd = fd;

	if ((rc = read(fd, &pfh, sizeof(pfh))) != sizeof(pfh))
		goto __err;

	if (pfh.magic != TCPDUMP_MAGIC)
		goto __err;

	if (pfh.version_major != PCAP_VERSION_MAJOR
	    || pfh.version_minor != PCAP_VERSION_MINOR)
		goto __err;

	pf->pf_dtl = pfh.linktype;

	return wi;

__err:
	wi_close(wi);
	return (struct wif*) -1;
}
