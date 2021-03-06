/* 
 * Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 * All OS dependent crap should go here.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#ifndef __AIRCRACK_NG_OSEDEP_H__
#define __AIRCRACK_NG_OSEDEP_H__

#include <netinet/in.h>
#include <stdint.h>

#include "byteorder.h"
#include "packed.h"

/* For all structures, when adding new fields, always append them to the end.
 * This way legacy binary code does not need to be recompiled.  This is
 * particularly useful for DLLs.  -sorbo
 */

struct tx_info {
        unsigned int     ti_rate;
};

struct rx_info {
        uint64_t ri_mactime;
        int32_t ri_power;
        int32_t ri_noise;
        uint32_t ri_channel;
        uint32_t ri_freq;
        uint32_t ri_rate;
        uint32_t ri_antenna;
} __packed;

/* Normal code should not access this directly.  Only osdep.
 * This structure represents a single interface.  It should be created with
 * wi_open and destroyed with wi_close.
 */
#define MAX_IFACE_NAME	64
struct wif {
        int     (*wi_write)(struct wif *wi, unsigned char *h80211, int len,
                            struct tx_info *ti);
	void	(*wi_close)(struct wif *wi);
	int	(*wi_fd)(struct wif *wi);
	int	(*wi_get_mac)(struct wif *wi, unsigned char *mac);

        void	*wi_priv;
        char	wi_interface[MAX_IFACE_NAME];
};

/* Routines to be used by client code */
extern struct wif *wi_open(char *iface);
extern int wi_write(struct wif *wi, unsigned char *h80211, int len,
		    struct tx_info *ti);
extern void wi_close(struct wif *wi);
extern char *wi_get_ifname(struct wif *wi);
extern int wi_get_mac(struct wif *wi, unsigned char *mac);

/* wi_open_osdep should determine the type of card and setup the wif structure
 * appropriately.  There is one per OS.  Called by wi_open.
 */
extern struct wif *wi_open_osdep(char *iface);

/* This will return the FD used for reading.  This is required for using select
 * on it.
 */
extern int wi_fd(struct wif *wi);

/* Helper routines for osdep code.  */
extern struct wif *wi_alloc(int sz);
extern void *wi_priv(struct wif *wi);

#endif /* __AIRCRACK_NG_OSEDEP_H__ */
