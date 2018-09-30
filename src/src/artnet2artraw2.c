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

#include <stdbool.h>

#include "conversions.h"
#include "pcap.h"
#include "osdep/osdep.h"
#include "ieee80211.h"

#define RTC_RESOLUTION  8192

#define REQUESTS    30
#define MAX_APS     20

#define NEW_IV  1
#define RETRY   2
#define ABORT   3

#define PROBE_REQ       \
    "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define ARTNET_PORT      6454

#define ARTNET_POLL           0x2000
#define ARTNET_POLLREPLY      0x2100
#define ARTNET_DIAGDATA       0x2300
#define ARTNET_COMMAND        0x2400
#define ARTNET_DMX            0x5000
#define ARTNET_NZS            0x5100
#define ARTNET_ADDRESS        0x6000
#define ARTNET_INPUT          0x7000
#define ARTNET_TODREQUEST     0x8000
#define ARTNET_TODDATA        0x8100
#define ARTNET_TODCONTROL     0x8200
#define ARTNET_RDM            0x8300
#define ARTNET_RDMSUB         0x8400
#define ARTNET_VIDEOSTEUP     0xa010
#define ARTNET_VIDEOPALETTE   0xa020
#define ARTNET_VIDEODATA      0xa040
#define ARTNET_MACMASTER      0xf000
#define ARTNET_MACSLAVE       0xf100
#define ARTNET_FIRMWAREMASTER 0xf200
#define ARTNET_FIRMWAREREPLY  0xf300
#define ARTNET_FILETNMASTER   0xf400
#define ARTNET_FILEFNMASTER   0xf500
#define ARTNET_FILEFNREPLY    0xf600
#define ARTNET_IPPROG         0xf800
#define ARTNET_IPREPLY        0xf900
#define ARTNET_MEDIA          0x9000
#define ARTNET_MEDIAPATCH     0x9100
#define ARTNET_MEDIACONTROL   0x9200
#define ARTNET_MEDIACONTROLREPLY 0x9300
#define ARTNET_TIMECODE       0x9700
#define ARTNET_TIMESYNC       0x9800
#define ARTNET_TRIGGER        0x9900
#define ARTNET_DIRECTORY      0x9a00
#define ARTNET_DIRECTORYREPLY 0x9b00

char usage[] =

"\n"
"  artnet2artraw2 - (C) 2006-2013 Thomas d\'Otreppe\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: aireplay-ng <options> <replay interface>\n"
"\n"
"      --help              : Displays this usage screen\n"
"\n";


struct options
{
    char *iface_out;
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;

    unsigned char mac_in[6];
    unsigned char mac_out[6];
}
dev;

static struct wif *_wi_in, *_wi_out;

unsigned long nb_pkt_sent;
unsigned char h80211[4096];

static void encodeYCbCr5Bit(uint8_t* ycbcr5bit, uint8_t const* dmxPosition, unsigned int dmxLen)
{
    unsigned int i;
    unsigned int j;
    uint8_t cb[4];
    uint8_t cr[4];
    for (i = 0; i < dmxLen / (3 * 4); ++i)
    {
        for (j = 0; j < 4; ++j)
            conv_ycbcr_from_rgb(dmxPosition + (i * 3 * 4) + (j * 3),
                    ycbcr5bit + i * 9 + j, // y
                    cb + j,
                    cr + j);
        conv_cbcr_to_5bit(ycbcr5bit + i * 9 + 4, cb, cr);
    }
}

// buf is received packet
// len is received packet len
// essidPosition is an out 2 bytes buf
// strPosition is an out 85 bytes buf
static bool fillPacket(char const* buf, int len, char* macPosition, char* essidPosition, char* strPosition)
{
    if (len < 12)
    {
        printf("len too low\n");
        return false;
    }
    if (memcmp(buf, "Art-Net", 7))
    {
        printf("no Art-Net\n");
        return false;
    }
    if (buf[7] != 0)
    {
        printf("buf[7] != 0\n");
        return false;
    }

    int code = ((int)buf[9] << 8) | buf[8];

    if (code != ARTNET_DMX)
    {
        printf("not a DMX packet\n");
        return false;
    }
    if (len < 19)
    {
        printf("len too low for dmx\n");
        return false;
    }

    int universe = ((int)buf[15] << 8) | buf[14];
    int dmxLen = ((int)buf[16] << 8) | buf[17];
    int sequence = buf[12];

    if (dmxLen + 18 > len)
        dmxLen = len - 18;

    char const* dmxPosition = buf + 18;

    // macPosition[0] = 'A';
    // macPosition[1] = 'r';
    macPosition[2] = universe;
    macPosition[3] = sequence;
    // macPosition[4] = dmxLen;
    // macPosition[5] = data[0];

    // macPosition[6] = 'A';
    // macPosition[7] = 'r';
    // macPosition[8] = 't';
    // macPosition[9] = 'R';
    // macPosition[10] = 'a';
    // macPosition[11] = 'w';

    // macPosition[12] = data[3];
    // macPosition[13] = data[4];
    // macPosition[14] = data[5];
    // macPosition[15] = data[6];
    // macPosition[16] = data[7];
    // macPosition[17] = data[8];

    // essidPosition[0] = data[1];
    // essidPosition[1] = data[2];

    // strPosititon[xxx] = data[xxx + 9];

    uint8_t ycbcr5bit[90];

    // RGB, encode to ycbcr5bit
    if ((universe & 0x80) == 0)
    {
        printf("encoding to ycbcr5bit\n");
        if (dmxLen > 120)
            dmxLen = 120;
        dmxLen -= dmxLen % 4; // encode 4 by 4

        encodeYCbCr5Bit(ycbcr5bit, dmxPosition, dmxLen);

        dmxPosition = (char*)ycbcr5bit;
        dmxLen -= dmxLen / 4;
    }
    else
    {
        printf("not encoding to ycbcr5bit\n");
        if (dmxLen > 85 + 1 + 2 + 6)
            dmxLen = 85 + 1 + 2 + 6;
    }

    macPosition[4] = dmxLen;

    if (dmxLen)
    {
        macPosition[5] = dmxPosition[0];
        --dmxLen;
        ++dmxPosition;
    }

    if (dmxLen)
    {
        int copySize = 2;
        if (copySize > dmxLen)
            copySize = dmxLen;
        memcpy(essidPosition, dmxPosition, copySize);
        dmxLen -= copySize;
        dmxPosition += copySize;
    }

    if (dmxLen)
    {
        int copySize = 6;
        if (copySize > dmxLen)
            copySize = dmxLen;
        memcpy(macPosition + 12, dmxPosition, copySize);
        dmxLen -= copySize;
        dmxPosition += copySize;
    }

    if (dmxLen)
    {
        int copySize = 85;
        if (copySize > dmxLen)
            copySize = dmxLen;
        memcpy(strPosition, dmxPosition, copySize);
        dmxLen -= copySize;
        dmxPosition += copySize;
    }

    return true;
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

int do_attack_test()
{
    int len=0;

    if(1)
    {
        /* avoid blocking on reading the socket */
        if( fcntl( dev.fd_in, F_SETFL, O_NONBLOCK ) < 0 )
        {
            perror( "fcntl(O_NONBLOCK) failed" );
            return( 1 );
        }
    }

    printf("Trying broadcast probe requests...\n");

    memcpy(h80211, PROBE_REQ, 24);
    h80211[0] = IEEE80211_FC0_SUBTYPE_ATIM;

    len = 24;

    char* essidPosition = h80211 + 24;
    len += 2;


    h80211[len++] = IEEE80211_ELEMID_CHALLENGE;
    char* strPosition = h80211 + len;
    len += IEEE80211_CHALLENGE_LEN;

    char* macPosition = h80211 + 4;
    memcpy(macPosition, "Ar....ArtRaw......", 18); // MAC ADDRESS * 3

    {
        struct sockaddr_in si_me, si_other;

        int s;
        int slen = sizeof(si_other);
        int recv_len;
        char buf[512];

        //create a UDP socket
        if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            perror("socket");
            return 1;
        }

        // zero out the structure
        memset((char *) &si_me, 0, sizeof(si_me));

        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(ARTNET_PORT);
        si_me.sin_addr.s_addr = htonl(INADDR_ANY);

        //bind socket to port
        if( bind(s , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1)
        {
            perror("bind");
            return 1;
        }

        //keep listening for data
        while (1)
        {
            printf("Waiting for data...\n");

            //try to receive some data, this is a blocking call
            if ((recv_len = recvfrom(s, buf, sizeof(buf), 0,
                            (struct sockaddr *)&si_other, &slen)) == -1) {
                perror("recvfrom");
                return 1;
            }

            //print details of the client/peer and the data received
            printf("received packet\n");

            if (fillPacket(buf, recv_len, macPosition, essidPosition, strPosition))
            {
                printf("send packet\n");
                send_packet(h80211, len);
            }
        }

        //close(s);
        //return 0;
    }

    return 0;
}

int main( int argc, char *argv[] )
{
    int n, i, ret;

    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );

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

                printf( "%s", usage );
                return( 1 );

            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
        if(argc == 1)
        {
usage:
            printf( "%s", usage );
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

    opt.iface_out = argv[optind];

    //don't open interface(s) when using test mode and airserv
    if (1)
    {
        /* open the replay interface */
        _wi_out = wi_open(opt.iface_out);
        if (!_wi_out)
            return 1;
        dev.fd_out = wi_fd(_wi_out);

        /* open the packet source */
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

    return do_attack_test();
}
