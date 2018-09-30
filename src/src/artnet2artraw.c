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

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdbool.h>

#include "conversions.h"
#include "osdep/osdep.h"
#include "ieee80211.h"

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
"  usage: artnet2artraw <replay interface>\n"
"\n";

static char artPollReply[] = {
    'A', 'r', 't', '-', 'N', 'e', 't', '\0',
    // opcode (little endian)
    (ARTNET_POLLREPLY & 0xff), ((ARTNET_POLLREPLY >> 8) & 0xff),
    // ip address
    192, 168, 50, 1,
    // port (little endian)
    0x36, 0x19,
    // firmware version
    1, 0,
    // sub switch
    0, 0,
    // oem value
    0, 0,
    // UBEA version
    0,
    // Status1
    0,
    // ESTA Manufacturer
    'P', 'L',
    // short name
    'a', 'r', 't', 'n', 'e', 't', '2', 'a', 'r', 't', 'r', 'a', 'w', '\0', '\0', '\0', '\0', '\0',
    // long name
    't', 'p', '-', 'l', 'i', 'n', 'k', ' ', 'a', 'r', 't', '-', 'n', 'e', 't', ' ',
    'c', 'l', 'e', 'a', 'r', ' ', 'w', 'i', 'f', 'i', ' ', 'b', 'r', 'o', 'a', 'd',
    'c', 'a', 's', 't', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    // node report (status string)
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    // numport (big endian)
    1, 0,
    // port types: 5 is artnet
    5, 5, 5, 5,
    // good input
    0, 0, 0, 0,
    // good output
    0, 0, 0, 0,
    // swIn
    0, 0, 0, 0,
    // swOut
    0, 0, 0, 0,
    // swVideo
    0,
    // swMacro
    0,
    // swRemote
    0,
    // style
    0,
    // MAC
    0, 0, 0, 0, 0, 0,
    // bind ip
    0, 0, 0, 0,
    // bind index
    1,
    // Status2
    0,
    // 26 spares
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

struct options
{
    char *iface_out;
}
opt;

struct devices
{
    int fd_out, arptype_out;

    unsigned char mac_out[6];
}
dev;

static struct wif *_wi_out;

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char* macPosition = h80211 + 4;
unsigned char* essidPosition = h80211 + 24;
unsigned char* strPosition = h80211 + 27;
unsigned int h80211Len = 0;

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
static bool fillPacket(char const* buf, int len)
{
    if (len < 19)
    {
        printf("packet too short for dmx\n");
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

static bool checkPacket(uint8_t const* buf, unsigned int len, int* opCode)
{
    if (len < 12)
        return false;
    if (memcmp(buf, "Art-Net", 7))
        return false;
    if (buf[7] != 0)
        return false;

    *opCode = ((int)buf[9] << 8) | buf[8];
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

static void prepare_packet()
{
    memcpy(h80211, PROBE_REQ, 24);
    h80211Len += 24;
    // ATIM is probably the least harmful wifi mgt packet
    h80211[0] = IEEE80211_FC0_SUBTYPE_ATIM;

    // char* essidPosition = h80211 + 24;
    h80211Len += 2;

    h80211[h80211Len++] = IEEE80211_ELEMID_CHALLENGE;
    // char* strPosition = h80211 + len;
    h80211Len += IEEE80211_CHALLENGE_LEN;

    // char* macPosition = h80211 + 4;
    memcpy(macPosition, "Ar....ArtRaw......", 18); // MAC ADDRESS * 3
}

int do_artnet2artraw()
{
    prepare_packet();

    struct sockaddr_in si_me, si_other;

    int s;
    int slen = sizeof(si_other);
    int recv_len;
    char buf[512];
    int opCode;

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
        //try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(s, buf, sizeof(buf), 0,
                        (struct sockaddr *)&si_other, &slen)) == -1) {
            perror("recvfrom");
            return 1;
        }

        if (!checkPacket(buf, recv_len, &opCode))
            continue;

        if (opCode == ARTNET_POLL) {
            if (sendto(s, artPollReply, sizeof(artPollReply), 0, (struct sockaddr*)&si_other, slen) == -1)
            {
                perror("sendto");
                return 1;
            }
        } else if (opCode == ARTNET_DMX) {
            if (fillPacket(buf, recv_len))
            {
                printf("send packet\n");
                send_packet(h80211, h80211Len);
            }
        }
    }

    close(s);
    return 0;
}

int main( int argc, char *argv[] )
{
    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );

    /* check the arguments */
    if( argc != 2 )
    {
        printf("No replay interface specified.\n%s", usage);
        return 1;
    }

    opt.iface_out = argv[1];

    /* open interface */
    _wi_out = wi_open(opt.iface_out);
    if (!_wi_out)
        return 1;
    dev.fd_out = wi_fd(_wi_out);
    wi_get_mac(_wi_out, dev.mac_out);

    /* drop privileges */
    if (setuid( getuid() ) == -1) {
        perror("setuid");
    }

    return do_artnet2artraw();
}
