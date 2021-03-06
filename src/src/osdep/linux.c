/*
 *  OS dependent APIs for Linux
 *
 *  Copyright (C) 2006-2013 Thomas d'Otreppe
 *  Copyright (C) 2004, 2005 Christophe Devine
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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <net/if_arp.h>

#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/genetlink.h>

#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"
        /* radiotap-parser defines types like u8 that
         * ieee80211_radiotap.h needs
         *
         * we use our local copy of ieee80211_radiotap.h
         *
         * - since we can't support extensions we don't understand
         * - since linux does not include it in userspace headers
         */
#include "osdep.h"
#include "pcap.h"
#include "common.h"
#include "byteorder.h"

struct nl80211_state state;
static int chan;


typedef enum {
        DT_NULL = 0,
        DT_WLANNG,
        DT_HOSTAP,
        DT_MADWIFI,
        DT_MADWIFING,
        DT_BCM43XX,
        DT_ORINOCO,
        DT_ZD1211RW,
        DT_ACX,
        DT_MAC80211_RT,
        DT_AT76USB,
        DT_IPW2200

} DRIVER_TYPE;

static const char * szaDriverTypes[] = {
        [DT_NULL] = "Unknown",
        [DT_WLANNG] = "Wlan-NG",
        [DT_HOSTAP] = "HostAP",
        [DT_MADWIFI] = "Madwifi",
        [DT_MADWIFING] = "Madwifi-NG",
        [DT_BCM43XX] = "BCM43xx",
        [DT_ORINOCO] = "Orinoco",
        [DT_ZD1211RW] = "ZD1211RW",
        [DT_ACX] = "ACX",
        [DT_MAC80211_RT] = "Mac80211-Radiotap",
        [DT_AT76USB] = "Atmel 76_usb",
        [DT_IPW2200] = "ipw2200"
};

/*
 * XXX need to have a different read/write/open function for each Linux driver.
 */

struct priv_linux {
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_main;

    DRIVER_TYPE drivertype; /* inited to DT_UNKNOWN on allocation by wi_alloc */

    int sysfs_inject;
    int rate;
    char *wlanctlng; /* XXX never set */
    char *iwpriv;
    char *wl;
    char *main_if;
    unsigned char pl_mac[6];
    int inject_wlanng;
};

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

//Check if the driver is ndiswrapper */
static int is_ndiswrapper(const char * iface, const char * path)
{
    int n, pid, unused;
    if ((pid=fork())==0)
    {
        close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
        execl(path, "iwpriv",iface, "ndis_reset", NULL);
        exit( 1 );
    }

    waitpid( pid, &n, 0 );
    return ( ( WIFEXITED(n) && WEXITSTATUS(n) == 0 ));
}

/* Search a file recursively */
static char * searchInside(const char * dir, const char * filename)
{
    char * ret;
    char * curfile;
    struct stat sb;
    int len, lentot;
    DIR *dp;
    struct dirent *ep;

    dp = opendir(dir);
    if (dp == NULL)
    {
        return NULL;
	}

    len = strlen( filename );
    lentot = strlen( dir ) + 256 + 2;
    curfile = (char *) calloc( 1, lentot );

    while ((ep = readdir(dp)) != NULL)
    {

        memset(curfile, 0, lentot);
        sprintf(curfile, "%s/%s", dir, ep->d_name);

        //Checking if it's the good file
        if ((int)strlen( ep->d_name) == len && !strcmp(ep->d_name, filename))
        {
            (void)closedir(dp);
            return curfile;
        }
        lstat(curfile, &sb);

        //If it's a directory and not a link, try to go inside to search
        if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode))
        {
            //Check if the directory isn't "." or ".."
            if (strcmp(".", ep->d_name) && strcmp("..", ep->d_name))
            {
                //Recursive call
                ret = searchInside(curfile, filename);
                if (ret != NULL)
                {
                    (void)closedir(dp);
                    free( curfile );
                    return ret;
                }
            }
        }
    }
    (void)closedir(dp);
    free( curfile );
    return NULL;
}

/* Search a wireless tool and return its path */
static char * wiToolsPath(const char * tool)
{
        char * path /*, *found, *env */;
        int i, nbelems;
        static const char * paths [] = {
                "/sbin",
                "/usr/sbin",
                "/usr/local/sbin",
                "/bin",
                "/usr/bin",
                "/usr/local/bin",
                "/tmp"
        };
    /*
	#define SEPARATOR ":"

	env = getenv("PATH");
	if (env) {
		path = strtok(env, SEPARATOR);
		while (path) {
			found = searchInside(path, tool);
	                if (found != NULL)
	                        return found;
			path = strtok(NULL, SEPARATOR);
		}
	}
	#undef SEPARATOR
	*/
	
	// Also search in other known location just in case we haven't found it yet
	nbelems = sizeof(paths) / sizeof(char *);
	for (i = 0; i < nbelems; i++)
	{
		path = searchInside(paths[i], tool);
		if (path != NULL)
			return path;
	}

        return NULL;
}


struct nl80211_state {
    struct nl_sock *nl_sock;
    struct nl_cache *nl_cache;
    struct genl_family *nl80211;
};


static int linux_nl80211_init(struct nl80211_state *state)
{
    int err;

    state->nl_sock = nl_socket_alloc();

    if (!state->nl_sock) {
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return -ENOMEM;
    }

    if (genl_connect(state->nl_sock)) {
        fprintf(stderr, "Failed to connect to generic netlink.\n");
        err = -ENOLINK;
        goto out_handle_destroy;
    }

    if (genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache)) {
        fprintf(stderr, "Failed to allocate generic netlink cache.\n");
        err = -ENOMEM;
        goto out_handle_destroy;
    }

    state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
    if (!state->nl80211) {
        fprintf(stderr, "nl80211 not found.\n");
        err = -ENOENT;
        goto out_cache_free;
    }

    return 0;

 out_cache_free:
    nl_cache_free(state->nl_cache);
 out_handle_destroy:
    nl_socket_free(state->nl_sock);
    return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
    genl_family_put(state->nl80211);
    nl_cache_free(state->nl_cache);
    nl_socket_free(state->nl_sock);
}

static int linux_write(struct wif *wi, unsigned char *buf, int count,
                        struct tx_info *ti)
{
    struct priv_linux *dev = wi_priv(wi);
    unsigned char maddr[6];
    int ret, usedrtap=0;
    unsigned char tmpbuf[4096];
    unsigned char rate;
    unsigned short int *p_rtlen;

    unsigned char u8aRadiotap[] = {
        0x00, 0x00, // <-- radiotap version
        0x0c, 0x00, // <- radiotap header length
        0x04, 0x80, 0x00, 0x00, // <-- bitmap
        0x00, // <-- rate
        0x00, // <-- padding for natural alignment
        0x18, 0x00, // <-- TX flags
    };

    /* Pointer to the radiotap header length field for later use. */
    p_rtlen = (unsigned short int*)(u8aRadiotap+2);


    if((unsigned) count > sizeof(tmpbuf)-22) return -1;

    /* XXX honor ti */
    if (ti) {}

    rate = dev->rate;

    u8aRadiotap[8] = rate;

    switch (dev->drivertype) {

    case DT_MAC80211_RT:
        memcpy(tmpbuf, u8aRadiotap, sizeof (u8aRadiotap) );
        memcpy(tmpbuf + sizeof (u8aRadiotap), buf, count);
        count += sizeof (u8aRadiotap);

        buf = tmpbuf;
        usedrtap = 1;
        break;

    case DT_WLANNG:
        /* Wlan-ng isn't able to inject on kernel > 2.6.11 */
        if( dev->inject_wlanng == 0 )
        {
                perror( "write failed" );
                return( -1 );
        }

        if (count >= 24)
        {
            /* for some reason, wlan-ng requires a special header */

            if( ( ((unsigned char *) buf)[1] & 3 ) != 3 )
            {
                memcpy( tmpbuf, buf, 24 );
                memset( tmpbuf + 24, 0, 22 );

                tmpbuf[30] = ( count - 24 ) & 0xFF;
                tmpbuf[31] = ( count - 24 ) >> 8;

                memcpy( tmpbuf + 46, buf + 24, count - 24 );

                count += 22;
            }
            else
            {
                memcpy( tmpbuf, buf, 30 );
                memset( tmpbuf + 30, 0, 16 );

                tmpbuf[30] = ( count - 30 ) & 0xFF;
                tmpbuf[31] = ( count - 30 ) >> 8;

                memcpy( tmpbuf + 46, buf + 30, count - 30 );

                count += 16;
            }

            buf = tmpbuf;
        }
        /* fall thru */
    case DT_HOSTAP:
        if( ( ((unsigned char *) buf)[1] & 3 ) == 2 )
        {
            /* Prism2 firmware swaps the dmac and smac in FromDS packets */

            memcpy( maddr, buf + 4, 6 );
            memcpy( buf + 4, buf + 16, 6 );
            memcpy( buf + 16, maddr, 6 );
        }
        break;
    default:
        break;
    }

    ret = write( dev->fd_out, buf, count );

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS || errno == ENOMEM )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    /* radiotap header length is stored little endian on all systems */
    if(usedrtap)
        ret-=letoh16(*p_rtlen);

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS || errno == ENOMEM )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    return( ret );
}

static int opensysfs(struct priv_linux *dev, char *iface, int fd) {
    int fd2;
    char buf[256];

    /* ipw2200 injection */
    snprintf(buf, 256, "/sys/class/net/%s/device/inject", iface);
    fd2 = open(buf, O_WRONLY);

    /* bcm43xx injection */
    if (fd2 == -1) {
        snprintf(buf, 256, "/sys/class/net/%s/device/inject_nofcs", iface);
        fd2 = open(buf, O_WRONLY);
    }

    if (fd2 == -1)
        return -1;

    dup2(fd2, fd);
    close(fd2);

    dev->sysfs_inject=1;
    return 0;
}

int set_monitor( struct priv_linux *dev, char *iface, int fd )
{
    int pid, status, unused;
    struct iwreq wrq;

    if( strcmp(iface,"prism0") == 0 )
    {
        dev->wl = wiToolsPath("wl");
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execl( dev->wl, "wl", "monitor", "1", NULL);
            exit( 1 );
        }
        waitpid( pid, &status, 0 );
        if( WIFEXITED(status) )
            return( WEXITSTATUS(status) );
        return( 1 );
    }
    else if (strncmp(iface, "rtap", 4) == 0 )
    {
        return 0;
    }
    else
    {
        switch(dev->drivertype) {
        case DT_WLANNG:
            if( ( pid = fork() ) == 0 )
            {
                close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
                execl( dev->wlanctlng, "wlanctl-ng", iface,
                        "lnxreq_wlansniff", "enable=true",
                        "prismheader=true", "wlanheader=false",
                        "stripfcs=true", "keepwepflags=true",
                        "6", NULL );
                exit( 1 );
            }

            waitpid( pid, &status, 0 );

            if( WIFEXITED(status) )
                return( WEXITSTATUS(status) );
            return( 1 );
            break;

        case DT_ORINOCO:
            if( ( pid = fork() ) == 0 )
            {
                close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
                execlp( dev->iwpriv, "iwpriv", iface,
                        "monitor", "1", "1", NULL );
                exit( 1 );
            }

            waitpid( pid, &status, 0 );

            if( WIFEXITED(status) )
                return( WEXITSTATUS(status) );

            return 1;
            break;

        case DT_ACX:
            if( ( pid = fork() ) == 0 )
            {
                close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
                execlp( dev->iwpriv, "iwpriv", iface,
                        "monitor", "2", "1", NULL );
                exit( 1 );
            }

            waitpid( pid, &status, 0 );

            if( WIFEXITED(status) )
                return( WEXITSTATUS(status) );

            return 1;
            break;

        default:
            break;
        }

        memset( &wrq, 0, sizeof( struct iwreq ) );
        strncpy( wrq.ifr_name, iface, IFNAMSIZ );
        wrq.u.mode = IW_MODE_MONITOR;

        if( ioctl( fd, SIOCSIWMODE, &wrq ) < 0 )
        {
            perror( "ioctl(SIOCSIWMODE) failed" );
            return( 1 );
        }

        if(dev->drivertype == DT_AT76USB)
        {
            sleep(3);
        }
    }

    /* couple of iwprivs to enable the prism header */

    if( ! fork() )  /* hostap */
    {
        close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "monitor_type", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* r8180 */
    {
        close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* prism54 */
    {
        close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "set_prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    return( 0 );
}


static int openraw(struct priv_linux *dev, char *iface, int fd, int *arptype,
		   unsigned char *mac)
{
    struct ifreq ifr;
    struct ifreq ifr2;
    struct iwreq wrq;
    struct iwreq wrq2;
    struct packet_mreq mr;
    struct sockaddr_ll sll;
    struct sockaddr_ll sll2;

    /* find the interface index */

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFINDEX) failed" );
        return( 1 );
    }

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;

    switch(dev->drivertype) {
    case DT_IPW2200:
        /* find the interface index */

        memset( &ifr2, 0, sizeof( ifr ) );
        strncpy( ifr2.ifr_name, dev->main_if, sizeof( ifr2.ifr_name ) - 1 );

        if( ioctl( dev->fd_main, SIOCGIFINDEX, &ifr2 ) < 0 )
        {
            printf("Interface %s: \n", dev->main_if);
            perror( "ioctl(SIOCGIFINDEX) failed" );
            return( 1 );
        }

        /* set iw mode to managed on main interface */
        memset( &wrq2, 0, sizeof( struct iwreq ) );
        strncpy( wrq2.ifr_name, dev->main_if, IFNAMSIZ );

        if( ioctl( dev->fd_main, SIOCGIWMODE, &wrq2 ) < 0 )
        {
            perror("SIOCGIWMODE");
            return 1;
        }
        wrq2.u.mode = IW_MODE_INFRA;
        if( ioctl( dev->fd_main, SIOCSIWMODE, &wrq2 ) < 0 )
        {
            perror("SIOCSIWMODE");
            return 1;
        }

        /* bind the raw socket to the interface */

        memset( &sll2, 0, sizeof( sll2 ) );
        sll2.sll_family   = AF_PACKET;
        sll2.sll_ifindex  = ifr2.ifr_ifindex;
        sll2.sll_protocol = htons( ETH_P_ALL );

        if( bind( dev->fd_main, (struct sockaddr *) &sll2,
                sizeof( sll2 ) ) < 0 )
        {
            printf("Interface %s: \n", dev->main_if);
            perror( "bind(ETH_P_ALL) failed" );
            return( 1 );
        }

        opensysfs(dev, dev->main_if, dev->fd_in);
        break;
    case DT_BCM43XX:
        opensysfs(dev, iface, dev->fd_in);
        break;
    case DT_WLANNG:
        sll.sll_protocol = htons( ETH_P_80211_RAW );
        break;
    default:
        sll.sll_protocol = htons( ETH_P_ALL );
        break;
    }

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    /* lookup iw mode */
    memset( &wrq, 0, sizeof( struct iwreq ) );
    strncpy( wrq.ifr_name, iface, IFNAMSIZ );

    if( ioctl( fd, SIOCGIWMODE, &wrq ) < 0 )
    {
        /* most probably not supported (ie for rtap ipw interface) *
         * so just assume its correctly set...                     */
        wrq.u.mode = IW_MODE_MONITOR;
    }

    if( ( ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
          ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM &&
          ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL) ||
        ( wrq.u.mode != IW_MODE_MONITOR) )
    {
        if (set_monitor( dev, iface, fd ) && !dev->drivertype == DT_ORINOCO )
        {
            ifr.ifr_flags &= ~(IFF_UP | IFF_BROADCAST | IFF_RUNNING);

            if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
            {
                perror( "ioctl(SIOCSIFFLAGS) failed" );
                return( 1 );
            }

            if (set_monitor( dev, iface, fd ) && !dev->drivertype == DT_ORINOCO )
            {
                printf("Error setting monitor mode on %s\n",iface);
                return( 1 );
            }
        }
    }

    /* Is interface st to up, broadcast & running ? */
    if((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING) != ifr.ifr_flags)
    {
        /* Bring interface up*/
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
        {
            perror( "ioctl(SIOCSIFFLAGS) failed" );
            return( 1 );
        }
    }
    /* bind the raw socket to the interface */

    if( bind( fd, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    memcpy( mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

    *arptype = ifr.ifr_hwaddr.sa_family;

    if( ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL )
    {
        if( ifr.ifr_hwaddr.sa_family == 1 )
            fprintf( stderr, "\nARP linktype is set to 1 (Ethernet) " );
        else
            fprintf( stderr, "\nUnsupported hardware link type %4d ",
                     ifr.ifr_hwaddr.sa_family );

        fprintf( stderr, "- expected ARPHRD_IEEE80211,\nARPHRD_IEEE80211_"
                         "FULL or ARPHRD_IEEE80211_PRISM instead.  Make\n"
                         "sure RFMON is enabled: run 'airmon-ng start %s"
                         " <#>'\nSysfs injection support was not found "
                         "either.\n\n", iface );
        return( 1 );
    }

    /* enable promiscuous mode */

    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;

    if( setsockopt( fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }

    return( 0 );
}

/*
 * Open the interface and set mode monitor
 * Return 1 on failure and 0 on success
 */
static int do_linux_open(struct wif *wi, char *iface)
{
    int kver, unused;
    struct utsname checklinuxversion;
    struct priv_linux *dev = wi_priv(wi);
    char *iwpriv;
    char strbuf[512];
    FILE *f;
    char athXraw[] = "athXraw";
    pid_t pid;
    int n;
    DIR *net_ifaces;
    struct dirent *this_iface;
    FILE *acpi;
    char r_file[128], buf[128];
    struct ifreq ifr;
    char * unused_str;
    int iface_malloced = 0;

    dev->inject_wlanng = 1;
    dev->rate = 2; /* default to 1Mbps if nothing is set */

    /* open raw socks */
    if( ( dev->fd_in = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

    if( ( dev->fd_main = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

    /* Exit if ndiswrapper : check iwpriv ndis_reset */

    if ( is_ndiswrapper(iface, iwpriv ) )
    {
        fprintf(stderr, "Ndiswrapper doesn't support monitor mode.\n");
        goto close_in;
    }

    if( ( dev->fd_out = socket( PF_PACKET, SOCK_RAW,
                               htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        goto close_in;
    }
    /* figure out device type */

    /* mac80211 radiotap injection
     * detected based on interface called mon...
     * since mac80211 allows multiple virtual interfaces
     *
     * note though that the virtual interfaces are ultimately using a
     * single physical radio: that means for example they must all
     * operate on the same channel
     */

    /* mac80211 stack detection */
    memset(strbuf, 0, sizeof(strbuf));
    snprintf(strbuf, sizeof(strbuf) - 1,
            "ls /sys/class/net/%s/phy80211/subsystem >/dev/null 2>/dev/null", iface);

    if (system(strbuf) == 0)
        dev->drivertype = DT_MAC80211_RT;

    /* IPW2200 detection */
    memset(strbuf, 0, sizeof(strbuf));
    snprintf(strbuf, sizeof(strbuf) - 1,
            "ls /sys/class/net/%s/device/inject >/dev/null 2>/dev/null", iface);

    if (system(strbuf) == 0)
        dev->drivertype = DT_IPW2200;

    /* BCM43XX detection */
    memset(strbuf, 0, sizeof(strbuf));
    snprintf(strbuf, sizeof(strbuf) - 1,
            "ls /sys/class/net/%s/device/inject_nofcs >/dev/null 2>/dev/null", iface);

    if (system(strbuf) == 0)
        dev->drivertype = DT_BCM43XX;

    /* check if wlan-ng or hostap or r8180 */
    if( strlen(iface) == 5 &&
        memcmp(iface, "wlan", 4 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "wlancfg show %s 2>/dev/null | "
                  "grep p2CnfWEPFlags >/dev/null",
                  iface);

        if( system( strbuf ) == 0 )
        {
            if (uname( & checklinuxversion ) >= 0)
            {
                /* uname succeeded */
                if (strncmp(checklinuxversion.release, "2.6.", 4) == 0
                    && strncasecmp(checklinuxversion.sysname, "linux", 5) == 0)
                {
                    /* Linux kernel 2.6 */
                    kver = atoi(checklinuxversion.release + 4);

                    if (kver > 11)
                    {
                        /* That's a kernel > 2.6.11, cannot inject */
                        dev->inject_wlanng = 0;
                    }
                }
            }
            dev->drivertype = DT_WLANNG;
            dev->wlanctlng = wiToolsPath("wlanctl-ng");
        }

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s 2>/dev/null | "
                  "grep antsel_rx >/dev/null",
                  iface);

        if( system( strbuf ) == 0 )
            dev->drivertype=DT_HOSTAP;

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                    "iwpriv %s 2>/dev/null | "
                    "grep  GetAcx111Info  >/dev/null",
                    iface);

        if( system( strbuf ) == 0 )
            dev->drivertype=DT_ACX;
    }

    /* enable injection on ralink */

    if( strcmp( iface, "ra0" ) == 0 ||
        strcmp( iface, "ra1" ) == 0 ||
        strcmp( iface, "rausb0" ) == 0 ||
        strcmp( iface, "rausb1" ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s rfmontx 1 >/dev/null 2>/dev/null",
                  iface );
        unused = system( strbuf );
    }

    /* check if newer athXraw interface available */

    if( ( strlen( iface ) >= 4 || strlen( iface ) <= 6 )
        && memcmp( iface, "ath", 3 ) == 0 )
    {
        dev->drivertype = DT_MADWIFI;
        memset( strbuf, 0, sizeof( strbuf ) );

        snprintf(strbuf, sizeof( strbuf ) -1,
                  "/proc/sys/net/%s/%%parent", iface);

        f = fopen(strbuf, "r");

        if (f != NULL)
        {
            // It is madwifi-ng
            dev->drivertype=DT_MADWIFING;
            fclose( f );

            /* should we force prism2 header? */

            sprintf((char *) strbuf, "/proc/sys/net/%s/dev_type", iface);
            f = fopen( (char *) strbuf,"w");
            if (f != NULL) {
                fprintf(f, "802\n");
                fclose(f);
            }

            /* Force prism2 header on madwifi-ng */
        }
        else
        {
            // Madwifi-old
            memset( strbuf, 0, sizeof( strbuf ) );
            snprintf( strbuf,  sizeof( strbuf ) - 1,
                      "sysctl -w dev.%s.rawdev=1 >/dev/null 2>/dev/null",
                      iface );

            if( system( strbuf ) == 0 )
            {

                athXraw[3] = iface[3];

                memset( strbuf, 0, sizeof( strbuf ) );
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                          "ifconfig %s up", athXraw );
                unused = system( strbuf );

#if 0 /* some people reported problems when prismheader is enabled */
                memset( strbuf, 0, sizeof( strbuf ) );
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                         "sysctl -w dev.%s.rawdev_type=1 >/dev/null 2>/dev/null",
                         iface );
                unused = system( strbuf );
#endif

                iface = athXraw;
            }
        }
    }

    /* test if orinoco */

    if( memcmp( iface, "eth", 3 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( "iwpriv", "iwpriv", iface, "get_port3", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            dev->drivertype=DT_ORINOCO;

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s 2>/dev/null | "
                  "grep get_scan_times >/dev/null",
                  iface);

        if( system( strbuf ) == 0 )
            dev->drivertype=DT_AT76USB;
    }

    /* test if zd1211rw */

    if( memcmp( iface, "eth", 3 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( "iwpriv", "iwpriv", iface, "get_regdomain", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            dev->drivertype=DT_ZD1211RW;
    }

    if( dev->drivertype == DT_IPW2200 )
    {
        snprintf(r_file, sizeof(r_file),
            "/sys/class/net/%s/device/rtap_iface", iface);
        if ((acpi = fopen(r_file, "r")) == NULL)
            goto close_out;
        memset(buf, 0, 128);
        unused_str = fgets(buf, 128, acpi);
        buf[127]='\x00';
        //rtap iface doesn't exist
        if(strncmp(buf, "-1", 2) == 0)
        {
            //repoen for writing
            fclose(acpi);
            if ((acpi = fopen(r_file, "w")) == NULL)
                goto close_out;
            fputs("1", acpi);
            //reopen for reading
            fclose(acpi);
            if ((acpi = fopen(r_file, "r")) == NULL)
                goto close_out;
            unused_str = fgets(buf, 128, acpi);
        }
        fclose(acpi);

        //use name in buf as new iface and set original iface as main iface
        dev->main_if = (char*) malloc(strlen(iface)+1);
        memset(dev->main_if, 0, strlen(iface)+1);
        strncpy(dev->main_if, iface, strlen(iface));

        iface=(char*)malloc(strlen(buf)+1);
        iface_malloced = 1;
        memset(iface, 0, strlen(buf)+1);
        strncpy(iface, buf, strlen(buf));
    }

    /* test if rtap interface and try to find real interface */
    if( memcmp( iface, "rtap", 4) == 0 && dev->main_if == NULL)
    {
        memset( &ifr, 0, sizeof( ifr ) );
        strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

        n = 0;

        if( ioctl( dev->fd_out, SIOCGIFINDEX, &ifr ) < 0 )
        {
            //create rtap interface
            n = 1;
        }

        net_ifaces = opendir("/sys/class/net");
        if ( net_ifaces != NULL )
        {
            while (net_ifaces != NULL && ((this_iface = readdir(net_ifaces)) != NULL))
            {
                if (this_iface->d_name[0] == '.')
                    continue;

                snprintf(r_file, sizeof(r_file),
                    "/sys/class/net/%s/device/rtap_iface", this_iface->d_name);
                if ((acpi = fopen(r_file, "r")) == NULL)
                    continue;
                if (acpi != NULL)
                {
                    dev->drivertype = DT_IPW2200;

                    memset(buf, 0, 128);
                    unused_str = fgets(buf, 128, acpi);
                    if(n==0) //interface exists
                    {
                        if (strncmp(buf, iface, 5) == 0)
                        {
                            fclose(acpi);
                            if (net_ifaces != NULL)
                            {
                                closedir(net_ifaces);
                                net_ifaces = NULL;
                            }
                            dev->main_if = (char*) malloc(strlen(this_iface->d_name)+1);
                            strcpy(dev->main_if, this_iface->d_name);
                            break;
                        }
                    }
                    else //need to create interface
                    {
                        if (strncmp(buf, "-1", 2) == 0)
                        {
                            //repoen for writing
                            fclose(acpi);
                            if ((acpi = fopen(r_file, "w")) == NULL)
                                continue;
                            fputs("1", acpi);
                            //reopen for reading
                            fclose(acpi);
                            if ((acpi = fopen(r_file, "r")) == NULL)
                                continue;
                            unused_str = fgets(buf, 128, acpi);
                            if (strncmp(buf, iface, 5) == 0)
                            {
                                if (net_ifaces != NULL)
                                {
                                    closedir(net_ifaces);
                                    net_ifaces = NULL;
                                }
                                dev->main_if = (char*) malloc(strlen(this_iface->d_name)+1);
                                strcpy(dev->main_if, this_iface->d_name);
                                fclose(acpi);
                                break;
                            }
                        }
                    }
                    fclose(acpi);
                }
            }
            if (net_ifaces != NULL)
                closedir(net_ifaces);
        }
    }

    if(0)
    fprintf(stderr, "Interface %s -> driver: %s\n", iface,
        szaDriverTypes[dev->drivertype]);

    if (openraw(dev, iface, dev->fd_out, &dev->arptype_out, dev->pl_mac) != 0) {
        goto close_out;
    }

    /* don't use the same file descriptor for in and out on bcm43xx,
       as you read from the interface, but write into a file in /sys/...
     */
    if(!(dev->drivertype == DT_BCM43XX) && !(dev->drivertype == DT_IPW2200))
        dev->fd_in = dev->fd_out;
    else
    {
        /* if bcm43xx or ipw2200, swap both fds */
        n=dev->fd_out;
        dev->fd_out=dev->fd_in;
        dev->fd_in=n;
    }

    dev->arptype_in = dev->arptype_out;

    if(iface_malloced) free(iface);
    return 0;
close_out:
    close(dev->fd_out);
close_in:
    close(dev->fd_in);
    if(iface_malloced) free(iface);
    return 1;
}

static void do_free(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

        if(pl->wlanctlng)
            free(pl->wlanctlng);

        if(pl->iwpriv)
            free(pl->iwpriv);

        if(pl->wl)
            free(pl->wl);

	if(pl->main_if)
            free(pl->main_if);

	free(pl);
	free(wi);
}

static void linux_close_nl80211(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);
    nl80211_cleanup(&state);

	if (pl->fd_in)
		close(pl->fd_in);
	if (pl->fd_out)
		close(pl->fd_out);

	do_free(wi);
}

static int linux_fd(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

	return pl->fd_in;
}

static int linux_get_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_linux *pl = wi_priv(wi);
	struct ifreq ifr;
	int fd;

	fd = wi_fd(wi);
	/* find the interface index */

	/* ipw2200 got a file opened as fd  */
	if(pl->drivertype == DT_IPW2200)
	{
		memcpy(mac, pl->pl_mac, 6);
		return 0;
	}

	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, wi_get_ifname(wi), sizeof( ifr.ifr_name ) - 1 );

	if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFINDEX) failed" );
		return( 1 );
	}

	if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFHWADDR) failed" );
		return( 1 );
	}

	memcpy( pl->pl_mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

	/* XXX */
	memcpy(mac, pl->pl_mac, 6);
	return 0;
}

static struct wif *linux_open(char *iface)
{
	struct wif *wi;
	struct priv_linux *pl;

	wi = wi_alloc(sizeof(*pl));
	if (!wi)
		return NULL;
        wi->wi_write            = linux_write;
        linux_nl80211_init(&state);
        wi->wi_close            = linux_close_nl80211;
	wi->wi_fd		= linux_fd;
	wi->wi_get_mac		= linux_get_mac;


	if (do_linux_open(wi, iface)) {
		do_free(wi);
		return NULL;
	}

	return wi;
}

struct wif *wi_open_osdep(char *iface)
{
        return linux_open(iface);
}
