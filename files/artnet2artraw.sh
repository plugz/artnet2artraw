#!/bin/sh

# airmon-zc start <INTERFACE> <WIFI_CHANNEL>
/usr/sbin/airmon-zc start wlan0 1

# just in case, 1 second delay
sleep 1

/usr/sbin/artnet2artraw wlan0mon
