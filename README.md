make package/artnet2artraw/compile -j3
scp ./staging_dir/target-mipsel_24kc_musl/root-ramips/usr/sbin/artnet2artraw root@10.0.0.50:/usr/sbin
