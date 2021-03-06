#
# Copyright (C) 2006-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=artnet2artraw
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE

PKG_MAINTAINER:=Rick Farina <zerochaos@gentoo.org>

include $(INCLUDE_DIR)/package.mk

define Package/artnet2artraw
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=ArtNet
  DEPENDS:=+libpcap +libpthread +libopenssl +libnl-core +libnl-genl +zlib
  TITLE:=receive artnet, forward as raw wifi
  URL:=http://www.aircrack-ng.org/
endef

TARGET_CFLAGS += -std=gnu89

MAKE_FLAGS += prefix=/usr \
	libnl=true \
	sqlite=false \
	unstable=false \
	OSNAME=Linux

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/artnet2artraw/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/artnet2artraw $(1)/usr/sbin/
	$(INSTALL_BIN) files/artnet2artraw.sh $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) files/artnet2artraw.init $(1)/etc/init.d/artnet2artraw
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) files/artnet2artraw.config $(1)/etc/config/artnet2artraw
endef

$(eval $(call BuildPackage,artnet2artraw))
