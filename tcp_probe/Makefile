# 
# Copyright (C) Alcatel-Lucent 2013
# All rights reserved.
#
# Alcatel-Lucent Proprietary Information.
#
# Contains proprietary/trade secret information which is the property of 
# Alcatel-Lucent and must not be made available to, or copied or used by
# anyone outside Alcatel-Lucent without its written authorization.
#
# Authors: 
#   Rafael Laufer <rafael.laufer@alcatel-lucent.com>
#

obj-m += tcp_probe.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f Module.markers modules.order
