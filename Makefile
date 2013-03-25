obj-m += can-tp20.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

init: all
	sudo ./init.sh

load: all
	sudo ./load.sh
