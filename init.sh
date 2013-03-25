#/!/bin/sh
set -e
modprobe can
modprobe vcan
ip link add dev vcan0 type vcan
ip link set vcan0 up
insmod can-tp20.ko
