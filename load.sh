#!/bin/sh
set -e
rmmod can-tp20
insmod can-tp20.ko
