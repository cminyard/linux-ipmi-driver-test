#!/bin/sh

# This little script tests a panic situation to see that the watchdog
# timer gets properly extended.  If this works, the system will reset
# 255 seconds after the sysrq-trigger gets written.  If not, it will
# reset 10 seconds after.  This test takes too long for the normal
# test procedure, and isn't that critical.

insmod ipmi_msghandler.ko
insmod i2c-i801.ko
insmod ipmi_si.ko
insmod ipmi_ssif.ko
insmod ipmi_devintf.ko
insmod ipmi_watchdog.ko
echo 20 >/sys/module/ipmi_watchdog/parameters/timeout
echo 1 >/dev/watchdog
sleep 10
echo c >/proc/sysrq-trigger
