#!/bin/bash -e

make
echo -n copying wrath binary into /usr/sbin ... " "
cp wrath /usr/sbin
echo ok
echo -n copying wrath manpage into /usr/share/man/man8 ... " "
cp man/wrath.8 /usr/share/man/man8
echo ok
echo wrath successfully installed 
