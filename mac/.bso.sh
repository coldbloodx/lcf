#!/bin/bash

set -x 

username=xwuxwu@cn.ibm.com
password=pconline.com

hqhost=proxy23
xahost=gseed

echo "bso for hq gateway"
expect << EOF
set timeout 60
spawn telnet $hqhost

expect {
    "Username:" {send "$username\r"; exp_continue;}
    "Password:" {send "$password\r"; exp_continue;}
    {send "\n"; exit 0 }
    timeout {puts "Timeout! Unable to input username or password"; exit 1;}
}
catch wait result;
EOF

echo "bso for xa gateway"
expect << EOF
set timeout 60
spawn telnet $xahost

expect {
    "Username:" {send "$username\r"; exp_continue;}
    "Password:" {send "$password\r"; exp_continue;}
    {send "\n"; exit 0 }
    timeout {puts "Timeout! Unable to input username or password"; exit 1;}
}
catch wait result;
EOF