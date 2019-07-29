#!/bin/bash

echo "Remove old files"
rm -rf /etc/squid/refresh/generator.sh
rm -rf /etc/squid/refresh/config.list

echo "Create generator binaries"
cat >> /etc/squid/refresh/generator.sh << END
#!/usr/local/bin/bash
IPV6=ipv6_replace
#IPV6=`ip addr show | grep inet6 | grep l | cut -dl -f1 | cut -d/ -f1 | awk -F " " '{print $NF""$3}' | head -n1  | cut -d ":" -f 1,2,3,4`
ETH=`ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | grep -v "ens7"`
array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
MAXCOUNT=count_replace
count=1
port=port_replace
rnd_ip_block ()
{
    a=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    b=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    c=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    d=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
	echo http_port \$port >> /etc/squid/refresh/config.list
	echo acl user\$port myportname \$port >> /etc/squid/refresh/config.list
	echo tcp_outgoing_address \$IPV6:\$a:\$b:\$c:\$d user\$port >> /etc/squid/refresh/config.list
}
while [ "\$count" -le \$MAXCOUNT ] 
do
        rnd_ip_block
        let "count += 1"   
		let "port += 1"
        done
END

echo "Create configuration file"
bash /etc/squid/refresh/generator.sh

echo "Create squid conf file"
rm -rf /etc/squid/squid.conf
IP_ALLOW_1=allow1_replace
IP_ALLOW_2=allow2_replace
cat >> /etc/squid/squid.conf << END
# Log
logformat squid %tg.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt
access_log /var/log/squid/access.log squid
# Cache
cache_dir aufs /var/cache/squid 1024 16 256
coredump_dir /var/spool/squid
acl QUERY urlpath_regex cgi-bin \?
cache deny QUERY
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
# Network ACL
acl localnet src 10.0.0.0/8     # RFC 1918 possible internal network
acl localnet src 172.16.0.0/12  # RFC 1918 possible internal network
acl localnet src 192.168.0.0/16 # RFC 1918 possible internal network
acl localnet src fc00::/7       # RFC 4193 local private network range
acl localnet src fe80::/10      # RFC 4291 link-local (directly plugged) machines
# Port ACL
acl SSL_ports port 443          # https
acl SSL_ports port 563          # snews
acl SSL_ports port 873          # rync
acl Safe_ports port 80 8080     # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443 563     # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl purge method PURGE
acl CONNECT method CONNECT
# Access Restrictions
acl to_ipv4 dst ipv4 
http_access deny to_ipv4 
http_access allow manager localhost
http_access deny manager
http_access allow purge localhost
http_access deny purge
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_reply_access allow all
htcp_access deny all
icp_access deny all
always_direct allow all
# Allow for IP adress
acl server1 src $IP_ALLOW_1
http_access allow server1 
acl server2 src $IP_ALLOW_2
http_access allow server2
#http_access allow all
# General
visible_hostname firefox
forwarded_for delete
forwarded_for off
via off
dns_v4_first off
follow_x_forwarded_for deny all
request_header_access X-Forwarded-For deny all
tcp_outgoing_address 127.0.0.1 all
$(cat /etc/squid/refresh/config.list)
# Request Headers Forcing
request_header_access Allow allow all
request_header_access X-Forwarded-For deny all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access Cookie allow all
request_header_access From deny all
request_header_access Referer deny all
request_header_access User-Agent deny all
# Response Headers Spoofing
follow_x_forwarded_for deny all
reply_header_access Via deny all
reply_header_access X-Cache deny all
reply_header_access X-Cache-Lookup deny all
END

echo "Completed squid refresh service"
/etc/init.d/squid reload

exit 0
