# 2026-08-17 13:06:38 by RouterOS 7.23.3
# software id = 9C4L-801U
#
# model = RBD52G-5HacD2HnD
# serial number = <REDACTED>
/interface bridge
add admin-mac=B8:69:F4:06:59:69 auto-mac=no comment=defconf name=bridge
/interface ethernet
set [ find default-name=ether1 ] l2mtu=1598
set [ find default-name=ether2 ] l2mtu=1598
set [ find default-name=ether3 ] l2mtu=1598
set [ find default-name=ether4 ] l2mtu=1598
set [ find default-name=ether5 ] l2mtu=1598
/interface wireless
set [ find default-name=wlan1 ] band=2ghz-b/g/n channel-width=20/40mhz-XX \
    disabled=no distance=indoors frequency=auto mode=ap-bridge ssid=Leo-m \
    wireless-protocol=802.11
set [ find default-name=wlan2 ] band=5ghz-a/n/ac channel-width=\
    20/40/80mhz-XXXX distance=indoors frequency=auto mode=ap-bridge ssid=\
    Leo-m wireless-protocol=802.11
/interface wireguard
add listen-port=51820 mtu=1420 name=wg0
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
/interface wireless security-profiles
set [ find default=yes ] authentication-types=wpa-psk,wpa2-psk mode=\
    dynamic-keys supplicant-identity=MikroTik
/ip pool
add name=default-dhcp ranges=192.168.88.10-192.168.88.254
/ip dhcp-server
add address-pool=default-dhcp interface=bridge lease-time=1d name=defconf
/routing table
add comment="policy: abroad -> sing-box VM" fib name=table_vps
add comment="policy: work -> wg-work" fib name=table_work
/system script
add dont-require-permissions=no name=global-config-overlay owner=hermes \
    policy=reboot,read,write,test,password,sniff,sensitive,romon source=":glob\
    al TelegramTokenId \"<REDACTED-TELEGRAM-TOKEN>\";\
    \n:global TelegramChatId \"<REDACTED-CHAT-ID>\";\
    \n:global TelegramChatIdsTrusted { <REDACTED-CHAT-ID> };"
add dont-require-permissions=no name=test-script owner=hermes policy=\
    reboot,read,write,test,password,sniff,sensitive,romon source=\
    ":put \"hello\""
/disk settings
set auto-media-interface=bridge auto-media-sharing=yes auto-smb-sharing=yes
/interface bridge port
add bridge=bridge comment=defconf interface=ether2
add bridge=bridge comment=defconf interface=ether3
add bridge=bridge comment=defconf interface=ether4
add bridge=bridge comment=defconf interface=ether5
add bridge=bridge comment=defconf interface=wlan1
add bridge=bridge comment=defconf interface=wlan2
/ip neighbor discovery-settings
set discover-interface-list=LAN
/interface detect-internet
set detect-interface-list=all
/interface list member
add comment=defconf interface=bridge list=LAN
add comment=defconf interface=ether1 list=WAN
add interface=wg0 list=LAN
/interface wireguard peers
add allowed-address=10.200.200.2/32 interface=wg0 name=client1 \
    persistent-keepalive=25s public-key=\
    "LjYamno/RpPE6BxNYoywKWO9ImqqK/fAQb6DSr/XGlU="
add allowed-address=10.200.200.3/32 interface=wg0 name=client2 \
    persistent-keepalive=25s public-key=\
    "3Dzp1FMna0Uafko0cPDrq4kaHHL5Z3RJ3XX6XWzGEFw="
add allowed-address=10.200.200.4/32 interface=wg0 name=client3 \
    persistent-keepalive=25s public-key=\
    "YnflWE0yrlXWaI2ZJGLZUylp1RDYodYDVTOTCVDA51k="
/ip address
add address=192.168.88.1/24 comment=defconf interface=bridge network=\
    192.168.88.0
add address=10.200.200.1/24 comment=WireGuard-VPN interface=wg0 network=\
    10.200.200.0
/ip dhcp-client
add comment=defconf interface=ether1 name=ether1 use-peer-dns=no \
    use-peer-ntp=no
/ip dhcp-server network
add address=192.168.88.0/24 comment=defconf dns-server=192.168.88.1 gateway=\
    192.168.88.1
/ip dns
set allow-remote-requests=yes servers=192.168.88.45,1.1.1.1
/ip dns static
add address=192.168.88.1 comment=defconf name=router.lan type=A
/ip firewall address-list
add address=192.168.88.0/24 comment="policy: never route via policy tables" \
    list=policy-exempt
add address=10.200.200.0/24 comment="policy: never route via policy tables" \
    list=policy-exempt
add address=127.0.0.0/8 comment="policy: never route via policy tables" list=\
    policy-exempt
add address=169.254.0.0/16 comment="policy: never route via policy tables" \
    list=policy-exempt
add address=224.0.0.0/4 comment="policy: never route via policy tables" list=\
    policy-exempt
add address=255.255.255.255 comment="policy: never route via policy tables" \
    list=policy-exempt
add address=8.8.8.8 comment="TEST: \D0\BF\D1\80\D0\BE\D0\B2\D0\B5\D1\80\D0\BA\
    \D0\B0 \D0\BA\D0\BB\D0\B0\D1\81\D1\81\D0\B8\D1\84\D0\B8\D0\BA\D0\B0\D1\82\
    \D0\BE\D1\80\D0\B0, \D1\83\D0\B4\D0\B0\D0\BB\D0\B8\D1\82\D1\8C \D0\BF\D0\
    \BE\D1\81\D0\BB\D0\B5 \D1\88\D0\B0\D0\B3\D0\B0 1.5" list=abroad
add address=10.0.0.0/8 comment="work: \D0\BA\D0\BE\D1\80\D0\BF\D0\BE\D1\80\D0\
    \B0\D1\82\D0\B8\D0\B2\D0\BD\D0\B0\D1\8F \D1\81\D0\B5\D1\82\D1\8C (F7)" \
    list=work
/ip firewall filter
add action=accept chain=input comment=\
    "defconf: accept established,related,untracked" connection-state=\
    established,related,untracked
add action=drop chain=input comment="defconf: drop invalid" connection-state=\
    invalid
add action=accept chain=input comment=whitelist-LAN src-address=\
    192.168.88.0/24
add action=accept chain=input comment=whitelist-WG-clients src-address=\
    10.200.200.0/24
add action=drop chain=input comment=drop-port-scanners src-address-list=\
    port_scanners
add action=drop chain=input comment=drop-brute connection-state=new \
    src-address-list=login_attempt
add action=accept chain=input comment="defconf: accept ICMP" protocol=icmp
add action=accept chain=input comment=\
    "defconf: accept to local loopback (for CAPsMAN)" dst-address=127.0.0.1
add action=accept chain=input comment=HermesAI src-address=192.168.88.40
add action=accept chain=input comment=WireGuard-UDP dst-port=51820 protocol=\
    udp
add action=add-src-to-address-list address-list=port_scanners \
    address-list-timeout=2w chain=input comment=detect-port-scanners \
    protocol=tcp psd=21,3s,3,1
add action=add-src-to-address-list address-list=login_attempt \
    address-list-timeout=1h chain=input comment=detect-brute \
    connection-state=new dst-port=22,8291,443 protocol=tcp
add action=drop chain=input comment="defconf: drop all not coming from LAN" \
    in-interface-list=!LAN
add action=accept chain=forward comment="defconf: accept in ipsec policy" \
    ipsec-policy=in,ipsec
add action=accept chain=forward comment="defconf: accept out ipsec policy" \
    ipsec-policy=out,ipsec
add action=fasttrack-connection chain=forward comment="defconf: fasttrack (\D1\
    \82\D0\BE\D0\BB\D1\8C\D0\BA\D0\BE \D0\BD\D0\B5\D0\BC\D0\B0\D1\80\D0\BA\D0\
    \B8\D1\80\D0\BE\D0\B2\D0\B0\D0\BD\D0\BD\D1\8B\D0\B5 \E2\80\94 policy-safe,\
    \_O6)" connection-mark=no-mark connection-state=established,related
add action=accept chain=forward comment=\
    "defconf: accept established,related, untracked" connection-state=\
    established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" \
    connection-state=invalid
add action=drop chain=forward comment=\
    "defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat \
    connection-state=new in-interface-list=WAN
add action=accept chain=input comment=allow-DNS-LAN dst-port=53 \
    in-interface-list=LAN protocol=udp
add action=drop chain=input comment=block-DNS-WAN dst-port=53 \
    in-interface-list=WAN protocol=udp
/ip firewall mangle
add action=accept chain=prerouting comment="policy 00: local/exempt dst -> \D0\
    \B1\D0\B5\D0\B7 \D0\BC\D0\B0\D1\80\D0\BA\D0\B8\D1\80\D0\BE\D0\B2\D0\BA\D0\
    \B8" dst-address-list=policy-exempt
add action=mark-connection chain=prerouting comment=\
    "policy 10: abroad -> conn_abroad" connection-state=new dst-address-list=\
    abroad in-interface-list=LAN new-connection-mark=conn_abroad
add action=mark-routing chain=prerouting comment=\
    "policy 11: conn_abroad -> table_vps" connection-mark=conn_abroad \
    in-interface-list=LAN new-routing-mark=table_vps passthrough=no
add action=mark-connection chain=prerouting comment=\
    "policy 20: work -> conn_work (\D0\B6\D0\B4\D1\91\D1\82 wg-work)" \
    connection-state=new disabled=yes dst-address-list=work \
    in-interface-list=LAN new-connection-mark=conn_work
add action=mark-routing chain=prerouting comment=\
    "policy 21: conn_work -> table_work (\D0\B6\D0\B4\D1\91\D1\82 wg-work)" \
    connection-mark=conn_work disabled=yes in-interface-list=LAN \
    new-routing-mark=table_work passthrough=no
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" \
    ipsec-policy=out,none out-interface-list=WAN
/ip route
add comment="table_vps fail-open: abroad -> WAN direct" distance=10 \
    dst-address=0.0.0.0/0 gateway=91.200.224.129 routing-table=table_vps
/ip service
set ftp disabled=yes
set telnet disabled=yes
set www disabled=yes
set www-ssl address=0.0.0.0/0 certificate=www-ssl-cert disabled=no
set api address=192.168.88.0/24
set api-ssl disabled=yes
/ip upnp
set enabled=yes
/ip upnp interfaces
add interface=bridge type=internal
add interface=ether1 type=external
/ipv6 firewall address-list
add address=::/128 comment="defconf: unspecified address" list=bad_ipv6
add address=::1/128 comment="defconf: lo" list=bad_ipv6
add address=fec0::/10 comment="defconf: site-local" list=bad_ipv6
add address=::ffff:0.0.0.0/96 comment="defconf: ipv4-mapped" list=bad_ipv6
add address=::/96 comment="defconf: ipv4 compat" list=bad_ipv6
add address=100::/64 comment="defconf: discard only " list=bad_ipv6
add address=2001:db8::/32 comment="defconf: documentation" list=bad_ipv6
add address=2001:10::/28 comment="defconf: ORCHID" list=bad_ipv6
add address=3ffe::/16 comment="defconf: 6bone" list=bad_ipv6
/ipv6 firewall filter
add action=accept chain=input comment=\
    "defconf: accept established,related,untracked" connection-state=\
    established,related,untracked
add action=drop chain=input comment="defconf: drop invalid" connection-state=\
    invalid
add action=accept chain=input comment="defconf: accept ICMPv6" protocol=\
    icmpv6
add action=accept chain=input comment="defconf: accept UDP traceroute" \
    dst-port=33434-33534 protocol=udp
add action=accept chain=input comment=\
    "defconf: accept DHCPv6-Client prefix delegation." dst-port=546 protocol=\
    udp src-address=fe80::/10
add action=accept chain=input comment="defconf: accept IKE" dst-port=500,4500 \
    protocol=udp
add action=accept chain=input comment="defconf: accept ipsec AH" protocol=\
    ipsec-ah
add action=accept chain=input comment="defconf: accept ipsec ESP" protocol=\
    ipsec-esp
add action=accept chain=input comment=\
    "defconf: accept all that matches ipsec policy" ipsec-policy=in,ipsec
add action=drop chain=input comment=\
    "defconf: drop everything else not coming from LAN" in-interface-list=\
    !LAN
add action=fasttrack-connection chain=forward comment="defconf: fasttrack6" \
    connection-state=established,related
add action=accept chain=forward comment=\
    "defconf: accept established,related,untracked" connection-state=\
    established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" \
    connection-state=invalid
add action=drop chain=forward comment=\
    "defconf: drop packets with bad src ipv6" src-address-list=bad_ipv6
add action=drop chain=forward comment=\
    "defconf: drop packets with bad dst ipv6" dst-address-list=bad_ipv6
add action=drop chain=forward comment="defconf: rfc4890 drop hop-limit=1" \
    hop-limit=equal:1 protocol=icmpv6
add action=accept chain=forward comment="defconf: accept ICMPv6" protocol=\
    icmpv6
add action=accept chain=forward comment="defconf: accept HIP" protocol=139
add action=accept chain=forward comment="defconf: accept IKE" dst-port=\
    500,4500 protocol=udp
add action=accept chain=forward comment="defconf: accept ipsec AH" protocol=\
    ipsec-ah
add action=accept chain=forward comment="defconf: accept ipsec ESP" protocol=\
    ipsec-esp
add action=accept chain=forward comment=\
    "defconf: accept all that matches ipsec policy" ipsec-policy=in,ipsec
add action=drop chain=forward comment=\
    "defconf: drop everything else not coming from LAN" in-interface-list=\
    !LAN
/system clock
set time-zone-name=Europe/Moscow
/system ntp client
set enabled=yes
/system ntp client servers
add address=0.ru.pool.ntp.org
add address=1.ru.pool.ntp.org
add address=2.ru.pool.ntp.org
add address=3.ru.pool.ntp.org
/tool bandwidth-server
set enabled=no
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
