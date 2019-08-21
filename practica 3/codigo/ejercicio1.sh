#!/bin/bash

nIP=$(tshark -r traza.pcap -T fields -e 'eth.type' -Y 'eth.type eq 0x0800 or (eth.type eq 0x8100 and vlan.etype eq 0x0800)' | wc -l)
nTOT=$(tshark -r traza.pcap -T fields -e 'eth.type' | wc -l)
IPpercent=$(expr 100 \* $nIP / $nTOT)
notIPpercent=$(expr 100 - $IPpercent)

echo -e "paquetes totales: $nTOT\npaquetes IP: $nIP\nporcentaje IP: $IPpercent %\nporcentaje no IP: $notIPpercent %\n"

nTCP=$(tshark -r traza.pcap -T fields -e 'eth.type' -Y 'ip.proto eq 6' | wc -l)
nUDP=$(tshark -r traza.pcap -T fields -e 'eth.type' -Y 'ip.proto eq 17' | wc -l)
TCPpercent=$(expr 100 \* $nTCP / $nIP)
UDPpercent=$(expr 100 \* $nUDP / $nIP)
OTHERSpercent=$(expr 100 - $TCPpercent - $UDPpercent)

echo -e "porcentaje paquetes TCP: $TCPpercent %\nporcentaje paquetes UDP: $UDPpercent %\nporcentaje paquetes distintos: $OTHERSpercent %"
