#!/bin/bash

#volcamos al fichero ip.dat las 10 direcciones ip mas frecuentes
tshark -r traza.pcap -T fields -e 'ip.src' > "aux.dat"
tshark -r traza.pcap -T fields -e 'ip.dst' >> "aux.dat"
sort aux.dat | uniq -c | sort -n -r | head -n 10 > "ip.dat"
echo "se ha creado el fichero ip.dat"
#volcamos al fichero ipBytes.dat los 10 paquetes mas grandes
tshark -r traza.pcap -T fields -e 'ip.src' -e 'frame.len' > "aux.dat"
tshark -r traza.pcap -T fields -e 'ip.dst' -e 'frame.len' >> "aux.dat"
awk 'BEGIN{FS = " "} {suma_valores[$1] = suma_valores[$1] + $2;} END{for(valor in suma_valores){
		print suma_valores[valor]"				"valor;
	}
}' aux.dat | sort -r -n | head -n 10 > "ipBytes.dat"
echo "se ha creado el fichero ipBytes.dat"

#volcamos al fichero tcp.dat los 10 puertos mas frecuentes
tshark -r traza.pcap -T fields -e 'tcp.dstport' -Y 'ip.proto eq 6' > "aux.dat"
tshark -r traza.pcap -T fields -e 'tcp.srcport' -Y 'ip.proto eq 6' >> "aux.dat"
sort aux.dat | uniq -c | sort -n -r | head -n 10 > "tcp.dat"
echo "se ha creado el fichero tcp.dat"
#volcamos al fichero tcpBytes.dat los 10 paquetes de tcp mas grandes
tshark -r traza.pcap -T fields -e 'tcp.dstport' -e 'frame.len' -Y 'ip.proto eq 6' > "aux.dat"
tshark -r traza.pcap -T fields -e 'tcp.srcport' -e 'frame.len' -Y 'ip.proto eq 6' >> "aux.dat"
awk 'BEGIN{FS = " "} {suma_valores[$1] = suma_valores[$1] + $2;} END{for(valor in suma_valores){
		print suma_valores[valor]"				"valor;
	}
}' aux.dat | sort -r -n | head -n 10 > "tcpBytes.dat"
echo "se ha creado el fichero tcpBytes.dat"

#volcamos al fichero udp.dat los 10 puertos mas frecuentes
tshark -r traza.pcap -T fields -e 'udp.dstport' -Y 'ip.proto eq 17' > "aux.dat"
tshark -r traza.pcap -T fields -e 'udp.srcport' -Y 'ip.proto eq 17' >> "aux.dat"
sort aux.dat | uniq -c | sort -n -r | head -n 10 > "udp.dat" 
echo "se ha creado el fichero udp.dat"
#volcamos al fichero udpBytes.dat los 10 paquetes de udp mas grandes
tshark -r traza.pcap -T fields -e 'udp.dstport' -e 'frame.len' -Y 'ip.proto eq 17' > "aux.dat"
tshark -r traza.pcap -T fields -e 'udp.srcport' -e 'frame.len' -Y 'ip.proto eq 17' >> "aux.dat"
awk 'BEGIN{FS = " "} {suma_valores[$1] = suma_valores[$1] + $2;} END{for(valor in suma_valores){
		print suma_valores[valor]"				"valor;
	}
}' aux.dat | sort -r -n | head -n 10 > "udpBytes.dat"
echo "se ha creado el fichero udpBytes.dat"

rm aux.dat
