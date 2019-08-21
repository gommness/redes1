#!/bin/bash
tshark -r traza.pcap -T fields -e 'frame.len' -Y 'udp' -Y 'udp.srcport eq 53' > aux5_src.txt
tshark -r traza.pcap -T fields -e 'frame.len' -Y 'udp' -Y 'udp.dstport eq 53' > aux5_dst.txt

./crearCDF aux5_src.txt ejercicio5_src.txt
./crearCDF aux5_dst.txt ejercicio5_dst.txt
gnuplot -e "entrada = 'ejercicio5_src.txt'; titulo = 'tamaños de paquetes DNS'; ejex = 'tamaños'; ejey = 'ECDF'; titulo2 = 'ECDF source';imagen = 'ejercicio5_src.jpeg'" ejemploGNUplot.gp
gnuplot -e "entrada = 'ejercicio5_dst.txt'; titulo = 'tamaños de paquetes DNS'; ejex = 'tamaños'; ejey = 'ECDF'; titulo2 = 'ECDF destino';imagen = 'ejercicio5_dst.jpeg'" ejemploGNUplot.gp

rm aux5_src.txt
rm aux5_dst.txt
