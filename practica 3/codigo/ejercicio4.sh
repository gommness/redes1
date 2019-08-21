#!/bin/bash
tshark -r traza.pcap -T fields -e 'frame.len' -Y 'tcp' -Y 'tcp.srcport eq 80' > aux4_src.txt
tshark -r traza.pcap -T fields -e 'frame.len' -Y 'tcp' -Y 'tcp.dstport eq 80' > aux4_dst.txt

./crearCDF aux4_src.txt ejercicio4_src.txt
./crearCDF aux4_dst.txt ejercicio4_dst.txt
gnuplot -e "entrada = 'ejercicio4_src.txt'; titulo = 'tamaños de paquetes HTTP'; ejex = 'tamaños'; ejey = 'ECDF'; titulo2 = 'ECDF source';imagen = 'ejercicio4_src.jpeg'" ejemploGNUplot.gp
gnuplot -e "entrada = 'ejercicio4_dst.txt'; titulo = 'tamaños de paquetes HTTP'; ejex = 'tamaños'; ejey = 'ECDF'; titulo2 = 'ECDF destino';imagen = 'ejercicio4_dst.jpeg'" ejemploGNUplot.gp

rm aux4_src.txt
rm aux4_dst.txt
