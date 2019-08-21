#!/bin/bash
tshark -r traza.pcap -T fields -e 'frame.len' -Y 'eth.src eq 00:11:88:CC:33:32' > aux3_src.txt
tshark -r traza.pcap -T fields -e 'frame.len' -Y 'eth.dst eq 00:11:88:CC:33:32' > aux3_dst.txt

./crearCDF aux3_src.txt ejercicio3_src.txt
./crearCDF aux3_dst.txt ejercicio3_dst.txt
gnuplot -e "entrada = 'ejercicio3_src.txt'; titulo = 'tamaños de paquetes MAC = 00:11:88:CC:33:32'; ejex = 'tamaños'; ejey = 'ECDF'; titulo2 = 'ECDF source';imagen = 'ejercicio3_src.jpeg'" ejemploGNUplot.gp
gnuplot -e "entrada = 'ejercicio3_dst.txt'; titulo = 'tamaños de paquetes MAC = 00:11:88:CC:33:32'; ejex = 'tamaños'; ejey = 'ECDF'; titulo2 = 'ECDF destino';imagen = 'ejercicio3_dst.jpeg'" ejemploGNUplot.gp
rm aux3_src.txt
rm aux3_dst.txt
