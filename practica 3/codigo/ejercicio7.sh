#!/bin/bash
tshark -r traza.pcap -T fields -e 'frame.time_delta_displayed' -Y 'udp' -Y 'udp.srcport eq 49714' > aux7_src.txt
tshark -r traza.pcap -T fields -e 'frame.time_delta_displayed' -Y 'udp' -Y 'udp.dstport eq 49714' > aux7_dst.txt

./crearCDF aux7_src.txt ejercicio7_src.txt
./crearCDF aux7_dst.txt ejercicio7_dst.txt
gnuplot -e "entrada = 'ejercicio7_src.txt'; titulo = 'tiempos de llegada de flujo UDP'; ejex = 'tiempos de llegada'; ejey = 'ECDF'; titulo2 = 'ECDF source';imagen = 'ejercicio7_src.jpeg'" ejemploGNUplot.gp
gnuplot -e "entrada = 'ejercicio7_dst.txt'; titulo = 'tiempos de llegada de flujo UDP'; ejex = 'tiempos de llegada'; ejey = 'ECDF'; titulo2 = 'ECDF destino';imagen = 'ejercicio7_dst.jpeg'" ejemploGNUplot.gp

rm aux7_src.txt
rm aux7_dst.txt
