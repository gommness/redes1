#!/bin/bash
tshark -r traza.pcap -T fields -e 'frame.time_delta_displayed' -Y 'tcp' -Y 'ip.src eq 36.173.217.43' > aux6_src.txt
tshark -r traza.pcap -T fields -e 'frame.time_delta_displayed' -Y 'tcp' -Y 'ip.dst eq 36.173.217.43' > aux6_dst.txt

./crearCDF aux6_src.txt ejercicio6_src.txt
./crearCDF aux6_dst.txt ejercicio6_dst.txt
gnuplot -e "entrada = 'ejercicio6_src.txt'; titulo = 'tiempos de llegada de flujo TCP'; ejex = 'tiempos de llegada'; ejey = 'ECDF'; titulo2 = 'ECDF source';imagen = 'ejercicio6_src.jpeg'" ejemploGNUplot.gp
gnuplot -e "entrada = 'ejercicio6_dst.txt'; titulo = 'tiempos de llegada de flujo TCP'; ejex = 'tiempos de llegada'; ejey = 'ECDF'; titulo2 = 'ECDF destino';imagen = 'ejercicio6_dst.jpeg'" ejemploGNUplot.gp

rm aux6_src.txt
rm aux6_dst.txt
