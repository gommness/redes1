#!/bin/bash
tshark -r traza.pcap -T fields -e 'frame.time_relative' -e 'frame.len' -Y 'eth.src eq 00:11:88:CC:33:32 '> aux8_src.txt
tshark -r traza.pcap -T fields -e 'frame.time_relative' -e 'frame.len' -Y 'eth.dst eq 00:11:88:CC:33:32 '> aux8_dst.txt
cat aux8_src.txt aux8_dst.txt > aux8_tot.txt

awk 'BEGIN {
}
{
	suma_valores[int($1)] = suma_valores[int($1)] + $2;
}
END {
	for (valor in suma_valores) {
	suma_valores[valor] = suma_valores[valor] * 8;
	print valor " " suma_valores[valor];
}
}' aux8_src.txt | sort -n > ejercicio8_src.txt

awk 'BEGIN {
}
{
	suma_valores[int($1)] = suma_valores[int($1)] + $2;
}
END {
	for (valor in suma_valores) {
	suma_valores[valor] = suma_valores[valor] * 8;
	print valor " " suma_valores[valor];
}
}' aux8_dst.txt | sort -n > ejercicio8_dst.txt

awk 'BEGIN {
}
{
	suma_valores[int($1)] = suma_valores[int($1)] + $2;
}
END {
	for (valor in suma_valores) {
	suma_valores[valor] = suma_valores[valor] * 8;
	print valor " " suma_valores[valor];
}
}' aux8_tot.txt | sort -n > ejercicio8_tot.txt

gnuplot -e "entrada = 'ejercicio8_src.txt'; titulo = 'ancho de banda'; ejex = 'tiempo'; ejey = 'ancho de banda'; titulo2 = 'ancho de banda source';imagen = 'ejercicio8_src.jpeg'" ejemploGNUplot.gp
gnuplot -e "entrada = 'ejercicio8_dst.txt'; titulo = 'ancho de banda'; ejex = 'tiempo'; ejey = 'ancho de banda'; titulo2 = 'ancho de banda destino';imagen = 'ejercicio8_dst.jpeg'" ejemploGNUplot.gp
gnuplot -e "entrada = 'ejercicio8_tot.txt'; titulo = 'ancho de banda'; ejex = 'tiempo'; ejey = 'ancho de banda'; titulo2 = 'ancho de banda total';imagen = 'ejercicio8_tot.jpeg'" ejemploGNUplot.gp

rm aux8_src.txt
rm aux8_dst.txt
rm aux8_tot.txt
