#!/usr/bin/gnuplot
#chmod +x ejemploGNUplot.gp

# Salida por pantalla simple: sudo apt-get install gnuplot-x11; set term 11
set term dumb

#set data style points
set title titulo
set xlabel ejex
set ylabel ejey
plot entrada using 1:2 with steps title titulo2

# Para salida a un archivo tipo portable network graphics
set term jpeg
set output imagen
replot

# Cierra el archivo de salida
set output

#pause -1 "Pulse Enter para continuar"
