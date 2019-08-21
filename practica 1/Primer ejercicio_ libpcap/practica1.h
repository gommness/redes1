/***************************************************************************
practica1.h
	Muestra el tiempo de llegada de los paquetes a la interface eth0
	y los vuelca a traza correctamente nueva con tiempo actual menos un mes
	o lee trazas ya creadas

 Compila: gcc -Wall -o practica1 practica1.c -lpcap
 Autor: Carlos Li Hu y Javier Gomez Martinez
 2016 EPS-UAM
 ***************************************************************************/
#ifndef PRACTICA1_H
#define PRACTICA1_H
#endif
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#define OK 0
#define ERROR 1

#define ETH_FRAME_MAX 1514	// Tamanio maximo trama ethernet
