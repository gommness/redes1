/***************************************************************************
 practica2.h
 * cabecera de la practica 2

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Javier Gomez Martinez y Carlos Li Hu
 2015 EPS-UAM
 ***************************************************************************/

#ifndef PRACTICA2_H
#define PRACTICA2_H

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4   /* Tamanio de la direccion IP					*/

#define OK 0
#define ERROR 1
#define SI 1
#define NO 0

/*tamanios de campos de nivel 3*/
#define IP_IHL_LEN 1
#define IP_SERVICE_TYPE_LEN 1
#define IP_TOTAL_LEN 2
#define IP_ID_LEN 2
#define IP_POS_LEN 2
#define IP_LIFE_LEN 1
#define IP_PROTOCOL_LEN 1
#define IP_CHECKSUM_LEN 2
#define IP_SRC_LEN 4
#define IP_DST_LEN 4
#define IP_OP_LEN 3
#define IP_RELL_LEN 1

/*tamanios de campos nivel 4*/
#define SRC_PORT_LEN 2
#define DST_PORT_LEN 2
#define UDP_LEN 2










void analizar_paquete(const struct pcap_pkthdr *cabecera, const uint8_t *paquete);

void handleSignal(int nsignal);

#endif /* PRACTICA2_H */

