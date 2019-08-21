/***************************************************************************
 practica1.c
	Muestra el tiempo de llegada de los paquetes a la interface eth0
	y los vuelca a traza correctamente nueva con tiempo actual menos un mes
	o lee trazas ya creadas

 Compila: gcc -Wall -o practica1 practica1.c -lpcap
 Autor: Carlos Li Hu y Javier Gomez Martinez
 2016 EPS-UAM
 ***************************************************************************/

#include "practica1.h"

pcap_t *descr = NULL, *descr2 = NULL;
pcap_dumper_t *pdumper = NULL;
int contador = 0;

/*Esta funcion se encarga de imprimir los "len" bits del paquete "cadena"*/
void print_hex(uint8_t *cadena, int len) {
    int i;
    char palabra[1000];

    strcpy(palabra, "0X ");
    for (i = 0; i < len; i++) {
        sprintf(palabra, "%s %X ", palabra, cadena[i]);
    }
    printf("%s\n", palabra);
}

void handle(int nsignal) {
    printf("Control C pulsado\n");
    if (descr)
        pcap_close(descr);
    if (descr2)
        pcap_close(descr2);
    if (pdumper)
        pcap_dump_close(pdumper);
    printf("numero de paquetes recibidos: %d\n", contador);
    exit(OK);
}

int main(int argc, char **argv) {
    int retorno = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t *paquete = NULL;
    struct pcap_pkthdr *cabecera = NULL;
    char file_name[256];
    struct timeval time;

    /*capturamos la sennal SIGINT*/
    if (signal(SIGINT, handle) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    //Apertura de interface
    /*si no se especifica traza, se abre la interfaz eth0*/
    if (argc < 2) {
        if ((descr = pcap_open_live("eth0", ETH_FRAME_MAX, 0, 100, errbuf)) == NULL) {
            printf("Error: pcap_open_live(): %s, %s %d.\n", errbuf, __FILE__, __LINE__);
            exit(ERROR);
        }
        
    /*si se especifica la traza a analizar, se abre esta*/
    } else {
        if ((descr = pcap_open_offline(argv[1], errbuf)) == NULL) {
            printf("Error: pcap_open_offline(): %s, %s %d.\n", errbuf, __FILE__, __LINE__);
            exit(ERROR);
        }
    }

    //Volcado de traza
    /*Si se abre online, abrimos la traza donde volcaremos los datos*/
    if (argc < 2) {
    descr2 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX);
    if (!descr2) {
        printf("Error al abrir el dump.\n");
        pcap_close(descr);
        exit(ERROR);
    }
    gettimeofday(&time, NULL);
    sprintf(file_name, "eth0.%lld.pcap", (long long) time.tv_sec);
    
        pdumper = pcap_dump_open(descr2, file_name);
        if (!pdumper) {
            printf("Error al abrir el dumper: %s, %s %d.\n", pcap_geterr(descr2), __FILE__, __LINE__);
            pcap_close(descr);
            pcap_close(descr2);
        }
    }

    while (1) {
        retorno = pcap_next_ex(descr, &cabecera, (const u_char **) &paquete);

        if (retorno == -1) { //En caso de error
            printf("Error al capturar un paquete %s, %s %d.\n", pcap_geterr(descr), __FILE__, __LINE__);
            pcap_close(descr);
            if(descr2){
				pcap_close(descr2);
				if(pdumper)
					pcap_dump_close(pdumper);
			}
            exit(ERROR);
        } else if (retorno == 0) {
            continue;
        } else if (retorno == -2) {
            break;
        }


		/*imprimimos los 15 primeros bytes de dicho paquete*/
        print_hex(paquete, 15);
        //En otro caso
        contador++;
        printf("Nuevo paquete capturado a las %s\n", ctime((const time_t*) &(cabecera->ts.tv_sec)));
        if (pdumper) {
            /*restamos los 2592000 segundos que equivalen a un mes
             * y hacemos el dump en dicha traza*/
            cabecera->ts.tv_sec -= 2592000;
            
            pcap_dump((uint8_t *) pdumper, cabecera, paquete);
        }
    }
    pcap_close(descr);
    if (descr2) {
        pcap_close(descr2);
        if (pdumper)
            pcap_dump_close(pdumper);
    }
    printf("numero de paquetes leidos: %d\n", contador);
    return OK;
}
