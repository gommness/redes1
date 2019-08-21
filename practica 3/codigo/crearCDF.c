/***********************************************************
 crearCDF.c	 
 Primeros pasos para implementar y validar la funcion crearCDF(). Est funcion debe devolver
 un fichero con dos columnas, la primera las muestras, la segunda de distribucion de
 probabilidad acumulada. En la version actual la funcion realiza los dos primeros pasos para
 este objetivo, cuenta el numero de muestras y las ordena.
 El alumno debe acabar su implementacion de crearCDF() y usar un main similar para validar su fucionamiento.
 
 Compila: gcc -Wall -o crearCDF crearCDF.c
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM 
***************************************************************************/

#include <stdio.h> 
#include <stdlib.h> 
#include <strings.h> 
#include <string.h> 

#define OK 0
#define ERROR 1

int crearCDF(char* filename_data, char* filename_cdf);

int main(int argc, char *argv[]){
	printf("El formato a introducir es ./crearCDF entrada salida\n");
	if(argc == 3){
		crearCDF(argv[1],argv[2]);
	}
	else 
		printf("Escribe bien el formato!! \n");
		
	return OK;
}

int crearCDF(char* filename_data, char* filename_cdf) {
	char comando[255]; char linea[255]; char aux[255];
	int num_lines, total=0, counter, i;
	FILE *f,*output;
	double ecdf=0,muestra;
//sin control errores
	sprintf(comando,"sort -n < %s > %s 2>&1",filename_data,filename_cdf);
	printf("Comando en ejecucion: %s\n",comando);
	f = popen(comando, "r");
	if(f == NULL){
		printf("Error ejecutando el comando\n");
		return ERROR;
	}
	bzero(linea,255);
	fgets(linea,255,f);
	printf("Retorno: %s\n",linea);
	pclose(f);
	/*Hasta aqui el codigo guarda en filename_cdf la columna de datos de forma ordenada*/
	
	
//crear CDF
	//vuelco en aux.txt el conjunto de frecuencias y muestras
	sprintf(comando,"uniq -c %s > aux.txt 2>&1",filename_cdf);
	printf("Comando en ejecucion: %s\n",comando);
	f = popen(comando, "r");
	if(f == NULL){
		printf("Error ejecutando el comando\n");
		return ERROR;
	}
	pclose(f);
	//cuento el numero de lineas en este fichero aux.txt
	sprintf(comando,"wc -l aux.txt 2>&1");
	printf("Comando en ejecucion: %s\n",comando);
	f = popen(comando, "r");
	if(f == NULL){
		printf("Error ejecutando el comando\n");
		return ERROR;
	}
	fgets(linea,255,f);
	printf("Retorno: %s\n",linea);
	sscanf(linea,"%d %s",&num_lines,aux);
	printf("Este es el numero de lineas: %d\n",num_lines);
	pclose(f);
	
	//abro el fichero aux.txt
	f=fopen("aux.txt","r");
	
	output=fopen(filename_cdf,"w");
	
	for(i=0;i<num_lines;i++){
		fscanf(f, "%d %lf",&counter,&muestra);
		total += counter;
	}
	fclose(f);
	f=fopen("aux.txt","r");
	for(i=0;i<num_lines;i++){
		fscanf(f, "%d %lf",&counter,&muestra);
		ecdf += counter;
		fprintf(output,"%lf %lf\n",muestra,(ecdf/total));
	}
	

	fclose(f);
	fclose(output);
	system("rm aux.txt");
	return OK;
}



