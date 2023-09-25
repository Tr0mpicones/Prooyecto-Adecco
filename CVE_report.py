#!/usr/bin/python3
#-*- encoding utf-8 -*-
import requests
from bs4 import BeautifulSoup
import html2text
import nmap
import re

# Limitaciones: de momento solo analiza los CVE todas las demás nomeclaturas.

def escaneo_normalizado(ip):
    # Escanea el objetivo y almacena resultados de CVE y notas encontrados.
    # Patron para buscar el código CVE y la nota del escaneo con vulners.
    patron = re.compile(r"CVE-[0-9]{4}-[0-9]{4}\s+[0-9]{1,2}\.[0-9]")

    escaneo = nmap.PortScanner()  # Variable Objeto de nmap.
    # Escaneo al objetivo con salida a archivo.
    vulnersS = escaneo.scan(hosts= ip, arguments='-A -T4 --script vulners -oN nmap_scan_vulners.txt')  # 

    #Limpieza del archivo generado en el escaneo y normalizado para la búsqueda web.
    with open("CVE_notas.txt", "w") as mngrCVE_notas:
        with open("nmap_scan_vulners.txt", "r") as mngrCVE:
            lista_lineas = mngrCVE.readlines()
            for linea in lista_lineas:
                coincidencias = patron.findall(linea)
                if coincidencias:
                    #print(coincidencias)
                    mngrCVE_notas.write(coincidencias[0] + "\n")



def codigoCVE():
    lista_cve_nota = []
    # Abrir resultado de nmap para discriminar entre código CVE y nota.
    with open("CVE_notas.txt","r") as mngrCVE:

        for i in mngrCVE:
            #print(i)
            cve_code = i.split("\t")[0] # Primer dato es CVE.
            nota = i.split("\t")[1] # Segundo dato es Nota.
            lista_cve_nota.append(cve_code)
            #print(cve_code, nota)
    return lista_cve_nota

def consulta(cve):
    url_base = 'https://www.cvedetails.com/cve-details.php?t=1&cve_id='
    url = url_base + cve # Construir url para petición.
    # Obtener el código fuente de la página web.
    response = requests.get(url)
    html = response.text

    # Analizar el código HTML con BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    # Encontrar la tabla con el identificador y la clase especificados
    tabla = soup.find('table', {'id': 'cvssscorestable', 'class': 'details'})

    if tabla:
        # Obtener el contenido de la tabla sin etiquetas HTML
        descripcion = html2text.HTML2Text()
        descripcion.ignore_links = True
        tabla_contenido = descripcion.handle(str(tabla))

        return cve, tabla_contenido

    else:
        print('No se encontró la tabla en el código fuente de la página.')
  
def reporte(cve_lista):
    with open("reporte.txt","w") as mngrReporte:
        for cve in cve_lista:
            nombre, datosCVE = consulta(cve)
            mngrReporte.write("________________________________________________________" + "\n")
            mngrReporte.write(nombre + "\n")
            mngrReporte.write(datosCVE + "\n")
        

        
if __name__ == "__main__":
    ip = input('IP del equipo victima -> ')
    print(f"Escaneando host {ip} - Puede tardar unos minutos..."
    escaneo_normalizado(ip)
    cve_lista = codigoCVE()
    reporte(cve_lista)