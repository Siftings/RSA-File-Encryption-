"""
Cifrado y Descifrado RSA - Laboratorio 03
Ciberseguridad
Universidad de los Andes
===================================================
Este módulo implementa las funciones de cifrado y descifrado usando el
algoritmo RSA con el esquema de padding OAEP (Optimal Asymmetric Encryption
Padding) y la función hash SHA-256.

Autor: Juan David Daza
Fecha: Febrero 2026
"""

# Includes

from Crypto.Cipher import PKCS1_OAEP  # Implementación del cifrado RSA con padding OAEP
from Crypto.Hash import SHA256         # Función hash SHA-256, usada internamente por OAEP



def cifrar_con_rsa(datos_planos, clave_publica):
    # Esta funcion cifra datos usando RSA-OAEP con SHA 256 y la clave publica del destinatario
    # El resultado es un bloque de datos cifrados con el mismo tamaño que la clave RSA (384 bytes para RSA 3072 bits)

    # Crear el objeto cifrador RSA-OAEP
    cifrador = PKCS1_OAEP.new(clave_publica, hashAlgo=SHA256)

    # Cifrar los datos con RSA-OAEP
    datos_cifrados = cifrador.encrypt(datos_planos)

    return datos_cifrados


def descifrar_con_rsa(datos_cifrados, clave_privada):
    # Esta funcion descifra datos cifrados con RSA-OAEP usando la clave privada del destinatario
    
    # Crear el objeto descifrador RSA-OAEP con la misma configuracion que el cifrador

    descifrador = PKCS1_OAEP.new(clave_privada, hashAlgo=SHA256)

    # Intentar descifrar los datos, si la clave no es correcta o los datos estan corruptos, lanza una excepcion ValueError
    try:
        datos_planos = descifrador.decrypt(datos_cifrados)
    except ValueError as error:
        print(f"Error al descifrar con RSA: clave privada incorrecta o datos corruptos.")
        return None  
    # Retornar los datos originales descifrados
    return datos_planos
