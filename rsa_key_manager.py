"""
Gestión de Claves RSA - Laboratorio 03
Ciberseguridad
Universidad de los Andes
===================================================
Este modulo se encarga de generar el par de claves RSA para cada host, 
las guarda en formato PEM (Privacy Enhanced Mail). La clave privada se 
guarda con permisos restrictivos (600) para que solo el dueño pueda leerla.

Se utiliza RSA con 3072 bits, este tamaño es recomendado por NIST y su seguridad es equivalente a AES-128.

Autor: Juan David Daza
Fecha: Febrero 2026
"""

#Imports

import os   
import sys  

from Crypto.PublicKey import RSA  # Modulo de PyCryptodome para generar, importar y exportar claves RSA


#Const

RSA_KEY_SIZE = 3072  # Tamaño de la clave RSA
KEYS_DIR = "keys"    # Drectorio donde se guardan las claves RSA generadas



def generar_par_claves(nombre_maquina):
    # Genera las claves RSA con el nombre del host y las guarda en el directorio keys

    # Crear el directorio keys
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Generar el par de claves RSA usando PyCryptodome
    par_claves = RSA.generate(RSA_KEY_SIZE)

    # Exportar la clave privada 
    clave_privada_pem = par_claves.export_key(format='PEM')

    # Construir la ruta del archivo de clave privada
    ruta_privada = os.path.join(KEYS_DIR, f"{nombre_maquina}_private.pem")

    # Escribir la clave privada en el archivo 
    with open(ruta_privada, 'wb') as archivo_privado:
        archivo_privado.write(clave_privada_pem)

    # Establecer permisos del archivo a 600 (solo lectura/escritura para el dueño)
    os.chmod(ruta_privada, 0o600)

    # Exportar la clave publica
    clave_publica_pem = par_claves.publickey().export_key(format='PEM')

    # Construir la ruta del archivo de clave pública
    ruta_publica = os.path.join(KEYS_DIR, f"{nombre_maquina}_public.pem")

    # Escribir la clave pública en el archivo (sin restricciones de permisos)
    with open(ruta_publica, 'wb') as archivo_publico:
        archivo_publico.write(clave_publica_pem)

    # Info para al usuario
    print(f"\n  Clave privada guardada en: {ruta_privada}")
    print(f"  Clave publica guardada en: {ruta_publica}")
    print(f"\n  IMPORTANTE: La clave privada ({ruta_privada}) NUNCA debe compartirse.")

    # Return de las rutas en tuple
    return ruta_privada, ruta_publica


def cargar_clave_publica(ruta):

    #Carga una clave publica RSA desde la ruta de un archivo .PEM. Retorna un objeto de clave RSA para cifrar con RSA-OAEP

    # Verificar que el archivo existe antes de intentar leerlo
    if not os.path.isfile(ruta):
        print(f"Error: El archivo de clave publica '{ruta}' no existe.")
        return None  

    # Abrir el archivo en modo binario y leer su contenido 
    with open(ruta, 'rb') as archivo:
        contenido_pem = archivo.read() 

    # import_key() parsea el formato PEM y reconstruye el objeto de clave RSA
    # Tambien detecte si es la clave publica o privada automaticamente por el header del archivo PEM
    clave_publica = RSA.import_key(contenido_pem)

    print(f"Clave publica cargada desde: {ruta}")

    # Return del objeto de clave RSA 
    return clave_publica


def cargar_clave_privada(ruta):
    #Carga una clave privada RSA desde la ruta de un archivo .PEM. Retorna un objeto de clave RSA para descifrar con RSA-OAEP
    
    # Verificar que el archivo existe antes de intentar leerlo
    if not os.path.isfile(ruta):
        print(f"Error: El archivo de clave privada '{ruta}' no existe.")
        return None  

    # Abrir el archivo en modo binario y leer su contenido
    with open(ruta, 'rb') as archivo:
        contenido_pem = archivo.read() 

    # import_key() parsea el formato PEM y reconstruye el objeto de clave RSA
    # Para claves privadas, el objeto resultante contiene tanto la parte privada como la pública
    clave_privada = RSA.import_key(contenido_pem)

    print(f"Clave privada cargada desde: {ruta}")

    # Return del objeto de clave RSA
    return clave_privada


def listar_claves():
    # Lista las claves RSA en el directorio keys 

    # Verificar si el directorio de claves existe
    if not os.path.isdir(KEYS_DIR):
        print("No se han generado claves aun. Use la opcion [1] para generar un par.")
        return []  

    # Obtener lista de archivos .pem en el directorio, ordenados 
    archivos = sorted([f for f in os.listdir(KEYS_DIR) if f.endswith('.pem')])

    # Verificar si hay archivos
    if not archivos:
        print("No hay claves disponibles en el directorio 'keys/'.")
        return []  

    # Separar claves públicas y privadas para mostrarlas organizadamente
    publicas = [f for f in archivos if '_public.pem' in f]   # Filtrar claves públicas
    privadas = [f for f in archivos if '_private.pem' in f]  # Filtrar claves privadas

    # Mostrar claves públicas
    print("\n  Claves publicas:")
    for nombre in publicas:
        ruta_completa = os.path.join(KEYS_DIR, nombre)
        print(f"    - {ruta_completa}")

    # Mostrar claves privadas
    print("\n  Claves privadas:")
    for nombre in privadas:
        ruta_completa = os.path.join(KEYS_DIR, nombre)
        print(f"    - {ruta_completa}")
    
    # Return de la lista completa de claves RSA
    return archivos


if __name__ == "__main__":

    # Para propisito del laboratorio este archivo al ser ejecutado directamente muestra
    # un menu para generar un par de claves RSA de prueba
    print("=" * 60)
    print("   Generador de Claves RSA de prueba")
    print("=" * 60)

    # Solicitar nombre del host
    nombre = input("\nNombre del host (ej: student1): ").strip()

    if not nombre:
        print("Error: El nombre no puede estar vacio.")
        sys.exit(1)  

    # Generar el par de claves
    generar_par_claves(nombre)

    # Mostrar las claves generadas
    print("\n--- Claves disponibles ---")
    listar_claves()
