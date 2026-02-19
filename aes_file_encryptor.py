"""
Cifrado de archivos con AES - Laboratorio 02 
Ciberseguridad
Universidad de los Andes
===================================================
Este programa tiene el objetivo de cifrar y descifrar archivos usando el algoritmo AES-256 en modo CBC.
Con el fin de ser transferidos por FTP en una red interna.
EL programa hace el cifrado con AES-256-CBC, para esto se utilizaron 3 conceptos los cuales son:

'Derivacion de clave': Se utiliza PBKDF2 el cual es un estandar para poder generar una clave segura, que no pueda ser adivinada por medio de un diccionario, o fuerza bruta.
'Salt': Es un valor aleatorio autogenerado que se utiliza para que cada clave sea distinta entre si, esto para evitar que dada una clave hayada se pueda usar para descifrar otros archivos cifrados con la misma contraseña.
'IV': Otro valor aleatorio necesario para el CBC, el cual se utiliza en caso de que 2 archivos tengan los primeros 16 bytes iguales, se cifren de manera distinta, y esto por el 'efecto domino' se transfiere al resto del bloques del archivo.
'Padding': Es necesario dado que AES cifra bloques de 16 bytes, de esta mnera si el archivo no es multiplo de 16 bytes, se le agrega un relleno para completar el bloque, y al descifrar se remueve este relleno.

Autor: Juan David Daza
Fecha: Febrero 2026
"""


# Includes
import os
import sys
import getpass

from Crypto.Cipher import AES       # Implementacion del algoritmo AES, usando el modo CBC de PyCryptodome
from Crypto.Util.Padding import pad, unpad # Funciones para el padding
from Crypto.Protocol.KDF import PBKDF2     # FUncion para la derivacion de clave usando PBKDF2
from Crypto.Random import get_random_bytes # Generador de bytes aleatorios seguros


# Constantes
SIZE_SALT = 16
SIZE_IV = 16
SIZE_CLAVE = 32
ITERACIONES = 100000
SIZE_BLOQUE = 16
ENC = ".enc"


def derivar_clave(password, salt):
    # Genera la clave a partir de la contraseña elegida y 16 bytes random, despues es usado para hacer 100k iteraciones de SHA256, y generar la clave de 32 bytes (Propia de AES 256)
    clave = PBKDF2(
        password,
        salt,
        dkLen=SIZE_CLAVE,
        count=ITERACIONES
    )
    return clave


def cifrar_archivo(ruta_archivo, password):
    """
    Cifra el archivo con AES-256-CBC y lo guarda con la extension .enc
    Estructura:
    [salt (16 bytes)][IV (16 bytes)][datos cifrados]
    """
    if os.path.isfile(ruta_archivo) != True:
        print(f"El archivo '{ruta_archivo}' no existe.")
        sys.exit(1)

    # Leer el archivo
    with open(ruta_archivo, "rb") as f:
        datos_originales = f.read()

    print(f"Archivo leido: {ruta_archivo} ({len(datos_originales)} bytes)")

    # Generar salt aleatorio
    salt = get_random_bytes(SIZE_SALT)

    # Derivar clave con PBKDF2
    clave = derivar_clave(password, salt)

    # Generar IV 
    iv = get_random_bytes(SIZE_IV)

    # Inicializar el cifrador AES en modo CBC (Por lo cual requerie el IV)
    cifrador = AES.new(clave, AES.MODE_CBC, iv)

    # Aplicar padding y cifrar
    datos_con_padding = pad(datos_originales, SIZE_BLOQUE)
    datos_cifrados = cifrador.encrypt(datos_con_padding)

    # Guardar archivo cifrado
    ruta_cifrado = ruta_archivo + ENC
    with open(ruta_cifrado, "wb") as f:
        f.write(salt)
        f.write(iv)
        f.write(datos_cifrados)

    size_final = os.path.getsize(ruta_cifrado)
    print(f"Archivo cifrado: {ruta_cifrado} ({size_final} bytes)")

    return ruta_cifrado


def descifrar_archivo(ruta_cifrado, password):
    if os.path.isfile(ruta_cifrado) != True:
        print(f"El archivo '{ruta_cifrado}' no existe.")
        sys.exit(1)

    # Leer archivo cifrado
    with open(ruta_cifrado, "rb") as f:
        contenido = f.read()

    if len(contenido) < SIZE_SALT + SIZE_IV:
        print("Archivo corrupto, o muy pequeño para ser valido.")
        sys.exit(1)

    # Sacar salt, IV y datos cifrados
    salt = contenido[:SIZE_SALT] # De 0 a 16 bytes lee el salt
    iv = contenido[SIZE_SALT:SIZE_SALT + SIZE_IV] # De 16 a 32 bytes lee el IV
    datos_cifrados = contenido[SIZE_SALT + SIZE_IV:] # El resto es el contenido del archivo cifrado

    print(f"Archivo cifrado leido: {ruta_cifrado} ({len(contenido)} bytes)")

    # Derivar la misma clave usando la contraseña + salt extraido
    clave = derivar_clave(password, salt)

    # Crear descifrador AES en modo CBC con la misma clave y IV
    descifrador = AES.new(clave, AES.MODE_CBC, iv)

    # Descifrar y remover padding
    try:
        datos_con_padding = descifrador.decrypt(datos_cifrados)
        datos_originales = unpad(datos_con_padding, SIZE_BLOQUE)
    except ValueError:
        print("Contraseña incorrecta o archivo corrupto.")
        sys.exit(1)

    # Guardar archivo descifrado
    nombre_base, _ = os.path.splitext(ruta_cifrado)
    nombre_sin_ext, extension = os.path.splitext(nombre_base)
    ruta_descifrado = nombre_sin_ext + "_descifrado" + extension

    with open(ruta_descifrado, "wb") as f:
        f.write(datos_originales)

    print(f"Archivo descifrado: {ruta_descifrado} ({len(datos_originales)} bytes)")

    return ruta_descifrado


def menu():
    print("=" * 60)
    print("   Cifrado de archivos con AES-256-CBC")
    print("=" * 60)
    print()
    print("  [1] Cifrar un archivo")
    print("  [2] Descifrar un archivo")
    print("  [0] Salir")
    print()

    opcion = input("Seleccione una opcion: ").strip()

    if opcion == "1":
        ruta = input("Ruta del archivo a cifrar: ").strip()
        password = getpass.getpass("Contraseña para cifrar: ")
        password2 = getpass.getpass("Confirme de la contraseña: ")
        
        if password != password2:
            print("Las contraseñas no coinciden, intente de nuevo.")
            sys.exit(1)
        
        cifrar_archivo(ruta, password)

    elif opcion == "2":
        ruta = input("Ruta del archivo .enc a descifrar: ").strip()
        password = getpass.getpass("Contraseña para descifrar: ")
        descifrar_archivo(ruta, password)

    elif opcion == "0":
        print("Saliendo del programa. \nBye o/")
        sys.exit(0)

    else:
        print("Opcion no valida, intente de nuevo.")
        sys.exit(1)


if __name__ == "__main__":
    menu()
