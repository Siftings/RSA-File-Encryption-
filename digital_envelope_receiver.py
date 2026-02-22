"""
Receptor del Sobre Digital - Laboratorio 03
Ciberseguridad
Universidad de los Andes
===================================================
Este modulo cumple la funcion de "abrir" el sobre digital, dado a que el receptor recive 2 
archivo, el primero (.enc) es el archivo cifrado con AES. El segundo (.envelope) es el sobre digital
que contiene la constraseña AES cifrada con RSA. De manera que solo el receptor que es el dueño de 
la clave privada, puede recuperar la contraseña AES, para poder descifrar el archivo .enc

Autor: Juan David Daza
Fecha: Febrero 2026
"""

# Import de librerias
import os   

# Importar la funcion de descifrado AES, correspondiente al laboratorio 02.
from aes_file_encryptor import descifrar_archivo

# Importar la funcion para cargar claves privadas RSA
from rsa_key_manager import cargar_clave_privada

# Importar la funcion de descifrado RSA-OAEP
from rsa_cipher import descifrar_con_rsa



def abrir_sobre_digital(ruta_cifrada, ruta_sobre, ruta_clave_privada):
    # Esta funcion abre un sobre digital
    # Primero lee el envelope, en el cual con la clave privada RSA se recupera la clave simetria AES
    # Luego se usa la clave AES recuperada para descifrar el archivo cifrado con AES
    # El resultado es el archivo original descifrado


    # Verificar que el archivo cifrado (.enc) existe
    if not os.path.isfile(ruta_cifrada):
        print(f"Error: El archivo cifrado '{ruta_cifrada}' no existe.")
        return None  

    # Verificar que el sobre digital (.envelope) existe
    if not os.path.isfile(ruta_sobre):
        print(f"Error: El sobre digital '{ruta_sobre}' no existe.")
        return None  

    # Cargar la clave privada RSA del receptor desde el archivo PEM
    clave_privada = cargar_clave_privada(ruta_clave_privada)

    # Verificar que la clave se cargó correctamente
    if clave_privada is None:
        return None  

    # Paso 1: Leer el sobre digital (.envelope) 

    # El archivo .envelope contiene la contraseña AES cifrada con RSA
    # Su tamaño es fijo: 384 bytes para clave RSA de 3072 bits
    print("\n[Paso 1/3] Leyendo sobre digital...")
    with open(ruta_sobre, 'rb') as archivo_sobre:
        password_cifrada_rsa = archivo_sobre.read()  # Leer todo el contenido (384 bytes)

    # Mostrar el tamaño leído para verificación
    print(f"  Sobre leido: {len(password_cifrada_rsa)} bytes")

    # Paso 2: Descifrar la contraseña AES con RSA 

    # Usar la clave privada RSA para descifrar la contraseña AES
    print("\n[Paso 2/3] Descifrando contrasena AES con RSA (clave privada)...")
    password_recuperada = descifrar_con_rsa(password_cifrada_rsa, clave_privada)

    # Verificar que el descifrado RSA fue exitoso
    if password_recuperada is None:
        print("Error: No se pudo recuperar la contrasena AES del sobre digital.")
        print("  Posibles causas:")
        print("    - La clave privada no corresponde a la publica usada para cifrar.")
        print("    - El archivo .envelope esta corrupto o fue modificado.")
        return None  

    # Mostrar confirmación de que la contraseña fue recuperada 
    # Deberia ser 32 bytes (256 bits) para AES-256
    print(f"  Contrasena AES recuperada: {len(password_recuperada) * 8} bits")

    # Paso 3: Descifrar el archivo con AES 

    # Usar la contraseña AES recuperada para descifrar el archivo .enc
    print("\n[Paso 3/3] Descifrando archivo con AES-256-CBC...")
    ruta_descifrada = descifrar_archivo(ruta_cifrada, password_recuperada)

    # Resumen final 

    # Obtener tamaño del archivo descifrado para el resumen
    size_descifrado = os.path.getsize(ruta_descifrada)

    # Mostrar resumen con el resultado
    print(f"\n{'=' * 60}")
    print("  SOBRE DIGITAL ABIERTO EXITOSAMENTE")
    print(f"{'=' * 60}")
    print(f"  Archivo descifrado: {ruta_descifrada} ({size_descifrado} bytes)")
    print(f"{'=' * 60}")

    # Retornar la ruta del archivo descifrado
    return ruta_descifrada