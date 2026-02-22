"""
Emisor del Sobre Digital - Laboratorio 03
Ciberseguridad
Universidad de los Andes
===================================================
Este modulo implementa la funcion de crear un sobre digital, que consiste en cifrar un archivo con una clave simetrica usando AES-256-CBC
y luego cifrar la clave simetrica con RSA-OAEP usando la clave publica del receptor. 
El resultado son dos archivos: el archivo cifrado con AES (.enc) y el sobre digital (.envelope) que contiene la clave AES cifrada con RSA.
Estos 2 archivos son enviados al receptor, quien con su clave privada RSA puede descifrar la contraseña AES y luego usarla para descifrar el archivo original.
Esto tiene varias ventajas, como la eficiencia del cifrado simetrico y la seguridad de la transferencia de claves por uso de una clave asimetrica.

Autor: Juan David Daza
Fecha: Febrero 2026
"""

# Include
import os   

# Importar la función de cifrado AES del laboratorio anterior
from aes_file_encryptor import cifrar_archivo

# Importar la función para cargar claves públicas RSA
from rsa_key_manager import cargar_clave_publica

# Importar la función de cifrado RSA-OAEP
from rsa_cipher import cifrar_con_rsa

# Generador de bytes aleatorios seguros
from Crypto.Random import get_random_bytes

# CONSTANTES

# Tamaño de la contraseña AES 
SIZE_PASSWORD_RANDOM = 32

# Extension del archivo que contiene la clave AES cifrado con RSA 
ENVELOPE_EXT = ".envelope"



def crear_sobre_digital(ruta_archivo, ruta_clave_publica_receptor):

    # Esta funcion cifra el archivo a enviar con AES y luego cifra la clave con RSA usando la clave publica del receptos
    # El receptor tendra que usar su clave privada para recuperar la contraseña AES y luego descifrar el archivo cifrado con AES

    # Verificar que el archivo original existe
    if not os.path.isfile(ruta_archivo):
        print(f"Error: El archivo '{ruta_archivo}' no existe.")
        return None, None  # Indica error

    # Cargar la clave pública RSA del receptor desde el archivo PEM
    # Retorna none si hubo un error
    clave_publica = cargar_clave_publica(ruta_clave_publica_receptor)

    # Verificar que la clave se cargó correctamente
    if clave_publica is None:
        return None, None  

    # Paso 1: Generar contraseña AES aleatoria 
    # Se genera una contraseña unica aleatoria de 32 bytes, para cada archivo a cifrar
    print("\n[Paso 1/4] Generando contrasena AES aleatoria de 256 bits...")
    password_aleatoria = get_random_bytes(SIZE_PASSWORD_RANDOM)

    # Mostrar el tamaño para confirmación 
    print(f"  Contrasena generada: {len(password_aleatoria) * 8} bits de entropia")

    # Paso 2: Cifrar el archivo con AES-256-CBC 

    # Llamar a la función del laboratorio anterior para cifrar el archivo
    print("\n[Paso 2/4] Cifrando archivo con AES-256-CBC...")
    ruta_cifrada = cifrar_archivo(ruta_archivo, password_aleatoria)

    # Paso 3: Cifrar la contraseña AES con RSA

    # Cifrar los 32 bytes de la contraseña con la clave pública RSA del receptor
    print("\n[Paso 3/4] Cifrando contrasena AES con RSA (clave publica del receptor)...")
    password_cifrada_rsa = cifrar_con_rsa(password_aleatoria, clave_publica)

    # Mostrar el tamaño del resultado RSA (384 bytes para clave de 3072 bits)
    print(f"  Contrasena AES cifrada con RSA: {len(password_cifrada_rsa)} bytes")

    # Paso 4: Guardar el sobre digital (.envelope)

    # El archivo .envelope contiene SOLO la contraseña AES cifrada con RSA
    ruta_sobre = ruta_archivo + ENVELOPE_EXT

    # Escribir la contraseña cifrada en el archivo .envelope (modo binario)
    print(f"\n[Paso 4/4] Guardando sobre digital...")
    with open(ruta_sobre, 'wb') as archivo_sobre:
        archivo_sobre.write(password_cifrada_rsa)
 
    # Reumen final
    # Obtener tamaños de los archivos generados para el resumen
    size_enc = os.path.getsize(ruta_cifrada)       # Tamaño del archivo cifrado con AES
    size_sobre = os.path.getsize(ruta_sobre)        # Tamaño del sobre digital con la contraseña cifrada con RSA

    # Mostrar resumen con todos los archivos generados
    print(f"\n{'=' * 60}")
    print("  SOBRE DIGITAL CREADO EXITOSAMENTE")
    print(f"{'=' * 60}")
    print(f"  Archivo cifrado (AES): {ruta_cifrada} ({size_enc} bytes)")
    print(f"  Sobre digital  (RSA): {ruta_sobre} ({size_sobre} bytes)")
    print(f"{'=' * 60}")
    print(f"\n  Envie AMBOS archivos al destinatario:")
    print(f"    1. {ruta_cifrada}")
    print(f"    2. {ruta_sobre}")
    print(f"\n  Comando SCP de ejemplo:")
    print(f"    scp {ruta_cifrada} {ruta_sobre} student@OTHER.11:~/recibido/")

    # Retornar las rutas de ambos archivos generados
    return ruta_cifrada, ruta_sobre