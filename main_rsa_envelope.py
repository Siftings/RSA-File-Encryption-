"""
Sobre Digital con RSA y AES - Laboratorio 03
Ciberseguridad
Universidad de los Andes
===================================================
Programa principal con menu (CLI) para generar claves RSA, enviar archivos (crear sobre digital) y recibir archivos (abrir sobre digital).

Autor: Juan David Daza
Fecha: Febrero 2026
"""

#Imports

import os   
import sys  

# Importar funciones de gestión de claves RSA
# generar_par_claves(): crea par de claves RSA y las guarda en formato PEM
# listar_claves(): muestra todas las claves disponibles en el directorio keys/
# KEYS_DIR: constante con el nombre del directorio de claves ("keys")
from rsa_key_manager import generar_par_claves, listar_claves, KEYS_DIR

# Importar función del emisor: crea el sobre digital (cifra archivo + cifra contraseña)
from digital_envelope_sender import crear_sobre_digital

# Importar función del receptor: abre el sobre digital (descifra contraseña + descifra archivo)
from digital_envelope_receiver import abrir_sobre_digital



def opcion_generar_claves():
    # Genera un par de claves (publica y privada) para un hosty los guarda en formato PEM en el directorio keys/

    # Mostrar encabezado de la opción
    print("\n" + "-" * 60)
    print("  Generar par de claves RSA")
    print("-" * 60)

    # Solicitar el nombre de la máquina al usuario
    # Este nombre se usa como prefijo en los archivos: {nombre}_private.pem, {nombre}_public.pem
    nombre = input("\n  Nombre de la maquina (ej: student1, student2): ").strip()

    # Validar que el nombre no esté vacío
    if not nombre:
        print("  Error: El nombre no puede estar vacio.")
        return  

    # Generar el par de claves RSA (3072 bits)
    generar_par_claves(nombre)


def opcion_enviar_archivo():
    # Esta funcion crea el sobre digital, cifra el archivo con AES y la contraseña con RSA usando la clave publica del receptor.

    # Mostrar encabezado de la opción
    print("\n" + "-" * 60)
    print("  Enviar archivo (crear sobre digital)")
    print("-" * 60)

    # Solicitar la ruta del archivo que se quiere enviar
    ruta_archivo = input("\n  Ruta del archivo a enviar: ").strip()

    # Validar que la ruta no esté vacía
    if not ruta_archivo:
        print("  Error: La ruta no puede estar vacia.")
        return  

    # Verificar que el archivo existe antes de continuar
    if not os.path.isfile(ruta_archivo):
        print(f"  Error: El archivo '{ruta_archivo}' no existe.")
        return  

    # Mostrar las claves públicas disponibles para que el usuario sepa cuáles hay
    print("\n  Claves disponibles:")
    claves = listar_claves()

    # Solicitar la ruta de la clave pública del receptor
    print()  
    ruta_clave_pub = input("  Ruta de la clave PUBLICA del receptor (.pem): ").strip()

    # Validar que la ruta no esté vacía
    if not ruta_clave_pub:
        print("  Error: La ruta de la clave publica no puede estar vacia.")
        return  

    # Crear el sobre digital: cifra el archivo con AES y la contraseña con RSA
    crear_sobre_digital(ruta_archivo, ruta_clave_pub)


def opcion_recibir_archivo():
    # Esta funcion abre un sobre digital: descifra la contraseña con RSA y el archivo con AES
    # necesita la ruta del archivo cifrado (.enc), la ruta del sobre digital (.envelope) y la ruta de la clave privada del receptor para poder recuperar el archivo original descifrado.

    # Mostrar encabezado de la opción
    print("\n" + "-" * 60)
    print("  Recibir archivo (abrir sobre digital)")
    print("-" * 60)

    # Solicitar la ruta del archivo cifrado (.enc)
    ruta_enc = input("\n  Ruta del archivo cifrado (.enc): ").strip()

    # Validar que la ruta no esté vacía
    if not ruta_enc:
        print("  Error: La ruta del archivo cifrado no puede estar vacia.")
        return  

    # Solicitar la ruta del sobre digital (.envelope)
    ruta_sobre = input("  Ruta del sobre digital (.envelope): ").strip()

    # Validar que la ruta no esté vacía
    if not ruta_sobre:
        print("  Error: La ruta del sobre digital no puede estar vacia.")
        return  

    # Mostrar las claves privadas disponibles para que el usuario sepa cuáles hay
    print("\n  Claves disponibles:")
    claves = listar_claves()

    # Solicitar la ruta de la clave privada propia del receptor
    print()  
    ruta_clave_priv = input("  Ruta de SU clave PRIVADA (.pem): ").strip()

    # Validar que la ruta no esté vacía
    if not ruta_clave_priv:
        print("  Error: La ruta de la clave privada no puede estar vacia.")
        return  

    # Abrir el sobre digital: descifra la contraseña con RSA y el archivo con AES
    abrir_sobre_digital(ruta_enc, ruta_sobre, ruta_clave_priv)


def opcion_ver_claves():

    # Muestra todas las claves RSA disponibles en el directorio keys/ 

    # Mostrar encabezado de la opción
    print("\n" + "-" * 60)
    print("  Claves RSA disponibles")
    print("-" * 60)

    # Listar todas las claves disponibles
    listar_claves()



def menu():

    # Bucle del menu
    while True:

        # Mostrar el encabezado del menú con formato visual
        print("\n" + "=" * 60)
        print("   Sobre Digital RSA + AES-256-CBC")
        print("   Laboratorio 03 - Ciberseguridad")
        print("   Universidad de los Andes")
        print("=" * 60)

        # Mostrar las opciones disponibles
        print()
        print("  [1] Generar par de claves RSA")
        print("  [2] Enviar archivo (crear sobre digital)")
        print("  [3] Recibir archivo (abrir sobre digital)")
        print("  [4] Ver claves disponibles")
        print("  [0] Salir")
        print()

        # Leer la opción seleccionada por el usuario
        opcion = input("  Seleccione una opcion: ").strip()

        if opcion == "1":
            opcion_generar_claves()

        elif opcion == "2":
            opcion_enviar_archivo()

        elif opcion == "3":
            opcion_recibir_archivo()

        elif opcion == "4":
            opcion_ver_claves()

        elif opcion == "0":
            print("\nSaliendo del programa.\nBye o/")
            sys.exit(0)  

        else:
            print("\n  Opcion no valida, intente de nuevo.")

if __name__ == "__main__":
    menu()
