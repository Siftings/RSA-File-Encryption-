# Laboratorio 03 — Sobre Digital RSA + AES
---
Universidad de Los Andes  
Ciberseguridad (ISIS 3311)  
Autor: Juan David Daza Caro

## Descripción

Este proyecto implementa un sistema de **sobre digital** (digital envelope) que permite el intercambio seguro de archivos entre dos nodos (`student1` y `student2`) sin necesidad de compartir contraseñas por adelantado.

Combina dos técnicas criptográficas complementarias:
- **RSA-OAEP-SHA256** (cifrado asimétrico): para distribuir la clave AES de forma segura.
- **AES-256-CBC** (cifrado simétrico): para cifrar el archivo de forma eficiente.

## Requisitos

- Python 3.8 o superior
- Librería `pycryptodome`

## Instalación

```bash
# 1. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate        # En macOS/Linux

# 2. Instalar dependencias
python3 -m pip install PyCryptodome
```

## Uso

### Programa principal (menú interactivo)

```bash
python main_rsa_envelope.py
```

| Opción | Descripción |
|-|-|
|**1**| Generar par de claves RSA (pública + privada) |
|**2**| Enviar archivo (crear sobre digital) |
|**3**| Recibir archivo (abrir sobre digital) |
|**4**| Ver claves disponibles |
|**0**| Salir |

## Detalles técnicos

### RSA (Cifrado Asimétrico)

| Parámetro | Valor |
|-----------|-------|
| Algoritmo | RSA |
| Tamaño de clave | 3072 bits |
| Esquema de padding | OAEP (Optimal Asymmetric Encryption Padding) |
| Función hash | SHA-256 |
| Función de máscara | MGF1-SHA256 |
| Formato de claves | PEM (PKCS#8 para privada, SubjectPublicKeyInfo para pública) |
| Tamaño máx. datos | 318 bytes (para clave 3072 bits con OAEP-SHA256) |

### AES (Cifrado Simétrico)

| Parámetro | Valor |
|-----------|-------|
| Algoritmo | AES-256 |
| Modo de operación | CBC (Cipher Block Chaining) |
| Tamaño de clave | 256 bits (32 bytes) |
| Derivación de clave | PBKDF2-HMAC-SHA256, 100,000 iteraciones |
| Padding | PKCS7 |
| Salt | 16 bytes aleatorios |
| IV | 16 bytes aleatorios |

### Estructura del archivo cifrado (.enc)

```
┌─────────────┬─────────────┬──────────────────────────┐
│  Salt (16B) │   IV (16B)  │   Datos cifrados (N B)   │
└─────────────┴─────────────┴──────────────────────────┘
```

### Estructura del sobre digital (.envelope)

```
┌──────────────────────────────────────────────────┐
│   Contraseña AES cifrada con RSA-OAEP (384 B)   │
└──────────────────────────────────────────────────┘
```

## Programa AES independiente

El programa para el cifrado AES se puede utilizar de forma independiente, para mayor informacion visitar su [repositorio](https://github.com/Siftings/AES-Encryption-program-).