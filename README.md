# WC3_Lan_Scanner

Herramienta para escanear la conectividad LAN en partidas de **Warcraft III**, desarrollada por Azzlaer.

## 🚀 ¿Qué es?

**WC3_Lan_Scanner** es una utilidad que detecta hosts y puertos activos en la red local utilizados por partidas LAN de **Warcraft III**, ayudando a diagnosticar problemas de conexión y optimizar la experiencia multijugador.

## 🧩 Funcionalidades

- Escaneo de hosts activos en la red local  
- Detección de puertos específicos del servicio LAN de Warcraft III  
- Interfaz simple basada en línea de comandos  
- Resultados en tiempo real para contribuir al diagnóstico de partidas LAN

## 🛠 Instalación

Requisitos:  
- Python 3.7+  
- (Opcional) permisos de administrador para escaneo de red

Pasos:

```bash
git clone https://github.com/Azzlaer/WC3_Lan_Scanner.git
cd WC3_Lan_Scanner
pip install -r requirements.txt
```

Si el repositorio no incluye `requirements.txt`, omite ese paso.

## ⚙️ Uso

```bash
python scanner.py --range 192.168.0.1-254 --timeout 2
```

Opciones comunes:

- `--range`: rango de IP a escanear (ej.: `192.168.1.1-100`)  
- `--timeout`: tiempo de espera en segundo por intento  
- `--port`: (opcional) especifica puerto a escanear, por defecto usa puertos de Warcraft III

Ejemplo:

```bash
python scanner.py --range 10.0.0.1-50 --timeout 1 --port 6112
```

## 🎯 ¿Para quién es útil?

- Jugadores que enfrentan problemas al conectar partidas LAN en Warcraft III  
- Administradores de red en LAN party o entornos de gaming local  
- Desarrolladores interesados en diagnóstico de red y automatización de pruebas de conectividad

## 📋 Resultados

El script listará:

- IP respondiendo al escaneo ping  
- Puertos abiertos relacionados a Warcraft III  
- Puertos cerrados o hosts inaccesibles

Ejemplo:

```
[+] 192.168.0.12 – puerto 6112 ABIERTO – Warcraft III disponible
[-] 192.168.0.15 – no responde
```

## 🧪 Pruebas

Puedes probarlo en tu red local o LAN party. Asegúrate de tener privilegios para escanear puertos. Prueba con rangos cortos y tiempos de espera reducidos para acelerar el escaneo.

## ⚖️ Licencia

Este proyecto está bajo licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

## ✅ Contribuciones

Si deseas mejorar el proyecto:

1. Haz un **fork**
2. Crea una rama (`feature/nueva-funcionalidad`)
3. Realiza tus cambios y agrega documentación si corresponde
4. Abre un **Pull Request**

---

## 📫 Contacto

Para dudas o sugerencias, abre un issue en el repositorio.

---

¡Buena suerte conectando partidas LAN en Warcraft III! 🎮
