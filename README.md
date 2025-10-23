# WC3_Lan_Scanner

![Preview](https://github.com/Azzlaer/WC3_Lan_Scanner/blob/main/01.png)
![Preview](https://github.com/Azzlaer/WC3_Lan_Scanner/blob/main/02.png)
![Preview](https://github.com/Azzlaer/WC3_Lan_Scanner/blob/main/03.png)

Herramienta para escanear la conectividad LAN en partidas de **Warcraft III**, desarrollada por Azzlaer.

## 馃殌 驴Qu茅 es?

**WC3_Lan_Scanner** es una utilidad que detecta hosts y puertos activos en la red local utilizados por partidas LAN de **Warcraft III**, ayudando a diagnosticar problemas de conexi贸n y optimizar la experiencia multijugador.

## 馃З Funcionalidades

- Escaneo de hosts activos en la red local  
- Detecci贸n de puertos espec铆ficos del servicio LAN de Warcraft III  
- Interfaz simple basada en l铆nea de comandos  
- Resultados en tiempo real para contribuir al diagn贸stico de partidas LAN

## 馃洜 Instalaci贸n

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

## 鈿欙笍 Uso

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

## 馃幆 驴Para qui茅n es 煤til?

- Jugadores que enfrentan problemas al conectar partidas LAN en Warcraft III  
- Administradores de red en LAN party o entornos de gaming local  
- Desarrolladores interesados en diagn贸stico de red y automatizaci贸n de pruebas de conectividad

## 馃搵 Resultados

El script listar谩:

- IP respondiendo al escaneo ping  
- Puertos abiertos relacionados a Warcraft III  
- Puertos cerrados o hosts inaccesibles

Ejemplo:

```
[+] 192.168.0.12 鈥?puerto 6112 ABIERTO 鈥?Warcraft III disponible
[-] 192.168.0.15 鈥?no responde
```

## 馃И Pruebas

Puedes probarlo en tu red local o LAN party. Aseg煤rate de tener privilegios para escanear puertos. Prueba con rangos cortos y tiempos de espera reducidos para acelerar el escaneo.

## 鈿栵笍 Licencia

Este proyecto est谩 bajo licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para m谩s detalles.

---

## 鉁?Contribuciones

Si deseas mejorar el proyecto:

1. Haz un **fork**
2. Crea una rama (`feature/nueva-funcionalidad`)
3. Realiza tus cambios y agrega documentaci贸n si corresponde
4. Abre un **Pull Request**

---

## 馃摣 Contacto

Para dudas o sugerencias, abre un issue en el repositorio.

---

隆Buena suerte conectando partidas LAN en Warcraft III! 馃幃
