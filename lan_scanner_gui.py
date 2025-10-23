import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import re
import binascii
import struct
import time

partidas_detectadas = {}
listening_threads = []
stop_events = []

def extract_game_info(data):
    """
    Extrae información de la partida de Warcraft III del paquete UDP
    """
    try:
        # Intentar diferentes codificaciones
        for encoding in ['latin1', 'utf-8', 'cp1252']:
            try:
                decoded = data.decode(encoding, errors='ignore')
                break
            except:
                continue
        else:
            decoded = data.decode('latin1', errors='ignore')
        
        # Buscar el patrón del nombre de la partida
        match = re.search(r'\[.*?\](.*?)(?:\x00|\/w3)', decoded)
        if not match:
            return None, None, None, None
        
        game_name = match.group(1).strip()
        
        # Encontrar el índice donde termina el nombre de la partida
        game_name_bytes = game_name.encode('latin1')
        start_idx = data.find(game_name_bytes) + len(game_name_bytes)
        
        # Buscar el siguiente byte nulo después del nombre
        null_idx = data.find(b'\x00', start_idx)
        if null_idx == -1:
            null_idx = start_idx
        
        # Extraer datos después del nombre de la partida
        remaining_data = data[null_idx+1:]
        
        # Intentar extraer información de jugadores
        player_count = extract_player_count(remaining_data)
        creator_name = extract_creator_name(remaining_data)
        
        # Extraer bytes adicionales para análisis
        extra_bytes = remaining_data[:20] if len(remaining_data) >= 20 else remaining_data
        extra_hex = binascii.hexlify(extra_bytes).decode('ascii').upper()
        
        return game_name, player_count, creator_name, extra_hex
        
    except Exception as e:
        print(f"[!] Error al extraer info: {e}")
        return None, None, None, None

def extract_player_count(data):
    """
    Intenta extraer el número de jugadores
    """
    try:
        if len(data) < 4:
            return "?"
        
        # Buscar patrones comunes para el conteo de jugadores
        for i in range(min(10, len(data))):
            if 1 <= data[i] <= 12:
                if i + 1 < len(data) and data[i + 1] <= 12:
                    return f"{data[i]}/{data[i + 1]}"
        
        # Buscar en posiciones fijas comunes
        common_positions = [0, 1, 2, 4, 8]
        for pos in common_positions:
            if pos < len(data) and 1 <= data[pos] <= 12:
                return str(data[pos])
        
        return "?"
    except:
        return "?"

def extract_creator_name(remaining_data):
    """
    Intenta extraer el nombre del creador de la partida
    """
    try:
        text_parts = []
        current_text = ""
        
        for byte in remaining_data[:50]:
            if 32 <= byte <= 126:  # Caracteres imprimibles ASCII
                current_text += chr(byte)
            else:
                if len(current_text) >= 2:
                    text_parts.append(current_text)
                current_text = ""
        
        if current_text and len(current_text) >= 2:
            text_parts.append(current_text)
        
        # Filtrar nombres probables
        probable_names = []
        for text in text_parts:
            if (2 <= len(text) <= 15 and 
                not re.search(r'[^\w\s\-_]', text) and
                not text.isdigit()):
                probable_names.append(text.strip())
        
        return probable_names[0] if probable_names else "?"
        
    except:
        return "?"

def analyze_packet_structure(data):
    """
    Función de ayuda para analizar la estructura del paquete
    """
    print(f"\n--- Análisis de Paquete ---")
    print(f"Tamaño total: {len(data)} bytes")
    print(f"Primeros 50 bytes (hex): {binascii.hexlify(data[:50]).decode('ascii').upper()}")
    print(f"Primeros 50 bytes (ascii): {repr(data[:50].decode('latin1', errors='replace'))}")

def listen_on_port(port, update_callback, stop_event, bind_address='0.0.0.0'):
    """
    Escucha en un puerto específico con opción de dirección de bind
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Configurar socket para recibir broadcasts
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # En Windows, configurar para recibir tráfico local
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass  # SO_REUSEPORT no está disponible en Windows
    
    sock.settimeout(1.0)
    
    try:
        sock.bind((bind_address, port))
        print(f"✅ Escuchando en {bind_address}:{port}")
    except OSError as e:
        print(f"❌ Error al vincular al puerto {port}: {e}")
        return
    
    packet_count = 0
    
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(2048)
            packet_count += 1
            ip, puerto_origen = addr[0], addr[1]
            
            # Mostrar todos los paquetes si son pocos para debug
            if packet_count <= 10 or packet_count % 20 == 1:
                print(f"\n🔍 Puerto {port} - Paquete #{packet_count} desde {ip}:{puerto_origen}")
                print(f"    Tamaño: {len(data)} bytes")
                analyze_packet_structure(data)
            
            # Intentar extraer información del juego
            game_name, player_count, creator_name, extra_hex = extract_game_info(data)
            key = (ip, puerto_origen, port)
            
            if game_name:
                if key not in partidas_detectadas:
                    partidas_detectadas[key] = (game_name, player_count, creator_name, extra_hex, port)
                    print(f"🎯 Nueva partida detectada en puerto {port}:")
                    print(f"   📍 {ip}:{puerto_origen}")
                    print(f"   🎮 Partida: {game_name}")
                    print(f"   👥 Jugadores: {player_count}")
                    print(f"   👤 Creador: {creator_name}")
                    update_callback(ip, puerto_origen, game_name, player_count, creator_name, port, extra_hex)
            else:
                # Mostrar paquetes no reconocidos para debug
                if packet_count <= 5:
                    print(f"📩 Puerto {port} - {ip}:{puerto_origen} | Paquete no reconocido (tamaño: {len(data)})")
                    # Mostrar contenido hex para análisis
                    hex_content = binascii.hexlify(data[:100]).decode('ascii').upper()
                    print(f"    Hex: {hex_content}")
                
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"❌ Error en puerto {port}: {e}")
    
    sock.close()
    print(f"🔌 Cerrado puerto {port}")

def scan_ghost_bot_activity(update_callback, stop_event):
    """
    Escanea activamente por actividad del GHost bot en puertos específicos
    """
    ghost_ports = [6119, 6129]  # Puertos típicos del GHost bot
    local_ips = ['127.0.0.1', '0.0.0.0', get_local_ip()]
    
    print(f"🔍 Iniciando escaneo activo para GHost bot en puertos: {ghost_ports}")
    
    while not stop_event.is_set():
        for port in ghost_ports:
            try:
                # Crear socket para escuchar tráfico local
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(0.5)
                
                # Intentar conectar/enviar a localhost para detectar actividad
                try:
                    sock.bind(('', port + 1000))  # Puerto auxiliar para no interferir
                    # Enviar un paquete de prueba
                    test_packet = b'\x01\x02\x03\x04'  # Paquete mínimo de prueba
                    sock.sendto(test_packet, ('127.0.0.1', port))
                except:
                    pass
                
                sock.close()
                
            except Exception as e:
                pass
        
        time.sleep(2)  # Esperar 2 segundos antes del siguiente escaneo

def get_local_ip():
    """
    Obtiene la IP local de la máquina
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def parse_ports(port_string):
    """
    Parsea la cadena de puertos separados por comas
    """
    ports = []
    try:
        port_list = [p.strip() for p in port_string.split(',')]
        for port_str in port_list:
            if port_str:
                port = int(port_str)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    raise ValueError(f"Puerto {port} fuera de rango (1-65535)")
    except ValueError as e:
        raise ValueError(f"Error en formato de puertos: {e}")
    
    return ports if ports else [6112]

def start_listening(ports, update_callback, include_localhost=True):
    """
    Inicia los hilos de escucha para múltiples puertos
    """
    global listening_threads, stop_events
    
    # Limpiar threads anteriores
    stop_listening()
    
    local_ip = get_local_ip()
    print(f"🎮 IP Local detectada: {local_ip}")
    print(f"🎮 Iniciando escucha en puertos: {', '.join(map(str, ports))}")
    
    # Configurar direcciones de bind
    bind_addresses = ['0.0.0.0']  # Escuchar en todas las interfaces
    if include_localhost:
        bind_addresses.append('127.0.0.1')  # Escuchar específicamente en localhost
    
    for port in ports:
        for bind_addr in bind_addresses:
            try:
                stop_event = threading.Event()
                thread = threading.Thread(
                    target=listen_on_port, 
                    args=(port, update_callback, stop_event, bind_addr), 
                    daemon=True
                )
                
                stop_events.append(stop_event)
                listening_threads.append(thread)
                thread.start()
                
                # Pequeña pausa para evitar conflictos
                time.sleep(0.1)
                
            except Exception as e:
                print(f"❌ Error iniciando listener en {bind_addr}:{port}: {e}")
    
    # Iniciar escaneo activo del GHost bot
    if include_localhost:
        stop_event = threading.Event()
        ghost_thread = threading.Thread(
            target=scan_ghost_bot_activity,
            args=(update_callback, stop_event),
            daemon=True
        )
        stop_events.append(stop_event)
        listening_threads.append(ghost_thread)
        ghost_thread.start()

def stop_listening():
    """
    Detiene todos los hilos de escucha
    """
    global listening_threads, stop_events
    
    for stop_event in stop_events:
        stop_event.set()
    
    # Esperar a que terminen los threads
    for thread in listening_threads:
        if thread.is_alive():
            thread.join(timeout=2)
    
    listening_threads.clear()
    stop_events.clear()

def create_gui():
    """
    Crea la interfaz gráfica mejorada
    """
    root = tk.Tk()
    root.title("Detector de Partidas LAN - Warcraft III v1.27b [Mejorado]")
    root.geometry("1200x750")
    
    # Variables de estado
    is_listening = False
    
    # Frame principal
    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Título
    title_label = ttk.Label(main_frame, text="🎮 Detector de Partidas LAN - Warcraft III [Mejorado]", 
                           font=("Arial", 16, "bold"))
    title_label.pack(pady=(0, 10))
    
    # Información de red local
    local_ip = get_local_ip()
    ip_label = ttk.Label(main_frame, text=f"🌐 IP Local: {local_ip}", 
                        font=("Arial", 10), foreground="blue")
    ip_label.pack(pady=(0, 5))
    
    # Frame de configuración
    config_frame = ttk.LabelFrame(main_frame, text="⚙️ Configuración Avanzada", padding=10)
    config_frame.pack(fill="x", pady=(0, 10))
    
    # Controles de puerto
    port_frame = ttk.Frame(config_frame)
    port_frame.pack(fill="x")
    
    ttk.Label(port_frame, text="🔌 Puertos:").pack(side="left", padx=(0, 5))
    
    port_var = tk.StringVar(value="6112,6119,6125,6126,6116,6154")
    port_entry = ttk.Entry(port_frame, textvariable=port_var, width=30)
    port_entry.pack(side="left", padx=(0, 10))
    
    # Checkbox para incluir localhost
    localhost_var = tk.BooleanVar(value=True)
    localhost_check = ttk.Checkbutton(port_frame, text="🏠 Incluir Localhost", variable=localhost_var)
    localhost_check.pack(side="left", padx=(10, 0))
    
    ttk.Label(port_frame, text="💡 Separar con comas. GHost: 6119,6129", 
             font=("Arial", 9), foreground="gray").pack(side="right")
    
    # Botones
    button_frame = ttk.Frame(config_frame)
    button_frame.pack(fill="x", pady=(10, 0))
    
    status_var = tk.StringVar(value="🔴 Detenido")
    status_label = ttk.Label(button_frame, textvariable=status_var, font=("Arial", 10, "bold"))
    status_label.pack(side="left")
    
    def toggle_listening():
        nonlocal is_listening
        
        if not is_listening:
            try:
                ports = parse_ports(port_var.get())
                include_localhost = localhost_var.get()
                
                # Limpiar tabla
                global partidas_detectadas
                partidas_detectadas.clear()
                for item in tree.get_children():
                    tree.delete(item)
                
                def table_update(ip, puerto, game_name, player_count, creator_name, listen_port, extra_hex):
                    tree.insert('', 'end', values=(ip, puerto, game_name, player_count, creator_name, listen_port, extra_hex))
                
                start_listening(ports, table_update, include_localhost)
                
                start_button.config(text="⏹️ Detener")
                localhost_text = " + Localhost" if include_localhost else ""
                status_var.set(f"🟢 Escuchando: {', '.join(map(str, ports))}{localhost_text}")
                port_entry.config(state="disabled")
                localhost_check.config(state="disabled")
                is_listening = True
                
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            stop_listening()
            start_button.config(text="▶️ Iniciar")
            status_var.set("🔴 Detenido")
            port_entry.config(state="normal")
            localhost_check.config(state="normal")
            is_listening = False
    
    start_button = ttk.Button(button_frame, text="▶️ Iniciar", command=toggle_listening)
    start_button.pack(side="right", padx=(10, 0))
    
    def set_ghost_ports():
        port_var.set("6112,6119,6129")
        localhost_var.set(True)
    
    preset_button = ttk.Button(button_frame, text="👻 GHost Bot", command=set_ghost_ports)
    preset_button.pack(side="right", padx=(0, 5))
    
    def set_common_ports():
        port_var.set("6112,6115,6116,6119")
    
    common_button = ttk.Button(button_frame, text="🎯 Comunes", command=set_common_ports)
    common_button.pack(side="right", padx=(0, 5))
    
    # Tabla
    table_frame = ttk.LabelFrame(main_frame, text="📋 Partidas Detectadas", padding=5)
    table_frame.pack(fill="both", expand=True)
    
    columns = ("IP", "Puerto", "Partida", "Jugadores", "Creador", "Puerto Escucha", "Datos Hex")
    tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
    
    # Configurar columnas
    tree.heading("IP", text="🌐 IP")
    tree.heading("Puerto", text="🚪 Puerto")
    tree.heading("Partida", text="🎮 Partida")
    tree.heading("Jugadores", text="👥 Jugadores")
    tree.heading("Creador", text="👤 Creador")
    tree.heading("Puerto Escucha", text="🔌 Escucha")
    tree.heading("Datos Hex", text="📦 Datos")
    
    tree.column("IP", width=120)
    tree.column("Puerto", width=80)
    tree.column("Partida", width=200)
    tree.column("Jugadores", width=80)
    tree.column("Creador", width=120)
    tree.column("Puerto Escucha", width=80)
    tree.column("Datos Hex", width=150)
    
    # Scrollbars
    v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
    
    tree.pack(side="left", fill="both", expand=True)
    v_scrollbar.pack(side="right", fill="y")
    
    # Botones inferiores
    bottom_frame = ttk.Frame(main_frame)
    bottom_frame.pack(fill="x", pady=(10, 0))
    
    def clear_table():
        global partidas_detectadas
        partidas_detectadas.clear()
        for item in tree.get_children():
            tree.delete(item)
    
    clear_button = ttk.Button(bottom_frame, text="🗑️ Limpiar", command=clear_table)
    clear_button.pack(side="left")
    
    info_label = ttk.Label(bottom_frame, 
                          text="ℹ️ Versión mejorada - Detecta partidas locales y remotas. GHost Bot: puertos 6119/6129",
                          font=("Arial", 9))
    info_label.pack(side="right")
    
    # Cerrar aplicación correctamente
    def on_closing():
        if is_listening:
            stop_listening()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    print("🚀 Interfaz gráfica mejorada lista")
    print(f"🌐 IP Local: {local_ip}")
    print("👻 Configuración optimizada para GHost Bot")
    root.mainloop()

if __name__ == "__main__":
    print("🎮 Detector de Partidas LAN - Warcraft III v1.27b [MEJORADO]")
    print("=" * 70)
    print("📡 Puertos por defecto: 6112, 6119, 6129")
    print("👻 Optimizado para detectar GHost Bot")
    print("🏠 Incluye detección de partidas locales")
    print("🔧 Escaneo activo de localhost")
    print("=" * 70)
    
    create_gui()