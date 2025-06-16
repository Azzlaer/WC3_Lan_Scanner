import socket
import re
import struct
import time
import threading
from collections import defaultdict

def clean_game_name(raw_name):
    """Limpia el nombre del juego de caracteres especiales"""
    if not raw_name:
        return None
    cleaned = raw_name.strip()
    # Remover caracteres de control y símbolos especiales
    cleaned = re.sub(r'[\x00-\x1F\x7F-\x9F]+.*$', '', cleaned).strip()
    cleaned = re.sub(r'[♥♠♦♣☺☻♪♫♀♂♯♭]+.*$', '', cleaned).strip()
    return cleaned if len(cleaned) >= 2 else None

def extract_wc3_game_info(data, addr, debug=False):
    """
    Extrae información del juego de WC3 - Versión corregida para slots
    WC3 siempre tiene 12 slots totales, pero puede configurar menos para el mapa
    """
    try:
        if len(data) < 8:
            return None
        
        game_info = {
            'name': None,
            'current_players': None,
            'max_players': 12,  # WC3 siempre tiene 12 slots totales
            'configured_slots': None,  # Slots que el mapa/host configuró
            'slots_taken': None,
            'slots_total': 12,  # Fijo para WC3
            'game_status': 'unknown',
            'host_ip': addr[0],
            'host_port': addr[1],
            'raw_data': None,
            'protocol_type': 'unknown'
        }
        
        # Debug: mostrar primeros bytes
        if debug:
            hex_data = ' '.join(f'{b:02x}' for b in data[:32])
            print(f"    🔍 Primeros 32 bytes: {hex_data}")
        
        # PROTOCOLO 1: WC3 Standard LAN Broadcast
        # Buscar firmas conocidas de WC3
        wc3_signatures = [
            b'\xf7\x2f\x00\x00',  # WC3 LAN game
            b'\xf7\x30\x00\x00',  # WC3 Custom game
            b'\xf7\x2e\x00\x00',  # WC3 Ladder game
            b'\x01\x02\x03\x04',  # Firma personalizada
            b'W3XP',              # Warcraft III Expansion
            b'WAR3'               # Warcraft III
        ]
        
        signature_found = False
        sig_pos = -1
        
        for signature in wc3_signatures:
            sig_pos = data.find(signature)
            if sig_pos != -1:
                signature_found = True
                game_info['protocol_type'] = f'wc3_sig_{signature.hex()}'
                break
        
        # PROTOCOLO 2: Battle.net style packets
        if not signature_found and len(data) > 4 and data[0] == 0xFF:
            packet_type = data[1]
            if packet_type in [0x30, 0x31, 0x32, 0x33]:
                signature_found = True
                sig_pos = 0
                game_info['protocol_type'] = f'bnet_style_{packet_type:02x}'
        
        # PROTOCOLO 3: UDP Game Discovery
        wc3_strings = [b'Warcraft', b'W3XP', b'WAR3', b'Game', b'Host']
        for wc3_str in wc3_strings:
            if wc3_str.lower() in data.lower():
                signature_found = True
                sig_pos = data.lower().find(wc3_str.lower())
                game_info['protocol_type'] = f'string_match_{wc3_str.decode()}'
                break
        
        # Si no encontramos firma, análisis genérico
        if not signature_found:
            for i in range(len(data) - 3):
                chunk = data[i:i+20]
                try:
                    text = chunk.decode('ascii', errors='ignore')
                    if len(text) > 3 and text.isprintable() and not text.isspace():
                        sig_pos = i
                        game_info['protocol_type'] = 'generic_text'
                        break
                except:
                    continue
        
        # Extraer nombre del juego
        if sig_pos != -1:
            # Método 1: Buscar después de la firma
            for offset in range(0, 20):
                try:
                    start_pos = sig_pos + offset
                    if start_pos >= len(data):
                        break
                    
                    # Buscar string terminado en null
                    null_pos = data.find(b'\x00', start_pos)
                    if null_pos != -1 and null_pos - start_pos > 2:
                        raw_name = data[start_pos:null_pos].decode('latin1', errors='ignore')
                        cleaned_name = clean_game_name(raw_name)
                        if cleaned_name:
                            game_info['name'] = cleaned_name
                            break
                    
                    # Buscar string de longitud fija
                    for length in [8, 12, 16, 20, 24, 32]:
                        if start_pos + length <= len(data):
                            raw_name = data[start_pos:start_pos + length].decode('latin1', errors='ignore')
                            cleaned_name = clean_game_name(raw_name)
                            if cleaned_name:
                                game_info['name'] = cleaned_name
                                break
                    
                    if game_info['name']:
                        break
                        
                except:
                    continue
        
        # Método 2: Buscar strings en todo el paquete
        if not game_info['name']:
            try:
                full_text = data.decode('latin1', errors='ignore')
                words = re.findall(r'[A-Za-z0-9][A-Za-z0-9\s\-_]{2,30}[A-Za-z0-9]', full_text)
                for word in words:
                    cleaned = clean_game_name(word)
                    if cleaned and len(cleaned) > 3:
                        game_info['name'] = cleaned
                        break
            except:
                pass
        
        # ANÁLISIS DE JUGADORES - ESTRATEGIA CORREGIDA PARA WC3
        candidates = []
        
        # Configuraciones típicas de WC3 (jugadores actuales, slots configurados)
        # Basado en tu imagen: se ve que hay juegos con diferentes configuraciones
        wc3_player_patterns = [
            # (current_players, configured_slots) - patrones reales de WC3
            (0, 12), (1, 12), (2, 12), (3, 12), (4, 12), (5, 12), (6, 12),
            (7, 12), (8, 12), (9, 12), (10, 12), (11, 12), (12, 12),
            (0, 10), (1, 10), (2, 10), (3, 10), (4, 10), (5, 10), 
            (6, 10), (7, 10), (8, 10), (9, 10), (10, 10),
            (0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (6, 8), (7, 8), (8, 8),
            (0, 6), (1, 6), (2, 6), (3, 6), (4, 6), (5, 6), (6, 6),
            (0, 4), (1, 4), (2, 4), (3, 4), (4, 4),
            (0, 3), (1, 3), (2, 3), (3, 3),
            (0, 2), (1, 2), (2, 2)
        ]
        
        # ESTRATEGIA 1: Buscar patrones específicos de WC3
        name_end_pos = -1
        if game_info['name']:
            name_bytes = game_info['name'].encode('latin1', errors='ignore')
            name_pos = data.find(name_bytes)
            if name_pos != -1:
                name_end_pos = name_pos + len(name_bytes)
                null_pos = data.find(b'\x00', name_end_pos)
                if null_pos != -1:
                    name_end_pos = null_pos + 1
        
        # Buscar en posiciones relativas al nombre
        if name_end_pos != -1:
            for offset in range(1, 25):  # Buscar más lejos
                pos = name_end_pos + offset
                if pos + 2 < len(data):
                    try:
                        b1, b2, b3 = data[pos], data[pos + 1], data[pos + 2]
                        
                        # Patrón A: (current, configured, other)
                        if (b1, b2) in wc3_player_patterns:
                            confidence = 0.95 - (offset * 0.01)
                            candidates.append({
                                'current': b1,
                                'configured': b2,
                                'confidence': confidence,
                                'source': f'name_rel_{offset}',
                                'bytes': (b1, b2, b3)
                            })
                        
                        # Patrón B: (configured, current, other) - algunos protocolos invierten
                        if (b2, b1) in wc3_player_patterns and b2 <= b1:
                            confidence = 0.85 - (offset * 0.01)
                            candidates.append({
                                'current': b2,
                                'configured': b1,
                                'confidence': confidence,
                                'source': f'name_rel_inv_{offset}',
                                'bytes': (b1, b2, b3)
                            })
                            
                    except:
                        continue
        
        # ESTRATEGIA 2: Posiciones fijas conocidas del protocolo WC3
        wc3_fixed_positions = [
            8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48,
            -16, -12, -8, -4  # Desde el final
        ]
        
        for pos_offset in wc3_fixed_positions:
            if pos_offset < 0:
                pos = len(data) + pos_offset
            else:
                pos = pos_offset
                
            if 0 <= pos + 2 < len(data):
                try:
                    b1, b2, b3 = data[pos], data[pos + 1], data[pos + 2]
                    
                    # Verificar patrones válidos
                    if (b1, b2) in wc3_player_patterns:
                        confidence = 0.8 if pos_offset > 0 else 0.75
                        candidates.append({
                            'current': b1,
                            'configured': b2,
                            'confidence': confidence,
                            'source': f'fixed_{pos}',
                            'bytes': (b1, b2, b3)
                        })
                    
                    if (b2, b1) in wc3_player_patterns and b2 <= b1:
                        confidence = 0.75 if pos_offset > 0 else 0.7
                        candidates.append({
                            'current': b2,
                            'configured': b1,
                            'confidence': confidence,
                            'source': f'fixed_inv_{pos}',
                            'bytes': (b1, b2, b3)
                        })
                        
                except:
                    continue
        
        # ESTRATEGIA 3: Búsqueda exhaustiva de patrones comunes
        # Según tu imagen, los más comunes son (1,12) y (1,10)
        priority_patterns = [(1, 12), (1, 10), (0, 12), (0, 10), (2, 12), (2, 10)]
        
        for current, configured in priority_patterns:
            pattern_bytes = bytes([current, configured])
            pos = data.find(pattern_bytes)
            if pos != -1:
                # Verificar contexto
                context_score = 0
                
                # Bonus si está cerca del nombre
                if name_end_pos != -1:
                    distance = abs(pos - name_end_pos)
                    if distance < 30:
                        context_score += 0.3
                
                # Bonus por posición estructural
                if pos % 4 == 0:
                    context_score += 0.1
                
                confidence = 0.9 + context_score
                candidates.append({
                    'current': current,
                    'configured': configured,
                    'confidence': confidence,
                    'source': f'priority_pattern_{pos}',
                    'bytes': pattern_bytes
                })
        
        # ESTRATEGIA 4: Análisis de secuencias completas
        # Buscar patrones como: [current, configured, 0, 0] o similares
        for i in range(len(data) - 3):
            chunk = data[i:i+4]
            b1, b2, b3, b4 = chunk
            
            # Patrón: current, configured, padding, padding
            if ((b1, b2) in wc3_player_patterns and 
                (b3 == 0 or b3 == 255 or b3 == b1 or b3 == b2) and
                (b4 == 0 or b4 == 255)):
                
                confidence = 0.7
                # Bonus por contexto
                if name_end_pos != -1 and abs(i - name_end_pos) < 20:
                    confidence += 0.2
                
                candidates.append({
                    'current': b1,
                    'configured': b2,
                    'confidence': confidence,
                    'source': f'sequence_{i}',
                    'bytes': chunk
                })
        
        # ESTRATEGIA 5: Análisis específico para casos edge
        # A veces WC3 usa formato diferente para slots
        for i in range(len(data) - 1):
            if i + 1 < len(data):
                b1, b2 = data[i], data[i + 1]
                
                # Caso especial: solo jugadores actuales (asumimos configured=12)
                if 0 <= b1 <= 12 and b2 == 0:
                    # Probablemente b1 es current_players, asumimos 12 slots configurados
                    confidence = 0.6
                    if name_end_pos != -1 and abs(i - name_end_pos) < 15:
                        confidence += 0.2
                    
                    candidates.append({
                        'current': b1,
                        'configured': 12,  # Asumir máximo por defecto
                        'confidence': confidence,
                        'source': f'single_value_{i}',
                        'bytes': (b1, b2)
                    })
        
        # Seleccionar el mejor candidato
        if candidates:
            best = max(candidates, key=lambda x: x['confidence'])
            game_info['current_players'] = best['current']
            game_info['configured_slots'] = best['configured']
            game_info['slots_taken'] = best['current']
            game_info['slots_total'] = 12  # Siempre 12 para WC3
            game_info['max_players'] = 12  # Siempre 12 para WC3
            game_info['raw_data'] = best
            
            # Determinar estado del juego basado en slots configurados
            if best['current'] == 0:
                game_info['game_status'] = 'empty'
            elif best['current'] >= best['configured']:
                game_info['game_status'] = 'full'
            else:
                game_info['game_status'] = 'waiting'
        
        if debug and candidates:
            print(f"    🔧 Candidatos: {len(candidates)}")
            for i, cand in enumerate(sorted(candidates, key=lambda x: x['confidence'], reverse=True)[:3]):
                bytes_info = cand.get('bytes', 'N/A')
                print(f"       {i+1}. {cand['source']}: {cand['current']}/{cand.get('configured', '?')} (conf: {cand['confidence']:.2f})")
        
        return game_info if (game_info['name'] or game_info['current_players'] is not None) else None
        
    except Exception as e:
        if debug:
            print(f"    ❌ Error: {e}")
        return None

class WC3LanScanner:
    def __init__(self, debug=True):
        self.debug = debug
        self.games = {}
        self.last_seen = {}
        self.cleanup_interval = 45
        self.lock = threading.Lock()
        
    def format_game_status(self, game_info):
        """Formatea la información del juego - Versión corregida"""
        if not game_info:
            return "❓ Info incompleta"
            
        name = game_info['name'] or "Sin nombre"
        protocol = game_info.get('protocol_type', 'unknown')
        
        if game_info['current_players'] is not None:
            current = game_info['current_players']
            configured = game_info.get('configured_slots', 12)
            total_slots = 12  # Siempre 12 en WC3
            
            # Estado basado en slots configurados
            if current == 0:
                status = "🟢 VACÍO"
            elif current >= configured:
                status = "🔴 LLENO"
            else:
                free_configured = configured - current
                status = f"🟡 {free_configured} LIBRES"
            
            # Mostrar: actual/configurados (total 12)
            if configured == 12:
                slot_info = f"{current}/12"
            else:
                slot_info = f"{current}/{configured}(12)"
            
            base_info = f"📝 {name} | 👥 {slot_info} | {status}"
        else:
            base_info = f"📝 {name} | ❓ Slots desconocidos"
        
        if self.debug:
            base_info += f" | 🔧 {protocol}"
            
        return base_info
    
    def cleanup_old_games(self):
        """Limpia juegos inactivos"""
        with self.lock:
            current_time = time.time()
            to_remove = [
                key for key, last_time in self.last_seen.items()
                if current_time - last_time > self.cleanup_interval
            ]
            
            for key in to_remove:
                self.games.pop(key, None)
                self.last_seen.pop(key, None)
            
            if to_remove and self.debug:
                print(f"🧹 Limpiados {len(to_remove)} juegos inactivos")
    
    def scan_multiple_ports(self):
        """Escanea múltiples puertos comunes de WC3"""
        ports = [6112, 6113, 6114, 6115, 6116, 47624]
        threads = []
        
        for port in ports:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            thread.daemon = True
            threads.append(thread)
            thread.start()
        
        return threads
    
    def scan_port(self, port):
        """Escanea un puerto específico"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            sock.bind(('', port))
            sock.settimeout(2.0)
            
            if self.debug:
                print(f"🎯 Escuchando en puerto {port}")
            
            packet_count = 0
            last_cleanup = time.time()
            
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    packet_count += 1
                    current_time = time.time()
                    
                    # Filtrar tráfico local
                    if addr[0] == '127.0.0.1' or len(data) < 4:
                        continue
                    
                    game_info = extract_wc3_game_info(data, addr, debug=self.debug)
                    
                    if game_info and (game_info['name'] or game_info['current_players'] is not None):
                        with self.lock:
                            game_key = f"{addr[0]}:{port}:{game_info.get('name', 'unnamed')}"
                            self.games[game_key] = game_info
                            self.last_seen[game_key] = current_time
                        
                        print(f"\n📦 Puerto {port} | Paquete #{packet_count} | {addr[0]}:{addr[1]}")
                        print(f"   {self.format_game_status(game_info)}")
                    
                    elif self.debug:
                        print(f"📦 Puerto {port} | Paquete #{packet_count} | {addr[0]}:{addr[1]} | Sin info útil")
                    
                    # Cleanup periódico
                    if current_time - last_cleanup > 15:
                        self.cleanup_old_games()
                        last_cleanup = current_time
                        self.show_active_games()
                
                except socket.timeout:
                    current_time = time.time()
                    if current_time - last_cleanup > 15:
                        self.cleanup_old_games()
                        last_cleanup = current_time
                    continue
                    
        except OSError as e:
            if self.debug:
                print(f"❌ Error en puerto {port}: {e}")
        finally:
            sock.close()
    
    def show_active_games(self):
        """Muestra resumen de juegos activos"""
        with self.lock:
            if self.games:
                print(f"\n📋 RESUMEN - JUEGOS ACTIVOS ({len(self.games)}):")
                for i, (key, game_info) in enumerate(self.games.items(), 1):
                    print(f"   {i}. {self.format_game_status(game_info)}")
                print("-" * 80)
    
    def start_scanning(self):
        """Inicia el escaneo"""
        print("🚀 WC3 LAN Game Scanner - Slots Corregidos")
        print("📊 Siempre muestra X/Y(12) donde:")
        print("   X = Jugadores actuales")
        print("   Y = Slots configurados para el mapa")
        print("   12 = Slots totales disponibles en WC3")
        print("📡 Escaneando puertos: 6112, 6113, 6114, 6115, 6116, 47624")
        print("⚡ Presiona Ctrl+C para salir")
        print("=" * 80)
        
        threads = self.scan_multiple_ports()
        
        try:
            while True:
                time.sleep(30)
                self.show_active_games()
                
        except KeyboardInterrupt:
            print(f"\n👋 Cerrando escáner...")
            with self.lock:
                print(f"🎮 Juegos únicos detectados: {len(self.games)}")
                if self.games:
                    print("📝 Últimos juegos detectados:")
                    for key, game_info in list(self.games.items())[-5:]:
                        print(f"   - {self.format_game_status(game_info)}")

def main():
    """Función principal - Inicia directamente en modo debug detallado"""
    print("🎮 WC3 LAN Game Scanner - Iniciando en modo debug detallado...")
    scanner = WC3LanScanner(debug=True)
    scanner.start_scanning()

if __name__ == "__main__":
    main()