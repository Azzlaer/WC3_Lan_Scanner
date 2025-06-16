import socket
import re

def clean_game_name(raw_name):
    if not raw_name:
        return None
    cleaned = raw_name.strip()
    cleaned = re.sub(r'[\x00-\x1F]+.*$', '', cleaned).strip()
    cleaned = re.sub(r'[♥♠♦♣☺☻]+.*$', '', cleaned).strip()
    return cleaned if len(cleaned) >= 3 else None

def extract_game_name(data, debug=False):
    try:
        decoded = data.decode('latin1', errors='ignore')
        candidates = []

        # Patrón 1
        pattern1 = r'\x01\x02\x03\x04([A-Za-z0-9\s#+@\-_.]{3,50})\x00'
        matches = re.findall(pattern1, decoded)
        for match in matches:
            cleaned = clean_game_name(match)
            if cleaned:
                candidates.append(("Patrón 1", cleaned))

        # Patrón 2
        pattern2 = r'\[.*?\]([^/]*?)\/w3'
        matches = re.findall(pattern2, decoded)
        for match in matches:
            cleaned = clean_game_name(match.strip())
            if cleaned:
                candidates.append(("Patrón 2", cleaned))

        # Patrón 3
        pattern3 = r'PX3W.*?\x01\x02\x03\x04([A-Za-z0-9\s#+@\-_.]{3,50})'
        matches = re.findall(pattern3, decoded)
        for match in matches:
            cleaned = clean_game_name(match)
            if cleaned:
                candidates.append(("Patrón 3", cleaned))

        # Patrón 4
        pattern4 = r'(\[(?:PE|US|CL|BR|AR|MX|CO|VE|EC|BO|PY|UY|CR|GT|HN|SV|NI|PA|DO|CU)\]\s*[A-Za-z0-9\s\[\]#+@\-_.]{1,45})'
        matches = re.findall(pattern4, decoded, re.IGNORECASE)
        for match in matches:
            cleaned = clean_game_name(match.strip())
            if cleaned:
                candidates.append(("Patrón 4", cleaned))

        # Patrón 5 (último recurso)
        pattern5 = r'([A-Za-z][A-Za-z0-9\s#+@\-_.]{2,45})\x00'
        matches = re.findall(pattern5, decoded)
        for match in matches:
            if len(match.strip()) >= 4 and not re.match(r'^[a-z]{1,4}$', match.lower()):
                cleaned = clean_game_name(match)
                if cleaned:
                    candidates.append(("Patrón 5", cleaned))

        # Mostrar todos los candidatos si debug está activo
        if debug and candidates:
            print("📋 Posibles nombres detectados:")
            for i, (source, name) in enumerate(candidates):
                print(f"   {i+1}. [{source}] -> '{name}'")

        # Elegir el primer candidato válido
        return candidates[0][1] if candidates else None

    except Exception as e:
        print(f"[!] Error al analizar paquete: {e}")
        return None

def analyze_packet_debug(data):
    try:
        decoded = data.decode('latin1', errors='ignore')
        print(f"    Longitud: {len(data)} bytes")
        print(f"    Hex (primeros 60 bytes): {data[:60].hex()}")
        print(f"    ASCII: {repr(decoded[:80])}")
    except Exception as e:
        print(f"    Error en debug: {e}")

def listen_lan_games(debug=True):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.bind(('', 6112))
    except OSError as e:
        print(f"❌ Error al abrir el puerto 6112: {e}")
        print("💡 Asegúrate de que no haya otra aplicación usando este puerto")
        return
    
    print("🎮 Escuchando partidas LAN en el puerto UDP 6112...")
    if debug:
        print("🔍 Modo debug activado")
    print()

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            game_name = extract_game_name(data, debug=debug)

            if game_name:
                print(f"\n🌐 {addr[0]}:{addr[1]} | Nombre detectado: {game_name}\n")
            else:
                print(f"\n📩 {addr[0]}:{addr[1]} | Sin nombre válido detectado.")
                if debug:
                    analyze_packet_debug(data)
                    print("-" * 70)

        except KeyboardInterrupt:
            print("\n👋 Cerrando escáner...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
    
    sock.close()

if __name__ == "__main__":
    listen_lan_games(debug=True)
