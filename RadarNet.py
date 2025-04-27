

import scapy.all as scapy
import os
import ipaddress
import csv
import socket
from datetime import datetime
from manuf import manuf  # Novo: identificação de fabricante

# Cores ANSI
VERDE = "\033[92m"
VERMELHO = "\033[91m"
AZUL = "\033[94m"
AMARELO = "\033[93m"
RESET = "\033[0m"

parser = manuf.MacParser()

def logo():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""{AZUL}
     ____            _             _   _      _   
    |  _ \ __ _  ___| | ____ _  __| | | | ___| |_ 
    | |_) / _` |/ __| |/ / _` |/ _` | | |/ _ \ __|
    |  _ < (_| | (__|   < (_| | (_| | | |  __/ |_ 
    |_| \_\__,_|\___|_|\_\__,_|\__,_| |_|\___|\__|

             {RESET}{AMARELO}→ Diagnóstico de Rede com ARP em Python ←{RESET}
                       {VERDE}Powered by: RadarNet{RESET}
    """)

def obter_ip():
    while True:
        ip = input(f"{AZUL}Insira o endereço IP da rede (ex: 192.168.1.0/24): {RESET}")
        if validar_ip(ip):
            return ip
        else:
            print(f"{VERMELHO}Endereço IP inválido. Tente novamente.{RESET}")

def validar_ip(ip):
    try:
        ipaddress.IPv4Network(ip, strict=False)
        return True
    except ValueError:
        return False

def diagnostico_rede(ip):
    print(f"\n{AMARELO}Iniciando o diagnóstico da rede: {ip}{RESET}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    resposta = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    dispositivos = []
    for elemento in resposta:
        mac = elemento[1].hwsrc
        fabricante = parser.get_manuf(mac) or "Desconhecido"
        dispositivo = {
            'ip': elemento[1].psrc,
            'mac': mac,
            'fabricante': fabricante
        }
        dispositivos.append(dispositivo)

    return dispositivos

def exibir_resultados(dispositivos):
    print(f"\n{VERDE}===== DISPOSITIVOS ENCONTRADOS ====={RESET}")
    if dispositivos:
        for d in dispositivos:
            print(f"{AZUL}IP: {d['ip']} | MAC: {d['mac']} | Fabricante: {d['fabricante']}{RESET}")
    else:
        print(f"{VERMELHO}Nenhum dispositivo encontrado.{RESET}")

def salvar_resultados(dispositivos):
    if not dispositivos:
        print(f"{VERMELHO}Nada a salvar. Nenhum dispositivo encontrado.{RESET}")
        return

    print(f"\n{AMARELO}Deseja salvar os resultados?{RESET}")
    print("1 - Salvar em .txt")
    print("2 - Salvar em .csv")
    print("3 - Não salvar")

    escolha = input("Escolha uma opção: ")
    agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if escolha == "1":
        nome = f"radarnet_{agora}.txt"
        with open(nome, "w") as arq:
            for d in dispositivos:
                arq.write(f"IP: {d['ip']} | MAC: {d['mac']} | Fabricante: {d['fabricante']}\n")
        print(f"{VERDE}Resultados salvos em: {nome}{RESET}")

    elif escolha == "2":
        nome = f"radarnet_{agora}.csv"
        with open(nome, mode='w', newline='') as arq:
            writer = csv.writer(arq)
            writer.writerow(["IP", "MAC", "Fabricante"])
            for d in dispositivos:
                writer.writerow([d['ip'], d['mac'], d['fabricante']])
        print(f"{VERDE}Resultados salvos em: {nome}{RESET}")

    else:
        print(f"{AZUL}Resultados não foram salvos.{RESET}")

def verificar_portas(ip, portas=[22, 80, 443, 3389]):
    print(f"\n{AMARELO}Verificando portas abertas em {ip}...{RESET}")
    for porta in portas:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        resultado = sock.connect_ex((ip, porta))
        if resultado == 0:
            print(f"{VERDE}Porta {porta} ABERTA{RESET}")
        sock.close()

def menu_portas(dispositivos):
    if not dispositivos:
        return
    print(f"\n{AMARELO}Deseja escanear as portas de algum dispositivo? (S/N){RESET}")
    opcao = input().strip().lower()
    if opcao == 's':
        for i, d in enumerate(dispositivos):
            print(f"{i+1} - {d['ip']} ({d['fabricante']})")
        try:
            escolha = int(input("Escolha o número do dispositivo: ")) - 1
            ip = dispositivos[escolha]['ip']
            verificar_portas(ip)
        except:
            print(f"{VERMELHO}Escolha inválida.{RESET}")

if __name__ == "__main__":
    logo()
    ip_rede = obter_ip()
    dispositivos_encontrados = diagnostico_rede(ip_rede)
    exibir_resultados(dispositivos_encontrados)
    salvar_resultados(dispositivos_encontrados)
    menu_portas(dispositivos_encontrados)


