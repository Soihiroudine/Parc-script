import socket

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

hostname = get_hostname("192.168.1.10") # Remplacez "192.168.1.10" par l'adresse IP souhaitée

if hostname:
    print(f"Hostname : {hostname}")
else:
    print("Hostname introuvable")
