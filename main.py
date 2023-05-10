import subprocess
import ipaddress
import nmap

def string_to_ip(user_ip):
    try:
        ip_obj = ipaddress.ip_address(user_ip)
        return ip_obj
    except ValueError:
        print("Invalid IP address format.")
        return None

user_ip = input("Enter IP address you want to scan: ")

ip_address_obj = string_to_ip(user_ip)
if ip_address_obj:
    print(ip_address_obj)


#def start_openvas_container():
#    command = "docker run -d -p 443:443 -p 9390:9390 --name openvas mikesplain/openvas"
#    subprocess.run(command, shell=True)

#def start_nmap_container():
#    command = "docker run -d --name nmap_container bytesizedalex/nmap"
#    subprocess.run(command, shell=True)

#start_openvas_container()
#start_nmap_container()

port_range = input("Enter the port range to scan (choose between '1-1024'): ")
protocol = input("Enter the protocol to use (TCP/UDP): ")
arguments = f"-p {port_range} -{protocol.lower()}" #make args line to give to function nm.scan()

nm=nmap.PortScanner()
nm.scan(ip_address_obj, arguments)

for host in nm.all_hosts():
     print('----------------------------------------------------')
     print('Host : %s (%s)' % (host, nm[host].hostname()))
     print('State : %s' % nm[host].state())
     for proto in nm[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)

         lport = nm[host][proto].keys()
         lport.sort()
         for port in lport:
             print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

