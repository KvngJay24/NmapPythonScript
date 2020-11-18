#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print('Welcome to my basic nmap port scanner')
print(' ')
print('<--------------------------------------------------------->')

ip_addr = input("Please input the IP address you wish to scan: ")
print('The IP you entered is: ', ip_addr)
type(ip_addr)

resp=input(""" \nWhat type of scan would you like to execute?
	1) SYN ACK Scan
	2) UDP Scan
	3) Comprehensive Scan""")

print('You have selected option: ', resp)

#First Scan
if resp == '1':
	print('Nmap version: '), scanner.nmap_version()
	scanner.scan(ip_addr,'1-1024','-v -sS')
	print(scanner.scaninfo())
	print('IP Status: ', scanner[ip_addr].state)
	print(scanner[ip_addr].allprotocols())
	print('Open Ports: ', scanner[ip_addr]['tcp'].keys())
elif resp=='2':
	print("Namp Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sU')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
	print("Namp Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
else resp >= '4':
	print("Input invalid! Please input valid option.")