#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print('Welcome to my basic nmap port scanner')
print(' ')
print('<--------------------------------------------------------->')

ip = input("Please input the IP address you wish to scan: ")
print('The IP you entered is: ', ip)
type(ip)

resp=input(""" \nWhat type of scan would you like to execute?
	1) SYN ACK Scan
	2) UDP Scan
	3) Comprehensive Scan""")

print('You have selected option: ', resp)

#First Scan
if resp == '1':
	print('Nmap version: '), scanner.nmap_version()
	scanner.scan(ip,'1-1024','-v -sS')
	print(scanner.scaninfo())
	print('IP Status: ', scanner[ip].state)
	print(scanner[ip].allprotocols())
	print('Open Ports: ', scanner[ip]['tcp'].keys())
elif resp=='2':
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip, '1-1024', '-v -sU')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip].state())
	print(scanner[ip].all_protocols())
	print("Open Ports: ", scanner[ip]['udp'].keys())
elif resp == '3':
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip, '1-1024', '-v -sS -sV -sC -A -O')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip].state())
	print(scanner[ip].all_protocols())
	print("Open Ports: ", scanner[ip]['tcp'].keys())
elif resp >= '4':
	print("Input invalid! Please input valid option.")