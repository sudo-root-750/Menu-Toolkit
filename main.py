import os
import typer
#<---Import_Network_Tools--->
from network.pingip import ping
from network.portscan import portscan
from network.whois_lookup import whois
from network.http_headers import http_headers
from network.ssl_checker import ssl_checker
from network.dns_lookup import dns_lookup
from network.speedtest import speedtest
from network.ping_sweep import ping_sweep

#<---Import_System_Tools--->
from system.system_info import system_info
from system.process_viewer import process_viewer
from system.open_connections import open_connections

#<---Import_Security_Tools--->
from security.crypto_tool import crypto_tool

#<---Start_Menu--->
def main():
    while True:
        choice = input("Enter Number Item: \n >> 1.network menu(8) \n >> 2.system menu(3) \n >> 3.security_menu(1) \n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                network_menu()
            case "2":
                system_menu()
            case "3":
                security_menu()    
            case "00":
                typer.echo("bye")
                raise SystemExit

            case _:
                typer.echo("Invalid command. Try '0-9'.")
#<---Network_Menu--->
def network_menu():
    while True:
        choice = input("Enter command: \n > 1.ping \n > 2.portscan \n > 3.whois \n > 4.http_headers \n > 5.ssl_checker \n > 6.dns_lookup \n > 7.speedtest \n > 8.ping_sweep \n > 0.back \n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                ping()
            case "2":
                portscan()
            case "3":
                whois()
            case "4":
                http_headers()
            case "5":
                ssl_checker()
            case "6":
                dns_lookup()
            case "7":
                speedtest() 
            case "8":
                ping_sweep()              
            case "0":
                return
            case "00":
                typer.echo("good bye")
                raise SystemExit

            case _:
                typer.echo("Invalid command. Try '0-9'.")
#<---System_Menu--->
def system_menu():
    while True:
        choice = input("System Menu: \n > 1.system info \n 2.process viewer \n 3.open connections\n > 0.back \n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                system_info()
            case "2":
                process_viewer()
            case "3":
                open_connections()        
            case "0":
                return
            case "00":
                typer.echo("bye")
                raise SystemExit
            case _:
                typer.echo("Invalid command. Try '1', '0' or '00'.") 
#<---Security_Menu--->
def security_menu():
    while True:
        choice = input("Security Menu: \n > 1.crypto_tool \n > 0.back \n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                crypto_tool()
            case "0":
                return
            case "00":
                typer.echo("bye")
                raise SystemExit
            case _:
                typer.echo("Invalid command. Try '1', '0' or '00'.")              
if __name__ == "__main__":
    main()