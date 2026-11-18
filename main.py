import os
import typer
#<---Import_Network_Tools--->
from network.pingip import ping
from network.portscan import portscan
from network.whois_lookup import whois
from network.http_headers import http_headers
from network.ssl_checker import ssl_checker
from network.dns_lookup import dns_lookup
#<---Import_System_Tools--->
from system.system_info import system_info

#<---Start_Menu--->
def main():
    while True:
        choice = input("Enter Number Item: \n >> 1.network menu(6) \n >> 2.system menu(1)\n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                network_menu()
            case "2":
                system_menu()
            case "00":
                typer.echo("bye")
                raise SystemExit

            case _:
                typer.echo("Invalid command. Try '0-9'.")
#<---Network_Menu--->
def network_menu():
    while True:
        choice = input("Enter command: \n > 1.ping \n > 2.portscan \n > 3.whois \n > 4.http_headers \n > 5.ssl_checker \n > 6.dns_lookup \n > 0.back \n > 00.exit \n>>>").strip().lower()

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
        choice = input("System Menu: \n > 1.system info \n > 0.back \n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                system_info()
            case "0":
                return
            case "00":
                typer.echo("bye")
                raise SystemExit
            case _:
                typer.echo("Invalid command. Try '1', '0' or '00'.")                
if __name__ == "__main__":
    main()