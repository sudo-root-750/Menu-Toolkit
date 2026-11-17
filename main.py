import os
import typer
from network.pingip import ping
from network.portscan import portscan
#<---Start_Menu--->
def main():
    while True:
        choice = input("Enter Number Item: \n >> 1.network menu(2) \n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                network_menu()
             
            case "00":
                typer.echo("bye")
                break

            case _:
                typer.echo("Invalid command. Try '0-9'.")
#<---Network_Menu--->
def network_menu():
    while True:
        choice = input("Enter command: \n > 1.ping \n > 2.portscan \n > 0.back \n > 00.exit \n>>>").strip().lower()

        match choice:
            case "1":
                ping()
            case "2":
                portscan()
            case "0":
                return
            case "00":
                typer.echo("good bye")
                break

            case _:
                typer.echo("Invalid command. Try '0-9'.")
                
if __name__ == "__main__":
    main()