import os
import typer
from network.pingip import ping
#<---Start_Menu--->
def main():
    while True:
        choice = input("Enter command: \n >> network menu \n > exit \n>>>").strip().lower()

        match choice:
            case "network menu":
                network_menu()
             
            case "exit":
                typer.echo("bye")
                break

            case _:
                typer.echo("Invalid command. Try 'ping' or 'exit'.")
#<---Network_Menu--->
def network_menu():
    while True:
        choice = input("Enter command: \n > ping \n > back \n > exit \n>>>").strip().lower()

        match choice:
            case "ping":
                ping()
            case "back":
                return
            case "exit":
                typer.echo("good bye")
                break

            case _:
                typer.echo("Invalid command. Try 'ping' or 'exit'.")
                
if __name__ == "__main__":
    main()