import os
import typer

def main():
    while True:
        choice = input("Enter command: \n > ping \n > exit \n>>>").strip().lower()

        match choice:
            case "ping":
                host = input("Please Enter Your Ip or Domain: ")
                response = os.system(f"ping -n 4 {host}")
                if response == 0:
                    typer.secho(f"{host} ==> Host is Reachable", fg=typer.colors.GREEN)
                else:
                    typer.secho(f"{host} ==> Host is Unreachable", fg=typer.colors.RED)

            case "exit":
                typer.echo("bye")
                break

            case _:
                typer.echo("Invalid command. Try 'ping' or 'exit'.")

if __name__ == "__main__":
    main()