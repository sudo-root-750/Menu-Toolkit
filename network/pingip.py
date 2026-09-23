import os
import typer

def ping():
    host = input("Please Enter Your Ip or Domain: ")
    response = os.system(f"ping -n 4 {host}")
    if response == 0:
        typer.secho(f"{host} ==> Host is Reachable", fg=typer.colors.GREEN)
    else:
        typer.secho(f"{host} ==> Host is Unreachable", fg=typer.colors.RED)