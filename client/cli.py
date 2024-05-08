#!/usr/bin/env python3

from socket import socket, AF_INET, SOCK_STREAM
from ssl import wrap_socket, CERT_NONE, PROTOCOL_SSLv23
from sys import argv


class client:

    def version(self, server_host, server_port):

        try:
            cli_soc = socket(AF_INET, SOCK_STREAM)
            serv_soc = wrap_socket(cli_soc, keyfile="key.pem", certfile='cert.pem',
                                   server_side=False, cert_reqs=CERT_NONE, ssl_version=PROTOCOL_SSLv23)

            print(f"\nConnecting to {server_host} : {server_port}")
            serv_soc.connect((server_host, server_port))

            print(serv_soc.recv(1024).decode())
            while True:
                Name = input("Name: ")
                register = input("Registration Number: ")
                password = input("Password: ")

                serv_soc.sendall(f"{Name} {register} {password}".encode())

                res_yn = serv_soc.recv(7025).decode()

                if res_yn == "pass":
                    print("\nLogin successful!\n")
                    break
                else:
                    print(
                        "\nIncorrect Name or Registration number or password. Please try again!")

            while True:
                print(f"Welcome {Name}!")
                print("Please enter a number (1-4)")
                print("1. Vote")
                print("2. View election result")
                print("3. My vote history")
                print("4. Exit")
                preference = input("Enter your preference: ")
                print(" ")

                if preference not in ["1", "2", "3", "4"]:
                    serv_soc.sendall("invalid".encode())
                    res = serv_soc.recv(7025).decode()
                    print(f"\n{res}\n")
                elif preference == "1":
                    serv_soc.sendall("1".encode())
                    res1 = serv_soc.recv(7025).decode()
                    if res1 == "0":
                        print("\nCandidates: (enter 1 or 2)")
                        print("1. Chris")
                        print("2. Linda")
                        choice = input("Enter your choice: ")
                        if choice == "1":
                            serv_soc.sendall("1".encode())
                            update = serv_soc.recv(7025).decode()
                            print("\n", update, "\n")
                        elif choice == "2":
                            serv_soc.sendall("2".encode())
                            update = serv_soc.recv(7025).decode()
                            print("\n", update, "\n")
                        else:
                            print("Enter valid choice")
                    elif res1 == "1":
                        print("\n***You have already voted!***\n")
                elif preference == "2":
                    serv_soc.sendall("2".encode())
                    winner = serv_soc.recv(7025).decode()
                    if winner == "0":
                        print("\nThe result is not available.\n")
                    else:
                        winner = eval(winner)
                        if winner[2] == 2 or winner[2] == 3:
                            print("{} Win".format(winner[0]))
                            print("{} {}".format(winner[0], winner[2]))
                            print("{} {}".format(winner[1], winner[3]))
                            print("")
                        else:
                            print("{} Win".format(winner[1]))
                            print("{} {}".format(winner[0], winner[2]))
                            print("{} {}".format(winner[1], winner[3]))
                            print("")
                elif preference == "3":
                    serv_soc.sendall("3".encode())
                    res3 = serv_soc.recv(7025).decode()
                    print(res3, "\n")
                elif preference == "4":
                    serv_soc.sendall("exit".encode())
                    res4 = serv_soc.recv(7025).decode()
                    print(res4, "\n")
                    break

            serv_soc.close()
            exit(0)

        except KeyboardInterrupt as e:
            print("Keyboard interrupt", e)
        except ConnectionRefusedError as e:
            print("\nplease run the server first")
            print("Connection refused", e)
        except OSError as e:
            print("Connection error", e)


if len(argv) != 3:
    print("Must be in this formate './sftpcli.py <server_host> <server_port>' ")
    exit(1)
server_host = argv[1]
server_port = int(argv[2])

s = client()
s.version(server_host, server_port)
