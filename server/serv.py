#!/usr/bin/env python3

from socket import socket, AF_INET, SOCK_STREAM, gethostname
from ssl import wrap_socket, CERT_NONE, PROTOCOL_SSLv23, SSLError
from sys import argv
from os import path, urandom
from datetime import datetime
from Crypto.Cipher import AES
from base64 import b64encode
from hashlib import sha1
from ast import literal_eval


class server():

    def version(self, HOST, PORT):

        try:

            serv_soc = socket(AF_INET, SOCK_STREAM)
            serv_soc.bind((HOST, PORT))
            serv_soc.listen(6)

            def encrypt(message, key):
                message = message.encode(
                    'utf-8') + (AES.block_size - len(message) % AES.block_size) * b"\0"
                iv = b"1234567890123456"
                cipher = AES.new(key, AES.MODE_CBC, iv)
                return b64encode(iv + cipher.encrypt(message))

            def sha1_hash(data):
                hash = sha1(data)
                return hash.hexdigest()

            while True:
                print(
                    '\nRunning Server on {}.cs.binghamton.edu : {}'.format(HOST, PORT))

                loc = path.join("voterinfo.txt")
                voterinfo = {}
                vote_data = {"Alice": {"0": 1123456, "1": b"1234"}, "Bob": {
                    "0": 1138765, "1": b"5678"}, "Tom": {"0": 1154571, "1": b"9012"}}

                symmetric_key = {}
                with open(loc, "w") as f:
                    symmetric_key['Alice'] = urandom(16)
                    f.writelines(
                        f"Alice {vote_data['Alice']['0']} { encrypt(sha1_hash(vote_data['Alice']['1']), symmetric_key['Alice']) }\n")
                    symmetric_key['Bob'] = urandom(16)
                    f.writelines(
                        f"Bob {vote_data['Bob']['0']} { encrypt(sha1_hash(vote_data['Bob']['1']), symmetric_key['Bob']) }\n")
                    symmetric_key['Tom'] = urandom(16)
                    f.writelines(
                        f"Tom {vote_data['Tom']['0']} { encrypt(sha1_hash(vote_data['Tom']['1']), symmetric_key['Tom']) }\n")

                with open('symmetrickey.txt', 'w') as f:
                    f.writelines(f"{symmetric_key['Alice']}\n")
                    f.writelines(f"{symmetric_key['Bob']}\n")
                    f.writelines(f"{symmetric_key['Tom']}\n")

                with open(loc, "r") as f:
                    for line in f:
                        name, register, password = line.strip().split(" ")
                        voterinfo[name] = {"0": register,
                                           "1": literal_eval(password)}

                client_socket, client_address = serv_soc.accept()
                print(
                    f"\n Client connected from {client_address[0]}:{client_address[1]}")

                cli_soc = wrap_socket(client_socket, keyfile="key.pem", certfile='cert.pem',
                                      server_side=True, cert_reqs=CERT_NONE, ssl_version=PROTOCOL_SSLv23)

                cli_soc.send(
                    "\n***Welcome to the BU Remote Server!***\n".encode())

                while True:
                    data = cli_soc.recv(1024).decode()
                    Name, register, password = data.split()

                    if Name in voterinfo:
                        if voterinfo[Name]['0'] == register:
                            if voterinfo[Name]['1'] == encrypt(sha1_hash(password.encode('utf-8')), symmetric_key[Name]):
                                res_yn = "pass"
                                cli_soc.sendall(res_yn.encode())
                                break
                            else:
                                res_yn = "invoke"
                        else:
                            res_yn = "invoke"
                    else:
                        res_yn = "invoke"

                    cli_soc.sendall(res_yn.encode())

                while True:

                    command_sftp = cli_soc.recv(1024).decode()
                    loc1 = path.join("history.txt")
                    loc2 = path.join("result.txt")
                    history = {}
                    result = {'Chris': 0, 'Linda': 0}

                    if (path.exists(loc1)):
                        with open(loc1, "r") as f1:
                            for line in f1:
                                n1, vote = line.strip().split(" ")
                                history[n1] = vote

                        if history != {}:
                            with open(loc2, "r") as f2:
                                for line in f2:
                                    leader, number = line.strip().split(" ")
                                    result[leader] = int(number)

                    if command_sftp == "1":
                        if history.__contains__(Name):
                            cli_soc.sendall("1".encode())
                        else:
                            cli_soc.sendall("0".encode())
                            choice = cli_soc.recv(1024).decode()
                            if choice == '1':
                                num = result['Chris']
                                num += 1
                                result['Chris'] = num
                            else:
                                num = result["Linda"]
                                num += 1
                                result["Linda"] = num
                            history[Name] = (datetime.today()).strftime(
                                "%YY-%mm-%dd-%HH:%MM:%SS")
                            with open(loc1, "w") as f1:
                                for i, v in history.items():
                                    f1.writelines(f"{i} {v}\n")

                            with open(loc2, "w") as f2:
                                for i, v in result.items():
                                    f2.writelines(f"{i} {v}\n")

                            cli_soc.sendall(
                                "Recorded your response. Thank you for voting!".encode())
                    elif command_sftp == "2":
                        if sum(result.values()) == 3:
                            keys = list(result.keys())
                            values = list(result.values())
                            keys.extend(values)
                            cli_soc.sendall(f"{keys}".encode())
                        else:
                            cli_soc.sendall("0".encode())
                    elif command_sftp == "3":
                        if history.__contains__(Name):
                            cli_soc.sendall(f"{Name} {history[Name]}".encode())
                        else:
                            cli_soc.sendall(
                                f"{Name}, you haven't voted.".encode())
                    elif command_sftp == 'exit':
                        cli_soc.sendall(
                            "Client Closed!".encode())
                        break
                    elif command_sftp == "invalid":
                        msg = "Invalid Number. Enter only (1 - 4) "
                        cli_soc.sendall(msg.encode())
                    elif command_sftp == '':
                        pass
                print(
                    f"\n Client disconnected from {client_address[0]}:{client_address[1]}")

        except SSLError as s:
            print("\nssl_client_socket Error", s)
        except FileNotFoundError as f:
            print("\nFile not found", f)
        except KeyboardInterrupt:
            print("\n Server Closed!")


if len(argv) != 2:
    print("Must be in this formate './sftpserv.py <server_port>' ")
    exit(1)

HOST = gethostname()
PORT = int(argv[1])

s = server()
s.version(HOST, PORT)
