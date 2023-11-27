# Client to implement simplified RSA algorithm and then subsequently send
# encrypted prime numbers to a server. The client says hello to the server
# and indicates
# which cryptographic algorithms it can support. The server picks one
# asymmetric key and one symmetric key algorithm and then responds to the
# client with its public key and a nonce. The client generates a symmetric
# key to send to the server, encrypts the symmetric key with the public key,
# and then encrypts the nonce with the symmetric key.
# If the nonce is verified, then the server will send the "106 Nonce Verified"
# message.

import socket
import math
import random
import sys
import simplified_AES
import NumTheory

# Author: Shemar Marks
# Last modified: 2023-11-13
# Version: 0.1
#!/usr/bin/python3


class RSAClient:
    def __init__(self, address, port):
        self.address = address
        self.port = int(port)
        self.socket = socket.socket()
        self.lastRcvdMsg = None
        self.sessionKey = None  # For storing the symmetric key
        self.modulus = None  # For storing the server's n in the public key
        self.serverExponent = None  # For storing the server's e in the public key

    def connect(self):
        self.socket.connect((self.address, self.port))

    def send(self, message):
        self.socket.send(bytes(message, "utf-8"))

    def read(self):
        try:
            data = self.socket.recv(4096).decode("utf-8")
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Server is unavailable")

    def close(self):
        print("closing connection to", self.address)
        try:
            self.socket.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f"{self.address}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None

    def RSAencrypt(self, msg):
        """Encrypts a message using RSA"""
        if msg >= self.modulus:
            raise ValueError("Message should be less than modulus for RSA encryption.")
        return NumTheory.NumTheory.expMod(msg, self.serverExponent, self.modulus)

    def RSAdecrypt(self, cText):
        # Decryption side of RSA
        return NumTheory.NumTheory.expMod(cText, self.privExponent, self.modulus)

    def computeSessionKey(self):
        """Computes this node's session key"""
        self.sessionKey = random.randint(1, 65536)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey)  # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext)  # Running simplified AES.
        return ciphertext

    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)


    def serverHello(self):
        status = "101 Hello 3DES, AES, RSA16, DH16"
        return status

    def sessionKeyMsg(self, nonce):
        """Generates a session key message to be sent to the server"""
        # Generate a random session key
        self.computeSessionKey()

        # Encrypt the session key using RSA
        encrypted_session_key = self.RSAencrypt(self.sessionKey)

        # Encrypt the nonce using the session key
        encrypted_nonce = self.AESencrypt(nonce)

        # Construct the session key message
        session_key_message = (
            f"103 SessionKey {encrypted_session_key} {encrypted_nonce}"
        )
        return session_key_message

    def primesEncryptedResponse(self, response, prime_a, prime_b):
        """Handles the response to the "109 CompositeEncrypted..." message from the server"""
        # Extract the encrypted product from the response
        _, _, encrypted_product = response.split()

        # Decrypt the product using simplified AES
        decrypted_product = self.AESdecrypt(int(encrypted_product))
        print(decrypted_product)
        # Send the "200 OK" message to the server if the products match
        if decrypted_product == (NumTheory.NumTheory.lcm(prime_a, prime_b)):
            self.send("200 OK")
        else:
            self.send("400 Error")

    def start(self):
        """Main sending and receiving loop for the client"""
        self.connect()

        # Send the server hello message
        self.send(self.serverHello())
        self.read()
        print(self.lastRcvdMsg)

        # Parse server response
        if "102 Hello AES, RSA16" in self.lastRcvdMsg:
            # Extract modulus, server exponent, and nonce from the server response
            _, _, _, _, modulus, server_exponent, nonce = self.lastRcvdMsg.split(" ")
            self.modulus = int(modulus)
            self.serverExponent = int(server_exponent)

            # Send the session key message to the server
            session_key_message = self.sessionKeyMsg(int(nonce))
            self.send(session_key_message)
            self.read()
            print(self.lastRcvdMsg)

            # Check for "104 Nonce Verified" or "400 Error" messages
            if "104 Nonce Verified" in self.lastRcvdMsg:
                print("Nonce Verified")

                # Simulate user input for two prime numbers
                prime_a = int(input("Enter the first prime number: "))
                prime_b = int(input("Enter the second prime number: "))

                # Encrypt the prime numbers using simplified AES
                encrypted_prime_a = self.AESencrypt(prime_a)
                encrypted_prime_b = self.AESencrypt(prime_b)

                # Send "108 PrimesEncrypted..." message to the server
                primes_encrypted_message = (
                    f"108 PrimesEncrypted {encrypted_prime_a} {encrypted_prime_b}"
                )
                self.send(primes_encrypted_message)
                self.read()
                print(self.lastRcvdMsg)
                self.primesEncryptedResponse(self.lastRcvdMsg, prime_a, prime_b)

            elif "400 Error" in self.lastRcvdMsg:
                print("Error: Nonce Verification Failed. Closing connection.")
                self.close()
        self.close()


def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 3:
        print("Please supply a server address and port.")
        sys.exit()
    print("Client of Shemar Marks")
    serverHost = str(args[1])  # The remote host
    serverPort = int(args[2])  # The same port as used by the server

    client = RSAClient(serverHost, serverPort)
    try:
        client.start()
    except (KeyboardInterrupt, SystemExit):
        exit()

if __name__ == "__main__":
    main()
