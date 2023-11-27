# Server to implement the simplified RSA algorithm and receive encrypted
# integers from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.

# Author: Shemar Marks
# Last modified: 2023-11-14
# Version: 0.1.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES
import NumTheory


class RSAServer(object):
    def __init__(self, port, p, q):
        self.socket = socket.socket()
        # The option below is to permit reuse of a socket in less than an MSL
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", int(port)))
        self.socket.listen(5)
        self.lastRcvdMsg = None
        self.sessionKey = None  # For storing the symmetric key
        self.modulus = None  # For storing the server's n in the public/private key
        self.pubExponent = None  # For storing the server's e in the public key
        self.privExponent = None  # For storing the server's d in the private key
        self.nonce = None
        # Call the methods to compute the public private/key pairs
        self.modulus, self.privExponent, self.pubExponent = self.genKeys(p, q)

    def send(self, conn, message):
        conn.send(bytes(message, "utf-8"))

    def read(self):
        try:
            data = self.socket.recv(4096).decode("utf-8")
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Client is unavailable")

    def close(self, conn):
        print("closing server side of connection")
        try:
            conn.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f" {repr(e)}",
            )
        finally:
            # Delete reference to socket object
            conn = None

    def RSAencrypt(self, msg):
        # Encryption side of RSA
        # Ensure msg < modulus before encrypting
        if msg >= self.modulus:
            raise ValueError("Message should be less than modulus for RSA encryption.")
        return NumTheory.expMod(msg, self.pubExponent, self.modulus)

    def RSAdecrypt(self, cText):
        # Decryption side of RSA
        return NumTheory.NumTheory.expMod(cText, self.privExponent, self.modulus)

    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey)  # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext)  # Running simplified AES.
        return ciphertext

    def generateNonce(self):
        """This method returns a 16-bit random integer derived from hashing the
        current time. This is used to test for liveness"""
        hash = hashlib.sha1()
        hash.update(str(time.time()).encode("utf-8"))
        self.nonce = int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

    def findE(self, phi):
        # Method to randomly choose a good e given phi
        # For simplicity, just use 65537
        e = 65537
        while NumTheory.NumTheory.gcd_iter(e, phi) != 1:
            e += 2  # Increment by 2 to ensure e is odd
        return e

    def genKeys(self, p, q):
        # Generates n, phi(n), e, and d
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = self.findE(phi_n)
        d = NumTheory.NumTheory.ext_Euclid(phi_n, e)

        print("n:", n)
        print("phi(n):", phi_n)
        print("e:", e)
        print("d:", d)
        return n, d, e

    def clientHelloResp(self):
        """Generates response string to client's hello message"""
        self.generateNonce()
        status = (
            "102 Hello AES, RSA16 "
            + str(self.modulus)
            + " "
            + str(self.pubExponent)
            + " "
            + str(self.nonce)
        )
        return status

    def clientResponse(self, connSocket, response):
        # Send the response to the client
        self.send(connSocket, response)

    def nonceVerification(self, decryptedNonce):
        # Verifies that the transmitted nonce matches that received from the client
        if decryptedNonce == self.nonce:
            return True
        else:
            return False

    def primesEncrypted(self, enprime1, enprime2):
        # Decrypt prime numbers using AES
        prime1 = self.AESdecrypt(int(enprime1))
        prime2 = self.AESdecrypt(int(enprime2))

        # Compute the product (LCM) of the primes
        product = NumTheory.NumTheory.lcm(prime1, prime2)
        print(product)
        # Encrypt the product using AES
        encrypted_product = self.AESencrypt(product)

        # Send the "109 CompositeEncrypted" message to the client
        response = f"109 CompositeEncrypted {encrypted_product}"
        return response


    def start(self):
        # Main sending and receiving loop
        while True:
            connSocket, addr = self.socket.accept()
            msg = connSocket.recv(1024).decode("utf-8")
            print(msg)

            if "Hello" in msg:
                # Respond to client's hello message
                self.send(connSocket, self.clientHelloResp())

                # Simulate receiving session key message from client
                session_key_message = connSocket.recv(1024).decode("utf-8")
                (
                    _,
                    _,
                    encrypted_symmetric_key,
                    encrypted_nonce,
                ) = session_key_message.split()
                print(session_key_message)

                # Decrypt symmetric key using RSA
                decrypted_symmetric_key = self.RSAdecrypt(int(encrypted_symmetric_key))
                self.sessionKey = decrypted_symmetric_key

                # Decrypt nonce using AES
                decrypted_nonce = self.AESdecrypt(int(encrypted_nonce))

                # Verify nonce
                if self.nonceVerification(decrypted_nonce):
                    print("Nonce Verified")

                    response = "104 Nonce Verified"
                    self.clientResponse(connSocket, response)
                    # Receiving "108 PrimesEncrypted..." message from client
                    primes_encrypted_message = connSocket.recv(1024).decode("utf-8")
                    (
                        _,
                        _,
                        encrypted_prime1,
                        encrypted_prime2,
                    ) = primes_encrypted_message.split()

                    # Respond with "109 CompositeEncrypted..." message
                    response = self.primesEncrypted(encrypted_prime1, encrypted_prime2)
                    self.clientResponse(connSocket, response)

                    # Simulate receiving client's response
                    msg = connSocket.recv(1024).decode("utf-8")
                    print(msg)

                    # Close the connection
                    self.close(connSocket)
                    exit(1)
                else:
                    print("400 Error, Failed to Verify Nonce")
                    self.send(connSocket, "400 Error")


def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 2:
        print("Please supply a server port.")
        sys.exit()

    HOST = ""  # Symbolic name meaning all available interfaces
    PORT = int(args[1])  # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()
    print("Server of Shemar Marks")
    print(
        """Enter prime numbers. One should be between 211 and 281,
    and the other between 229 and 307. The product of your numbers should
    be less than 65536"""
    )
    p = int(input("Enter P: "))
    q = int(input("Enter Q: "))

    server = RSAServer(PORT, p, q)
    server.start()


if __name__ == "__main__":
    main()
