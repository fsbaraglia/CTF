#!/usr/bin/python3
'''
aes128-gcm_decrypt.py
Copyright (C) 2019 fsbaraglia

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
'''


from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from optparse import OptionParser
from termcolor import colored
import base64, binascii

### Constants
ALGORITHM_KEY_SIZE = 32
PBKDF2_SALT_SIZE = 128
PBKDF2_ITERATIONS = 1000

def decryptStr(base64Ciphertext, password):

    try:
        encrypted = base64.b64decode(base64Ciphertext, validate=True)
    except binascii.Error:
        encrypted = base64Ciphertext

    # Extract Variables for Decryption
    b_salt = encrypted[:AES.block_size]
    b_nonce = encrypted[AES.block_size:ALGORITHM_KEY_SIZE]
    b_associatedText = encrypted[:ALGORITHM_KEY_SIZE]
    b_ciphertext = encrypted[ALGORITHM_KEY_SIZE:]

    # Derive the key using PBKDF2.
    b_password = PBKDF2(password, b_salt, ALGORITHM_KEY_SIZE, PBKDF2_ITERATIONS)

    # Create the cipher.
    cipher = AES.new(b_password, mode=AES.MODE_GCM, nonce=b_nonce)

    # Decrypt
    plaintext = cipher.decrypt(b_ciphertext)[:AES.block_size]

    return plaintext

def main():
    parser = OptionParser(usage="usage: %prog [options] filename",
                          version="%prog 1.0")
    parser.add_option("-e", "--encPass",
                      action="store",
                      type="string",
                      dest="encrypted_b64",
                      help="encryptedPass in b64 format")
    parser.add_option("-m", "--magicStr",
                      action="store",
                      type="string",
                      dest="magicStr",
                      help="default")

    (options, args) = parser.parse_args()

    decryptedText = decryptStr(options.encrypted_b64, options.magicStr)

    if len(decryptedText) > 0:
        print(colored("FOUND", 'green'))
        print("decryptedText:" + str(decryptedText))
    else:
        print(colored("NOT FOUND", 'red'))

if __name__ == '__main__':
    main()

