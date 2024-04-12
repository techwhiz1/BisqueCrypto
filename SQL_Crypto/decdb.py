#!/usr/bin/env python3
"""
Le script s’utilise en ligne de commande, le premier paramètre c’est le fichier chiffré à lire, 
le deuxième c’est le fichier déchiffré à écrire.
Il faut soit mettre BisquseDLL.dll dans le même dossier que le script, 
soit éditer le script pour modifier le chemin où est située la DLL.
"""
import ctypes
import struct
import base64


class OPTC:
    def __init__(self, key="JGcu2DjohFm84viZHe1Et5Qt", bisquselib="./BisquseDLL.dll"):
        libc = ctypes.cdll.LoadLibrary(bisquselib)
        libc.CreateFromKey.argtypes = [ctypes.c_char_p]
        libc.CreateFromKey.restype = ctypes.c_void_p
        libc.Decrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_char)),
        ]
        libc.Decrypt.restype = ctypes.c_int
        libc.Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
        libc.Encrypt.restype = ctypes.c_char_p
        libc.ReleaseBuffer.argtypes = [ctypes.c_char_p]
        libc.ReleaseInst.argtypes = [ctypes.c_void_p]

        self.bisquselib = libc
        self.keydata = libc.CreateFromKey(key.encode("utf-8"))

    def __del__(self):
        if hasattr(self, "bisquselib"):
            self.bisquselib.ReleaseInst(self.keydata)

    def read_header(self, fh):
        magic, rest_of_header = struct.unpack("<4s12s", fh.read(16))
        assert magic == b"IKMN"

    def read_dec_map(self, fh):
        (tables_crypted,) = struct.unpack("<512s", fh.read(512))
        tables_crypted_b64 = base64.b64encode(tables_crypted)
        tables = ctypes.pointer(ctypes.c_char())
        decrypted_len = self.bisquselib.Decrypt(
            self.keydata, tables_crypted_b64, ctypes.byref(tables)
        )
        assert decrypted_len == 512

        dec_map = bytearray(256)
        dec_map[:] = tables[256:512]
        self.bisquselib.ReleaseBuffer(tables)
        return dec_map

    def dec_block(self, dec_map, coded):
        decoded = bytearray(len(coded))
        for i in range(len(coded)):
            decoded[i] = dec_map[coded[i]]
        return decoded

    def dec_db(self, db_crypted, db_decrypted):
        with open(db_crypted, mode="rb") as fh_crypted:
            with open(db_decrypted, mode="wb") as fh_decrypted:
                self.read_header(fh_crypted)
                dec_map = self.read_dec_map(fh_crypted)
                while True:
                    coded = fh_crypted.read(8192)
                    if coded == b"":
                        break
                    decoded = self.dec_block(dec_map, coded)
                    fh_decrypted.write(decoded)


if __name__ == "__main__":
    import sys

    me = sys.argv[0]
    try:
        file_in, file_out = sys.argv[1:3]
    except ValueError:
        print(f"Usage: {me} <crypted.db> <decrypted.db>\n")
        print(f"Decrypts <crypted.db> into new file <decrypted.db>.\n")
        print(f"Example: {me} sakura.db sakura-dec.db")
        sys.exit(1)

    optc = OPTC()
    optc.dec_db(file_in, file_out)

    print(f"{file_in} successfully decrypted into {file_out}.")
