#!/usr/bin/env python3
"""
J’ai ajouté la fonction de chiffrement au script, je vous envoie la nouvelle version.
Il y a maintenant un paramètre supplémentaire "-d" pour chiffrer (comme initialement), et "-e" pour chiffrer,
auquel cas ça réécrit le fichier chiffré d’après le contenu du fichier déchiffré.

Exemple déchiffrement : ./decdb.py -d sakura.db sakura-dec.db
Exemple chiffrement (après avoir modifié sakura-dec.db) : ./decdb.py -e sakura.db sakura-dec.db

Déchiffrement : decdb.py -d sakura.db sakura-dec.db
-> comme actuellement mais avec -d
Chiffrement : decdb.py -e sakura.db sakura-dec.db
-> les infos de chiffrement sont lues depuis sakura.db, puis sakura.db est effacée,
puis elle est réécrite selon sakura-dec.db. C'est plus simple mais cela nécessite de faire
une sauvegarde de sakura.db si on ne veut pas perdre le fichier original.
"""

import ctypes
import struct
import base64

class OPTC:
  def __init__(self, key="JGcu2DjohFm84viZHe1Et5Qt", bisquselib="./BisquseDLL.dll"): 
    libc = ctypes.cdll.LoadLibrary(bisquselib)
    libc.CreateFromKey.argtypes = [ctypes.c_char_p]
    libc.CreateFromKey.restype = ctypes.c_void_p
    libc.Decrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
    libc.Decrypt.restype = ctypes.c_int
    libc.Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    libc.Encrypt.restype = ctypes.c_char_p
    libc.ReleaseBuffer.argtypes = [ctypes.c_char_p]
    libc.ReleaseInst.argtypes = [ctypes.c_void_p]

    self.bisquselib = libc
    self.keydata = libc.CreateFromKey(key.encode('utf-8'))

  def __del__(self):
    if hasattr(self, 'bisquselib'):
      self.bisquselib.ReleaseInst(self.keydata)

  def read_header(self, fh):
    magic, rest_of_header = struct.unpack('<4s12s', fh.read(16))
    assert(magic == b'IKMN')

  def read_map_tables(self, fh):
    tables_crypted, = struct.unpack('<512s', fh.read(512))
    tables_crypted_b64 = base64.b64encode(tables_crypted)
    tables = ctypes.pointer(ctypes.c_char())
    decrypted_len = self.bisquselib.Decrypt(self.keydata, tables_crypted_b64, ctypes.byref(tables))
    assert(decrypted_len == 512)

    enc_map = bytearray(256)
    dec_map = bytearray(256)
    enc_map[:] = tables[  0:256]
    dec_map[:] = tables[256:512]
    self.bisquselib.ReleaseBuffer(tables)
    return enc_map, dec_map

  def remap_block(self, the_map, original):
    mapped = bytearray(len(original))
    for i in range(len(original)):
      mapped[i] = the_map[original[i]]
    return mapped

  def dec_db(self, db_crypted, db_decrypted):
    with open(db_crypted, mode="rb") as fh_crypted:
      with open(db_decrypted, mode="wb") as fh_decrypted:
        self.read_header(fh_crypted)
        enc_map, dec_map = self.read_map_tables(fh_crypted)
        while True:
          coded = fh_crypted.read(8192)
          if coded == b'':
            break
          decoded = self.remap_block(dec_map, coded)
          fh_decrypted.write(decoded)

  def re_enc_db(self, db_crypted, db_decrypted):
    with open(db_crypted, mode="rb+") as fh_crypted:
      self.read_header(fh_crypted)
      enc_map, dec_map = self.read_map_tables(fh_crypted)
      with open(db_decrypted, mode="rb") as fh_decrypted:
        fh_crypted.truncate()
        while True:
          decoded = fh_decrypted.read(8192)
          if decoded == b'':
            break
          coded = self.remap_block(enc_map, decoded)
          fh_crypted.write(coded)
    

if __name__ == '__main__':
  def exit_with_help(me):
    print(f"Usage: {me} [-d|-e] <encrypted.db> <decrypted.db>\n")
    print( "-d  Decrypts <encrypted.db> into new file <decrypted.db>.")
    print( "-e  Re-encrypts <decrypted.db> into existing file <encrypted.db>.")
    print( "    Will first read <encrypted.db> and then overwrite it with new data.\n")
    print(f"Example: {me} -d sakura.db sakura-dec.db")
    sys.exit(1)

  import sys

  me = sys.argv[0]
  try:
    action, db_enc, db_dec = sys.argv[1:4]
  except ValueError:
    exit_with_help(me)

  if action == '-e':
    optc = OPTC()
    optc.re_enc_db(db_enc, db_dec)
    print(f"{db_dec} successfully re-encrypted into {db_enc}.")

  elif action == '-d':
    optc = OPTC()
    optc.dec_db(db_enc, db_dec)
    print(f"{db_enc} successfully decrypted into {db_dec}.")

  else:
    exit_with_help(me)
