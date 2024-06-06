from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import os

def RSA_key(message="154584", n=2048):

    # Генерация ключей
    key = RSA.generate(n)
    public_key = key.publickey().exportKey()
    private_key = key.exportKey()

    # Подписание сообщения
    message = bytes(message, 'utf-8')
    hash_object = SHA256.new(message)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(hash_object)

    # Проверка подписи
    verifier = PKCS1_v1_5.new(RSA.importKey(public_key))
    try:
        if verifier.verify(hash_object, signature):
            podterdit = "Подпись подтверждена."
        else:
            podterdit = "Подпись недействительна."
    except (ValueError, TypeError):
        podterdit = "Подпись недействительна."

    return signature, podterdit

signature, podterdit = RSA_key("154584", 2048)
print(signature)