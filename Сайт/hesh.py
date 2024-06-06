import hashlib

def md5_hash(input_str):
    # Создание объекта хеш-функции MD5
    md5_obj = hashlib.md5()
    # Обновление хеш-объекта с входной строкой
    md5_obj.update(input_str.encode('utf-8'))
    # Получение хеш-значения
    hash_value = md5_obj.hexdigest()
    return hash_value

'''input_string = "Hello, World!"
md5_hash_value = md5_hash(input_string)
print("MD5 hash value:", md5_hash_value)'''



def blake2_hash(input_str, digest_size=32):
    blake2_obj = hashlib.blake2b(digest_size=digest_size)# Создание объекта хеш-функции Blake2
    blake2_obj.update(input_str.encode('utf-8'))# Обновление хеш-объекта с входной строкой
    hash_value = blake2_obj.hexdigest()# Получение хеш-значения
    return hash_value

'''# Пример использования
input_string = "Hello, World!"
blake2_hash_value = blake2_hash(input_string)
print("Blake2 hash value:", blake2_hash_value)'''


def crc32(input_str):
    crc = 0xFFFFFFFF
    for char in input_str:
        crc ^= ord(char)
        for _ in range(8):
            if crc & 1: crc = (crc >> 1) ^ 0xEDB88320
            else: crc = crc >> 1
    return crc ^ 0xFFFFFFFF


'''# Пример использования
input_string = "Hello, World!"
crc32_value = crc32(input_string)
print("CRC-32 value:", hex(crc32_value))
'''

def adler32(input_str):
    a = 1
    b = 0
    for char in input_str:
        a = (a + ord(char)) % 65521
        b = (b + a) % 65521
    return (b << 16) | a

'''# Пример использования
input_string = "Hello, World!"
adler32_value = adler32(input_string)
print("Adler-32 value:", hex(adler32_value))'''


def fnv1a_hash(input_str):
    hash_value = 0x811c9dc5  # Начальное значение хеша
    for char in input_str: # Побитовые операции для вычисления хеша
        hash_value ^= ord(char)
        hash_value *= 0x01000193
    return hash_value


'''# Пример использования
input_string = "Hello, World!"
fnv1a_hash_value = fnv1a_hash(input_string)
print("FNV-1a hash value:", hex(fnv1a_hash_value))'''




