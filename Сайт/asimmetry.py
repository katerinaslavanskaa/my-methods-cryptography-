from math import gcd
import random
def __str__(self):
    return self.x, self.y

class DH_Endpoint(object):
    def __init__(self, public_key1, public_key2, private_key):
        self.public_key1 = public_key1
        self.public_key2 = public_key2
        self.private_key = private_key
        self.full_key = None

    def generate_partial_key(self):
        partial_key = self.public_key1**self.private_key
        partial_key = partial_key%self.public_key2
        return partial_key
    
    def generate_full_key(self, partial_key_r):
        full_key = partial_key_r ** self.private_key
        full_key = full_key % self.public_key2
        self.full_key = full_key
        return full_key
    
    def encrypt_message(self, message):
        encrypted_message = ""
        key = self.full_key
        for c in message:
            encrypted_message += chr(ord(c)+key)
        return encrypted_message
    
    def decrypt_message(self, encrypted_message):
        decrypted_message = ""
        key = self.full_key
        for c in encrypted_message:
            decrypted_message += chr(ord(c)-key)
        return decrypted_message

class RSA_Endpoint(object):
    def __init__(self, public_key1, public_key2, public_e):
        self.public_key1 = public_key1
        self.public_key2 = public_key2
        self.public_e = public_e
        self.private_key = None
        self.full_key = None
    
    def n_mod(self, public_key1, public_key2):
        return public_key1 * public_key2
    
    def function_Euler(self, public_key1, public_key2):
        return (public_key1 - 1) * (public_key2 - 1)
    
    def private_exponent(self, public_exponent, phi):
        return pow(public_exponent, -1, phi)
    
    def encrypt_message(self, message, public_exponent, modul_n):
        return pow(message, public_exponent, modul_n)
    
    def decrypt_message(self, message, private_exponent, modul_n):
        return pow(message, private_exponent, modul_n)
    
class LG_Endpoint(object):
    def gcd(a, b):
        if a < b:
            return gcd(b, a)
        elif a % b == 0:
            return b
        else:
            return gcd(b, a % b)
    
    # Generating large random numbers
    def gen_key(q):
        key = random.randint(1, q)
        while gcd(q, key) != 1:
            key = random.randint(1, q)
        return key
    
    # Modular exponentiation
    def power(a, b, c):
        x = 1
        y = a
        while b > 0:
            if b % 2 != 0:
                x = (x * y) % c
            y = (y * y) % c
            b = int(b / 2)
        return x % c
    
    # Asymmetric encryption
    def encrypt(msg, q, h, g):
        en_msg = []
        k = LG_Endpoint.gen_key(q)# Private key for sender
        s = LG_Endpoint.power(h, k, q)
        p = LG_Endpoint.power(g, k, q)
        for i in range(0, len(msg)):
            en_msg.append(msg[i])
        #print("g^k used : ", p)
        #print("g^ak used : ", s)
        for i in range(0, len(en_msg)):
            en_msg[i] = s * ord(en_msg[i])
        return en_msg, p

    def decrypt(en_msg, p, key, q):
        dr_msg = []
        h = LG_Endpoint.power(p, key, q)
        for i in range(0, len(en_msg)):
            dr_msg.append(chr(int(en_msg[i]/h)))
        return dr_msg

class ECDSA_Endpoint(object):
    def find_inverse(number, modulus):
        return pow(number, -1, modulus)
    
    def multiply(self, times):
            current_point = self
            current_coefficient = 1

            pervious_points = []
            while current_coefficient < times:
                # store current point as a previous point
                pervious_points.append((current_coefficient, current_point))
                # if we can multiply our current point by 2, do it
                if 2 * current_coefficient <= times:
                    current_point = current_point.add(current_point)
                    current_coefficient = 2 * current_coefficient
                # if we can't multiply our current point by 2, let's find the biggest previous point to add to our point
                else:
                    next_point = self
                    next_coefficient = 1
                    for (previous_coefficient, previous_point) in pervious_points:
                        if previous_coefficient + current_coefficient <= times:
                            if previous_point.x != current_point.x:
                                next_coefficient = previous_coefficient
                                next_point = previous_point
                    current_point = current_point.add(next_point)
                    current_coefficient = current_coefficient + next_coefficient

            return current_point
    
    
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from math import gcd
import random

def diffie_hellman(message="This is a very secret message!!!",
                    s_public=197,
                    s_private=199,
                    m_public=151,
                    m_private=157): 
    
    Sadat = DH_Endpoint(s_public, m_public, s_private)
    Michael = DH_Endpoint(s_public, m_public, m_private)
    s_partial = Sadat.generate_partial_key() #частичные ключи 147
    m_partial = Michael.generate_partial_key() #частичные ключи 66 
    s_full = Sadat.generate_full_key(m_partial)
    m_full = Michael.generate_full_key(s_partial)
    m_encrypted=Michael.encrypt_message(message)
    return m_encrypted #зашифрованное сообщение

def diffie_hellman_des(m_encrypted = "³´¾k´¾k¬kÁ°½Äk¾°®½°¿k¸°¾¾¬²°lll",
                    s_public=197,
                    s_private=199,
                    m_public=151,
                    m_private=157):
    Michael = DH_Endpoint(s_public, m_public, m_private)
    Sadat = DH_Endpoint(s_public, m_public, s_private)
    s_partial = Sadat.generate_partial_key() #частичные ключи 147
    m_partial = Michael.generate_partial_key() #частичные ключи 66 
    s_full = Sadat.generate_full_key(m_partial)
    message = Sadat.decrypt_message(m_encrypted)
    return message #дешифрованное сообщение

#print(diffie_hellman_des(diffie_hellman("Переведи нормально, пожалуйста!!")))

def RSA(message = 13,
        p_public = 3,
        q_public = 11,
        e_public = 7):
    Keys = RSA_Endpoint(p_public, q_public, e_public)
    n = Keys.n_mod(p_public, q_public)
    phi = Keys.function_Euler(p_public, q_public)
    while(e_public < phi):
        if (gcd(e_public, phi) == 1):
            break
        else:
            e_public += 1
    d = Keys.private_exponent(e_public, phi)
    encrypted = Keys.encrypt_message(message, e_public, n)
    return encrypted, d, n

def RSA_des(encrypted, d, n, 
    p_public = 3,
    q_public = 11,
    e_public = 7):
    Keys = RSA_Endpoint(p_public, q_public, e_public)
    message = Keys.decrypt_message(encrypted, d, n)
    return message

#encrypted, d, n = RSA()
#print(encrypted)
#print(RSA_des(encrypted, d, n))

def ElGamal(msg = 'hello',
    q = 13546135431235464415,
    g = random.randint(2, 13546135431235464415)):
    key = LG_Endpoint.gen_key(q)# Private key for receiver
    h = LG_Endpoint.power(g, key, q)
    en_msg, p = LG_Endpoint.encrypt(msg, q, h, g)
    return en_msg, p, key, q

#en_msg, p, key, q = ElGamal()
#print(en_msg)

def ElGamal_des(en_msg, p, key, q):
    dr_msg = LG_Endpoint.decrypt(en_msg, p, key, q)
    dmsg = ''.join(dr_msg)
    return dmsg

#print(ElGamal_des(en_msg, p, key, q))

def ECDSA(private_key = 1023456789012345,
          message = 12345):
    def find_inverse(number, modulus):
        return pow(number, -1, modulus)

    class Point:
        def __init__(self, x, y, curve_config):
            a = curve_config['a']
            b = curve_config['b']
            p = curve_config['p']

            if (y ** 2) % p != (x ** 3 + a * x + b) % p:
                raise Exception("The point is not on the curve")

            self.x = x
            self.y = y
            self.curve_config = curve_config

        def is_equal_to(self, point):
            return self.x == point.x and self.y == point.y

        def add(self, point):
            p = self.curve_config['p']

            if self.is_equal_to(point):
                slope = (3 * point.x ** 2) * find_inverse(2 * point.y, p) % p
            else:
                slope = (point.y - self.y) * find_inverse(point.x - self.x, p) % p

            x = (slope ** 2 - point.x - self.x) % p
            y = (slope * (self.x - x) - self.y) % p
            return Point(x, y, self.curve_config)

        def multiply(self, times):
            current_point = self
            current_coefficient = 1

            pervious_points = []
            while current_coefficient < times:
                # store current point as a previous point
                pervious_points.append((current_coefficient, current_point))
                # if we can multiply our current point by 2, do it
                if 2 * current_coefficient <= times:
                    current_point = current_point.add(current_point)
                    current_coefficient = 2 * current_coefficient
                # if we can't multiply our current point by 2, let's find the biggest previous point to add to our point
                else:
                    next_point = self
                    next_coefficient = 1
                    for (previous_coefficient, previous_point) in pervious_points:
                        if previous_coefficient + current_coefficient <= times:
                            if previous_point.x != current_point.x:
                                next_coefficient = previous_coefficient
                                next_point = previous_point
                    current_point = current_point.add(next_point)
                    current_coefficient = current_coefficient + next_coefficient

            return current_point

    secp256k1_curve_config = {
        'a': 0,
        'b': 7,
        'p': 115792089237316195423570985008687907853269984665640564039457584007908834671663
    }
    x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    g_point = Point(x, y, secp256k1_curve_config)

    def sign_message(message, private_key, k, k_inverse):
        r_point = g_point.multiply(k)
        r = r_point.x % n
        if r == 0:
            return sign_message(message, private_key)
        s = k_inverse * (message + r * private_key) % n
        return r, s

        # test starts here
    k = random.randint(1, n)
    k_inverse = find_inverse(k, n)
    public_key = g_point.multiply(private_key)
    public_key = __str__(public_key)
    signature = sign_message(message, private_key, k, k_inverse)
   
    return signature, k, k_inverse, private_key, n, public_key

def ECDSA_des(signature, k, k_inverse, private_key, n):
    r, s = signature
    def deschifr(r, s, k, k_inverse):
        message = ((s - k_inverse * r * private_key % n) * k % n) % n
        return message
    message = deschifr(r, s, k, k_inverse)
    return message
#ignature, k, k_inverse, private_key, n, public_key = ECDSA()
#print(ECDSA_des(signature, k, k_inverse, private_key, n))


def Points(message = (10, 9), a=1, b=6, key=7):
    p=11#случайное число
    r = 3
    def get_points(a, b, p): #Получить множество точек в конечном поле.
        # Вычислить все возможные координаты точек
        points = []
        for x in range(p):
            y_square = (x ** 3 + a * x + b) % p
            for y in range(p):
                if (y ** 2) % p == y_square:
                    points.append((x, y))
        return points

    def cal_k(point_A, point_B, p):#Вычислить угловой коэффициент k.
        if point_A == point_B:
            numerator = 3 * pow(point_A[0], 2) + a
            denominator = 2 * point_A[1]
            # Использовать малую теорему Ферма для вычисления дроби по модулю p
            return (numerator * pow(denominator, p - 2)) % p
        else:
            numerator = point_B[1] - point_A[1]
            denominator = point_B[0] - point_A[0]
            # Использовать малую теорему Ферма для вычисления дроби по модулю p
            return (numerator * pow(denominator, p - 2)) % p

    def cal_add(point_A, point_B, p, k):  # A+B=C, вычислить координаты точки C
        cx = (k ** 2 - point_A[0] - point_B[0]) % p
        cy = (k * (point_A[0] - cx) - point_A[1]) % p
        return cx, cy

    def cal_NA(key, point_A, point_B, p): # Выполнить key-1 итераций
        for i in range(key - 1):
            k = cal_k(point_A, point_B, p)
            point_B = cal_add(point_A, point_B, p, k)

        return point_B

    def encryption(r, Q, m, p):
        cx = cal_NA(r, A, B, p)
        rQ = cal_NA(r, Q, Q, p)
        k = cal_k(m, rQ, p)
        cy = cal_add(m, rQ, p, k)
        return cx, cy

    points = get_points(a, b, p)
    # A является базовой точкой, которая является точкой в множестве точек, B является другой точкой пересечения, изначально такой же, как A
    A = (a, b)
    B = (a, b)
    # Открытый ключ Q = kA
    Q = cal_NA(key, A, B, p)
    ciphertext = encryption(r, Q, message, p)
    return ciphertext

def Points_des(ciphertext, a=1, b=6, key=7):
    p=11#случайное число
    r = 3
    def get_points(a, b, p): #Получить множество точек в конечном поле.
        # Вычислить все возможные координаты точек
        points = []
        for x in range(p):
            y_square = (x ** 3 + a * x + b) % p
            for y in range(p):
                if (y ** 2) % p == y_square:
                    points.append((x, y))
        return points

    def cal_k(point_A, point_B, p):#Вычислить угловой коэффициент k.
        if point_A == point_B:
            numerator = 3 * pow(point_A[0], 2) + a
            denominator = 2 * point_A[1]
            # Использовать малую теорему Ферма для вычисления дроби по модулю p
            return (numerator * pow(denominator, p - 2)) % p
        else:
            numerator = point_B[1] - point_A[1]
            denominator = point_B[0] - point_A[0]
            # Использовать малую теорему Ферма для вычисления дроби по модулю p
            return (numerator * pow(denominator, p - 2)) % p

    def cal_add(point_A, point_B, p, k):  # A+B=C, вычислить координаты точки C
        cx = (k ** 2 - point_A[0] - point_B[0]) % p
        cy = (k * (point_A[0] - cx) - point_A[1]) % p
        return cx, cy

    def cal_NA(key, point_A, point_B, p): # Выполнить key-1 итераций
        for i in range(key - 1):
            k = cal_k(point_A, point_B, p)
            point_B = cal_add(point_A, point_B, p, k)

        return point_B

    def decryption(ciphertext, key, p):
        kc2 = cal_NA(key, ciphertext[0], ciphertext[0], p) # Вычитание является симметричной точкой относительно оси x
        kc2 = (kc2[0], -kc2[1])
        k = cal_k(ciphertext[1], kc2, p)
        result = cal_add(ciphertext[1], kc2, p, k)
        return result

    points = get_points(a, b, p)
    # A является базовой точкой, которая является точкой в множестве точек, B является другой точкой пересечения, изначально такой же, как A
    A = (a, b)
    B = (a, b)
    # Открытый ключ Q = kA
    Q = cal_NA(key, A, B, p)

    result = decryption(ciphertext, key, p)
    return result
'''ciphertext = Points()
print(ciphertext)
print(Points_des(ciphertext))'''