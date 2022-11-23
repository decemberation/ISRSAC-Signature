import math
import random
import sys
import time
sys.setrecursionlimit(10000)
from decimal import Decimal

# pip install astartool
from pysmx.SM3 import hash_msg

# 70 số nguyên tố đầu tiên dùng cho hàm sinh số nguyên tố
first_70_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                   31, 37, 41, 43, 47, 53, 59, 61, 67,
                   71, 73, 79, 83, 89, 97, 101, 103,
                   107, 109, 113, 127, 131, 137, 139,
                   149, 151, 157, 163, 167, 173, 179,
                   181, 191, 193, 197, 199, 211, 223,
                   227, 229, 233, 239, 241, 251, 257,
                   263, 269, 271, 277, 281, 283, 293,
                   307, 311, 313, 317, 331, 337, 347, 349]

# Thuật toán Miller-Rabin dùng để kiểm tra số nguyên tố
# Dựa trên video: https://youtu.be/qdylJqXCDGs 

def millerRabin(p, iteration):
    if p < 2:
        return False
    if p != 2 and p % 2 == 0:
        return False

    s = p - 1
    k = 0

    while s % 2 == 0:
        s >>= 1
        k += 1

    for i in range(iteration):
        a = random.randrange(2, p - 1)
        b0 = pow(a, s, p)

        if b0 == 1 or b0 == p - 1:
            continue

        for j in range(k):
            b0 = pow(b0, 2, p)
            if b0 == p - 1:
                break
        else:
            return False
    return True

# Dùng ý tưởng việc sinh số nguyên tố được đề cập trong original paper của RSA (URL: http://people.csail.mit.edu/rivest/Rsapaper.pdf)

# Cụ thể như sau: sinh số lẻ ngẫu nhiên cho tới khi tìm được số nguyên tố. Bài báo cũng đề cập việc sử dụng thuật toán kiểm tra số nguyên tố mang tính xác suất (có khả năng xảy ra).
# Đơn cử là thuật toán Solovay-Strassen. Tuy nhiên, trong demo lần này sẽ sử dụng thuật toán có hiệu quả tương tự và được sử dụng rộng rãi hơn: thuật toán Miller-Rabin (Rabin-Miller)

def generateOddNumber(num: int):
    assert num > 1
    return random.randrange(2 ** (num - 1) + 1, 2 ** num, 2)


def getLowLevelPrime(num):
    while True:
        z = generateOddNumber(num)

        for divisor in first_70_primes:
            if z % divisor == 0 and divisor**2 <= z:
                break
        else:
            return z

def generateRandomPrime(bits):
  while True:
      num = getLowLevelPrime(bits)
      if millerRabin(num, 40):
          return num

# Tham khảo: https://cp-algorithms.com/algebra/extended-euclid-algorithm.html#implementation
# Dùng để tìm d sao cho e * d đồng dư 1 mod (phi(n)) trong thuật toán RSA (URL: http://people.csail.mit.edu/rivest/Rsapaper.pdf)
def extendedEuclidean(a, b):
    if a == 0:
        return b, 0, 1

    d, x1, y1 = extendedEuclidean(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return d, x, y

def multiplicativeInverse(a, b):
    d, x, y = extendedEuclidean(a, b)
    assert d == 1

    if x < 0:
        x += b
    return x

# Hàm sinh khóa
# Chi tiết xem tại mục II và III.1 của bài báo tham khảo

def keyGeneration(key_len):
    st = time.time()
    # Sinh ngẫu nhiên số nguyên tố p và q sao cho p khác q, p > 3 và q > 3
    p = generateRandomPrime(key_len // 2)
    q = p
    while q == p:
        q = generateRandomPrime(key_len // 2)
    assert p > 3
    assert q > 3

    print('p = ', p)
    print('q = ', q)

    # Tính n
    n = p * q * (p - 1) * (q - 1)

    # Tính m
    m = p * q

    print('n = ', n)
    print('m = ', m)

    # Sinh giá trị r ngẫu nhiên sao cho p > 2^r < q
    if p > q:
        r = random.randint(0, int(math.log(q, 2) - 1))
    else:
        r = random.randint(0, int(math.log(p, 2) - 1))

    print('r = ', r)

    # Tính phi(n) theo công thức
    phi = int(((p - 1) * (q - 1) * Decimal(p - 2**r) * Decimal(q - 2**r)) / Decimal(2**r))
    print('phi = ', phi)

    # Sinh e ngẫu nhiên trong khoảng (1, phi(n)) sao cho UCLN(1, phi(n)) = 1
    e = random.randint(2, phi - 1)

    while math.gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # e * d đồng dư 1 mod phi(n)
    d = multiplicativeInverse(e, phi)
    print('e = ', e)
    print('d = ', d)

    et = time.time()
    exec_time = et - st;
    # print('Key generated in: ', exec_time*1000, 'ms')

    # Trả về khóa công khai và khóa bí mật
    return ((e, m), (d, n))

# Hàm sinh chữ ký

def generateSignature(private_key, plaintext):
    st = time.time()
    d, n = private_key

    signature = [pow(ord(char), d, n) for char in plaintext]
    et = time.time()
    exec_time = et - st
    # print('Signature generated in: ', exec_time*1000, 'ms')
    return signature

# Hàm xác minh chữ ký

def verifySignature(public_key, ciphertext):
    st = time.time()
    e, m = public_key

    verifier = [chr(pow(char, e, m)) for char in ciphertext]
    et = time.time()
    exec_time = et - st
    # print('Signature verified in: ', exec_time*1000, 'ms')
    return verifier

def main():
    key_size = 8
    keyPair = keyGeneration(key_size)
    public_key = keyPair[0]  # public_key (e, m) 
    private_key = keyPair[1] # private_key (d, n)

    # print('Public key: ', public_key)
    # print('Private key: ', private_key)

    # private_key = (413, 3233)
    # public_key = (17, 3233)

    # private_key = (3479, 143)
    # public_key = (5339, 17160)

    message = "hello"

    # Băm thông điệp M dùng hàm băm được đề nghị trong bài báo, hàm băm SM3
    msg = hash_msg(message)
    print('Hashed message: ', msg)

    # Tiến hành sinh chữ ký
    signature = generateSignature(private_key, msg)
    print("Signature: ", signature)
    
    # --------------------------------------------------------------------------
    # Chứng minh rằng H(M) = H(M)^(e * d) mod m

    # for c in msg:
    #   h_m = [chr(pow(ord(c), 3479 * 5339, 143)) for c in msg]
    
    # print("h(m): ", ''.join(h_m))
    # --------------------------------------------------------------------------

    # Xác minh chữ ký, nếu giải mã chữ ký bằng đúng digest thì chữ ký hợp lệ
    verifier = verifySignature(public_key, signature)
    checker = ''.join(verifier)
    print('Verifier: ', checker)
    
    if checker == msg:
      print('Valid signature!')
    else:
      print('Invalid signature!')

if __name__ == ('__main__'):
    main()