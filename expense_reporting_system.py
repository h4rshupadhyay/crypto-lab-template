"""Procedural exam template: file handling, crypto, client/server workflows and menus.

Install: python3 -m pip install pycryptodome cryptography
Run:     python3 expense_reporting_system.py

Edit the settings below, then run the role menus.

Every key generator returns (PUBLIC, PRIVATE), in that order. All returned
objects except the raw session key are JSON-serializable. Store public keys and
private keys separately; give only the numeric public key to the server.

Educational implementations: raw RSA arithmetic, Rabin, Schnorr and ElGamal
are for the lab. A package signature must be verified BEFORE CBC decryption.
"""
import base64
import binascii
import copy
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from datetime import datetime, timezone
from math import gcd, lcm

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pss
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh


# ======================= EDIT THIS SECTION =======================
DATA_DIR = Path(__file__).with_name('exam_data')
CONFIG = {
    'symmetric': 'AES',          # AES / DES / 3DES
    'key_bits': 128,             # AES:128/192/256; DES:64; 3DES:128/192
    # DES's 64 stored bits include parity: 56 effective key bits.
    # 3DES's 128/192 stored bits also include parity bits.
    'mode': 'CBC',               # ECB / CBC / CFB / OFB / CTR; AES also GCM
    'cfb_segment_bits': 8,       # CFB8 by default; e.g. 128 for AES-CFB128
    'key_wrap': 'rsa',           # rsa / elgamal / rabin / ecc / dh
    'signature': 'schnorr',      # rsa / elgamal / schnorr / ecdsa
    'hash': 'sha256',            # md5 / sha1 / sha256 / sha512 / djb2
    'signature_hash': 'sha256',  # Separate from the custom educational djb2 hash
    'homomorphic': 'paillier',   # paillier / rsa / elgamal
    'operation': 'sum',          # Paillier:sum/count/average/weighted_sum;
                                # RSA or ElGamal:product
    'rsa_bits': 2048,
    'paillier_bits': 2048,
    'rabin_bits': 2048,
    'group_bits': 2048,          # Fixed RFC 7919 public group; keep at 2048.
    'curve': 'P-256',            # Named curve for ECC key wrapping / ECDSA
}
SCENARIO = {
    'title': 'Secure Corporate Expense Reporting System',
    'subject_label': 'Employee ID', 'group_label': 'Department ID', 'value_label': 'Amount',
    'groups': {'1': 'Engineering', '2': 'Marketing', '3': 'Finance'},
    'choices': [],              # Voting: ['Alice', 'Bob']; encrypt a 0/1 vector.
    'one_per_subject': False,   # True for one vote per voter.
    'subject_is_user': True,    # False when an officer enters patient/customer IDs.
    'threshold': True,          # True: 2-of-3 Paillier; False: one release authority.
}
EMPLOYEES = ['employee1', 'employee2']  # Registered employee/officer signing keys.
TRUSTEES = ['trustee1', 'trustee2', 'trustee3']
# Available permissions:
# submit_record               - Create and submit an encrypted record.
# view_own_receipts           - View the selected account's submission receipts.
# verify_record               - Verify and accept pending submissions.
# search_records              - Search accepted records by group, subject or time.
# view_all_records            - View all submitted packages and their statuses.
# close_collection            - Stop submissions and freeze encrypted totals.
# view_encrypted_totals       - View totals without decrypting them.
# publish_totals              - Decrypt and publish totals after collection closes.
# generate_partial_decryption - Create a registered trustee's decryption share.
# Menus follow this dictionary: removing a role removes its main-menu entry.
# Removing an action hides its option and denies access to that operation.
PERMISSIONS = {
    'voter': {'submit_record', 'view_own_receipts'},
    'auditor': {'verify_record', 'search_records', 'view_all_records'},
    'coordinator': {'close_collection', 'view_encrypted_totals', 'publish_totals'},
    'trustee': {'generate_partial_decryption', 'view_encrypted_totals'},
}
# ================================================================


CIPHERS = {'AES': AES, 'DES': DES, '3DES': DES3}
HASHES = {'md5': MD5, 'sha1': SHA1, 'sha256': SHA256, 'sha512': SHA512}

# Public ffdhe2048 prime:
FFDHE2048_P = int(
    'FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1'
    'D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9'
    '7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561'
    '2433F51F5F066ED0856365553DED1AF3B557135E7F57C935'
    '984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735'
    '30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB'
    'B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19'
    '0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61'
    '9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73'
    '3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA'
    '886B423861285C97FFFFFFFFFFFFFFFF', 16)


def group_parameters(bits=2048):
    """Return the fixed public p, q, subgroup g and full-order g."""
    if type(bits) is not int or bits != 2048:
        raise ValueError('The fixed public group requires group_bits=2048')
    p = FFDHE2048_P
    g = 4  # Squaring 2 gives order q in this standard safe-prime group.
    # Negating g gives full order 2q (q is odd).
    return p, (p - 1) // 2, g, p - g


def validate_config(config=None):
    """Return a fresh configuration; unsupported options fail before key setup."""
    cfg = copy.deepcopy(CONFIG if config is None else config)
    choices = {
        'symmetric': CIPHERS,
        'mode': ('ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM'),
        'key_wrap': ('rsa', 'elgamal', 'rabin', 'ecc', 'dh'),
        'signature': ('rsa', 'elgamal', 'schnorr', 'ecdsa'),
        'hash': (*HASHES, 'djb2'),
        'signature_hash': HASHES,
        'homomorphic': ('paillier', 'rsa', 'elgamal'),
    }
    for field, allowed in choices.items():
        if cfg.get(field) not in allowed:
            raise ValueError(f'Unknown {field}: {cfg.get(field)}; choose {list(allowed)}')
    sizes = {'AES': (128, 192, 256), 'DES': (64,), '3DES': (128, 192)}
    if type(cfg.get('key_bits')) is not int or cfg['key_bits'] not in sizes[cfg['symmetric']]:
        raise ValueError('Wrong key_bits for ' + cfg['symmetric'])
    if cfg['mode'] == 'GCM' and cfg['symmetric'] != 'AES':
        raise ValueError('GCM is implemented only for AES')
    segment = cfg.get('cfb_segment_bits')
    block_bits = CIPHERS[cfg['symmetric']].block_size * 8
    if type(segment) is not int or not 8 <= segment <= block_bits or segment % 8:
        raise ValueError('cfb_segment_bits must be a multiple of 8 up to the block size')
    operations = ('sum', 'count', 'average', 'weighted_sum') if cfg['homomorphic'] == 'paillier' else ('product',)
    if cfg.get('operation') not in operations:
        raise ValueError(f'{cfg["homomorphic"]} supports these calculations: {operations}')
    if cfg['signature'] == 'ecdsa' and cfg['signature_hash'] not in ('sha256', 'sha512'):
        raise ValueError('ECDSA in this program uses SHA-256 or SHA-512')
    for field, minimum in [('rsa_bits', 1024), ('paillier_bits', 512), ('rabin_bits', 512)]:
        if type(cfg.get(field)) is not int or cfg[field] < minimum:
            raise ValueError(f'{field} must be an integer >= {minimum}')
    group_parameters(cfg.get('group_bits'))
    if cfg['key_wrap'] == 'rabin':
        # 01 prefix + key + 32-byte digest; leave room for every possible key.
        encoded_bits = 1 + 8 * (cfg['key_bits'] // 8 + 32)
        if cfg['rabin_bits'] <= encoded_bits:
            raise ValueError('Rabin modulus too small for session key + checksum; increase rabin_bits')
    if cfg['signature'] == 'rsa':
        digest_size = HASHES[cfg['signature_hash']].digest_size
        encoded_bytes = (cfg['rsa_bits'] - 1 + 7) // 8
        if encoded_bytes < 2 * digest_size + 2:
            raise ValueError('RSA-PSS key too small for digest-sized salt; increase rsa_bits')
    if cfg.get('curve') not in ('P-256', 'P-384', 'P-521'):
        raise ValueError('curve must be P-256, P-384 or P-521')
    return cfg


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def b64(raw):
    return base64.b64encode(raw).decode('ascii')


def un64(value):
    return base64.b64decode(value, validate=True)


def hash_data(raw, config=None):
    """Custom djb2 is for Lab 5 demonstration, not a cryptographic hash."""
    cfg = validate_config(config)
    if cfg['hash'] == 'djb2':
        value = 5381
        for byte in raw:
            value = (value * 33 + byte) & 0xffffffff
        return f'{value:08x}'
    return hashlib.new(cfg['hash'], raw).hexdigest()


def search_token(index_key, field, value):
    """Repeatable equality token. Same field/value/key gives the same token.

    This is a keyed inverted-index building block, not a complete public-key
    searchable-encryption protocol. It reveals equality and access patterns.
    """
    return hmac.new(index_key, canonical([field, value]), hashlib.sha256).hexdigest()


def _check_algorithm(obj, expected):
    if obj.get('algorithm') != expected:
        raise ValueError('Key/ciphertext algorithm does not match configuration')


def _integer(value, low, high):
    if type(value) is not int or not low <= value < high:
        raise ValueError(f'Expected integer in [{low}, {high})')
    return value


# ==================== SYMMETRIC RECORD ENCRYPTION ====================
def generate_session_key(config=None):
    cfg = validate_config(config)
    while True:
        key = secrets.token_bytes(cfg['key_bits'] // 8)
        if cfg['symmetric'] != '3DES':
            return key
        try:
            return DES3.adjust_key_parity(key)
        except ValueError:
            pass  # Retry if the key degenerates to single DES.


def _symmetric_cipher(key, cfg, box=None):
    module = CIPHERS[cfg['symmetric']]
    if len(key) != cfg['key_bits'] // 8:
        raise ValueError('Session key length does not match key_bits')
    mode = cfg['mode']
    options = {}
    if mode in ('CBC', 'CFB', 'OFB'):
        options['iv'] = un64(box['iv']) if box is not None else secrets.token_bytes(module.block_size)
    if mode == 'CFB':
        options['segment_size'] = cfg['cfb_segment_bits']
    if mode in ('CTR', 'GCM'):
        nonce_size = 12 if mode == 'GCM' else module.block_size // 2
        options['nonce'] = un64(box['nonce']) if box is not None else secrets.token_bytes(nonce_size)
    return module.new(key, getattr(module, 'MODE_' + mode), **options)


def encrypt_record(raw, key, config=None):
    """Only ECB/CBC need PKCS#7 padding. Every IV/nonce is fresh."""
    cfg = validate_config(config)
    cipher = _symmetric_cipher(key, cfg)
    box = {'algorithm': cfg['symmetric'], 'mode': cfg['mode'], 'key_bits': cfg['key_bits']}
    if cfg['mode'] in ('ECB', 'CBC'):
        raw = pad(raw, CIPHERS[cfg['symmetric']].block_size)
    if cfg['mode'] == 'GCM':
        ct, tag = cipher.encrypt_and_digest(raw)
        box['tag'] = b64(tag)
    else:
        ct = cipher.encrypt(raw)
    box['ct'] = b64(ct)
    if cfg['mode'] in ('CBC', 'CFB', 'OFB'):
        box['iv'] = b64(cipher.iv)
    if cfg['mode'] in ('CTR', 'GCM'):
        box['nonce'] = b64(cipher.nonce)
    if cfg['mode'] == 'CFB':
        box['segment_bits'] = cfg['cfb_segment_bits']
    return box


def decrypt_record(box, key, config=None):
    """Caller must verify the signed package first, especially for CBC."""
    cfg = validate_config(config)
    _check_algorithm(box, cfg['symmetric'])
    if box['mode'] != cfg['mode'] or box['key_bits'] != cfg['key_bits']:
        raise ValueError('Stored mode/key size does not match configuration')
    if cfg['mode'] == 'CFB' and box['segment_bits'] != cfg['cfb_segment_bits']:
        raise ValueError('CFB segment size does not match configuration')
    cipher = _symmetric_cipher(key, cfg, box)
    if cfg['mode'] == 'GCM':
        return cipher.decrypt_and_verify(un64(box['ct']), un64(box['tag']))
    raw = cipher.decrypt(un64(box['ct']))
    if cfg['mode'] in ('ECB', 'CBC'):
        raw = unpad(raw, CIPHERS[cfg['symmetric']].block_size)
    return raw


# ==================== ASYMMETRIC KEYS / SESSION-KEY WRAPPING ====================
def _rsa_keys(bits):
    key = RSA.generate(bits)
    return ({'algorithm': 'rsa', 'pem': key.publickey().export_key().decode()},
            {'algorithm': 'rsa', 'pem': key.export_key().decode()})


def _ecc_keys(algorithm, curve):
    key = ECC.generate(curve=curve)
    return ({'algorithm': algorithm, 'pem': key.public_key().export_key(format='PEM')},
            {'algorithm': algorithm, 'pem': key.export_key(format='PEM')})


def _discrete_log_keys(algorithm, bits):
    p, q, schnorr_g, elgamal_g = group_parameters(bits)
    order, g = (q, schnorr_g) if algorithm == 'schnorr' else (p - 1, elgamal_g)
    x = secrets.randbelow(order - 2) + 2
    public = {'algorithm': algorithm, 'p': p, 'g': g, 'y': pow(g, x, p)}
    return public, dict(public, x=x)


def _dh_keys(parameters=None, bits=2048):
    """Library-generated keys; reuse the public group or the recipient's group."""
    if parameters is None:
        p, _, g, _ = group_parameters(bits)
        parameters = dh.DHParameterNumbers(p, g).parameters()
    key = parameters.generate_private_key()
    return ({'algorithm': 'dh', 'pem': key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()},
            {'algorithm': 'dh', 'pem': key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()})


def _rabin_keys(bits):
    while True:
        p, q = getPrime(bits // 2), getPrime(bits - bits // 2)
        if p != q and p % 4 == q % 4 == 3 and (p * q).bit_length() == bits:
            return {'algorithm': 'rabin', 'n': p * q}, {'algorithm': 'rabin', 'n': p * q, 'p': p, 'q': q}


def generate_wrapping_keys(config=None):
    """ECC/DH use an ephemeral agreement + HKDF + AES-GCM key envelope.

    They are not direct encryption of bytes by a raw curve point or DH value.
    Rabin uses redundant encoding to select one of its four roots.
    """
    cfg = validate_config(config)
    algorithm = cfg['key_wrap']
    if algorithm == 'rsa':
        return _rsa_keys(cfg['rsa_bits'])
    if algorithm == 'rabin':
        return _rabin_keys(cfg['rabin_bits'])
    if algorithm == 'ecc':
        return _ecc_keys('ecc', cfg['curve'])
    if algorithm == 'dh':
        return _dh_keys(bits=cfg['group_bits'])
    return _discrete_log_keys(algorithm, cfg['group_bits'])


def _elgamal_encrypt(message, public):
    p, g, y = public['p'], public['g'], public['y']
    _integer(message, 1, p)
    _integer(y, 2, p - 1)
    k = secrets.randbelow(p - 3) + 2
    return {'c1': pow(g, k, p), 'c2': message * pow(y, k, p) % p}


def _elgamal_decrypt(box, private):
    p = private['p']
    c1, c2 = _integer(box['c1'], 1, p), _integer(box['c2'], 1, p)
    return c2 * pow(pow(c1, private['x'], p), -1, p) % p


def _agreement_key(algorithm, private, peer, salt):
    context = b'IS-LAB-key-wrap-v1:' + algorithm.encode()
    if algorithm == 'ecc':
        return key_agreement(static_priv=ECC.import_key(private['pem']),
                             static_pub=ECC.import_key(peer['pem']),
                             kdf=lambda secret: HKDF(secret, 32, salt, SHA256, context=context))
    private_key = serialization.load_pem_private_key(private['pem'].encode(), password=None)
    peer_key = serialization.load_pem_public_key(peer['pem'].encode())
    shared = private_key.exchange(peer_key)
    return HKDF(shared, 32, salt, SHA256, context=context)


def wrap_session_key(key, public, config=None):
    cfg = validate_config(config)
    algorithm = cfg['key_wrap']
    _check_algorithm(public, algorithm)
    if len(key) != cfg['key_bits'] // 8:
        raise ValueError('Wrong session key length')
    box = {'algorithm': algorithm}
    if algorithm == 'rsa':
        cipher = PKCS1_OAEP.new(RSA.import_key(public['pem']), hashAlgo=SHA256)
        return dict(box, ct=b64(cipher.encrypt(key)))
    if algorithm == 'elgamal':
        # Prefix 01 makes the entire byte string reversible, including zero keys.
        return dict(box, **_elgamal_encrypt(int.from_bytes(b'\x01' + key, 'big'), public))
    if algorithm == 'rabin':
        check = hashlib.sha256(b'RABIN-KEY-v1' + key).digest()
        message = int.from_bytes(b'\x01' + key + check, 'big')
        _integer(message, 1, public['n'])
        return dict(box, value=pow(message, 2, public['n']))
    if algorithm == 'dh':
        peer = serialization.load_pem_public_key(public['pem'].encode())
        ephemeral_public, ephemeral_private = _dh_keys(peer.parameters())
    else:
        ephemeral_public, ephemeral_private = generate_wrapping_keys(cfg)
    salt = secrets.token_bytes(16)
    wrapping_key = _agreement_key(algorithm, ephemeral_private, public, salt)
    cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=secrets.token_bytes(12))
    ct, tag = cipher.encrypt_and_digest(key)
    return dict(box, ephemeral=ephemeral_public, salt=b64(salt), nonce=b64(cipher.nonce),
                ct=b64(ct), tag=b64(tag))


def _rabin_unwrap(box, private, size):
    p, q, n = private['p'], private['q'], private['n']
    c = _integer(box['value'], 1, n)
    mp, mq = pow(c, (p + 1) // 4, p), pow(c, (q + 1) // 4, q)
    a, b = mp * q * pow(q, -1, p), mq * p * pow(p, -1, q)
    candidates = set()
    for root in {(a + b) % n, (-a - b) % n, (a - b) % n, (-a + b) % n}:
        if pow(root, 2, n) != c:
            continue
        raw = root.to_bytes((root.bit_length() + 7) // 8, 'big')
        if len(raw) != 1 + size + 32 or raw[:1] != b'\x01':
            continue
        key, check = raw[1:1 + size], raw[1 + size:]
        if hmac.compare_digest(check, hashlib.sha256(b'RABIN-KEY-v1' + key).digest()):
            candidates.add(key)
    if len(candidates) != 1:
        raise ValueError('Rabin key encoding invalid or ambiguous')
    return candidates.pop()


def unwrap_session_key(box, private, config=None):
    cfg = validate_config(config)
    algorithm, size = cfg['key_wrap'], cfg['key_bits'] // 8
    _check_algorithm(private, algorithm)
    _check_algorithm(box, algorithm)
    if algorithm == 'rsa':
        cipher = PKCS1_OAEP.new(RSA.import_key(private['pem']), hashAlgo=SHA256)
        key = cipher.decrypt(un64(box['ct']))
    elif algorithm == 'elgamal':
        message = _elgamal_decrypt(box, private)
        raw = message.to_bytes((message.bit_length() + 7) // 8, 'big')
        if len(raw) != size + 1 or raw[:1] != b'\x01':
            raise ValueError('Invalid ElGamal session-key encoding')
        key = raw[1:]
    elif algorithm == 'rabin':
        key = _rabin_unwrap(box, private, size)
    else:
        _check_algorithm(box['ephemeral'], algorithm)
        wrapping_key = _agreement_key(algorithm, private, box['ephemeral'], un64(box['salt']))
        cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=un64(box['nonce']))
        key = cipher.decrypt_and_verify(un64(box['ct']), un64(box['tag']))
    if len(key) != size:
        raise ValueError('Recovered session key has the wrong length')
    return key


# ==================== SIGNATURES ====================
def generate_signing_keys(config=None):
    cfg = validate_config(config)
    if cfg['signature'] == 'rsa':
        return _rsa_keys(cfg['rsa_bits'])
    if cfg['signature'] == 'ecdsa':
        return _ecc_keys('ecdsa', cfg['curve'])
    return _discrete_log_keys(cfg['signature'], cfg['group_bits'])


def _challenge(r, y, raw, name, q):
    message = canonical({'scheme': 'SCHNORR-EXAM-v1', 'r': r, 'y': y, 'message': b64(raw)})
    return int.from_bytes(hashlib.new(name, message).digest(), 'big') % q


def sign_data(raw, private, config=None):
    cfg = validate_config(config)
    algorithm, name = cfg['signature'], cfg['signature_hash']
    _check_algorithm(private, algorithm)
    signature = {'algorithm': algorithm}
    if algorithm == 'rsa':
        value = pss.new(RSA.import_key(private['pem'])).sign(HASHES[name].new(raw))
        return dict(signature, value=b64(value))
    if algorithm == 'ecdsa':
        value = DSS.new(ECC.import_key(private['pem']), 'fips-186-3').sign(HASHES[name].new(raw))
        return dict(signature, value=b64(value))
    p, g = private['p'], private['g']
    if algorithm == 'schnorr':
        q = (p - 1) // 2
        k = secrets.randbelow(q - 1) + 1
        r = pow(g, k, p)
        e = _challenge(r, private['y'], raw, name, q)
        return dict(signature, r=r, s=(k + e * private['x']) % q)
    while True:
        k = secrets.randbelow(p - 3) + 2
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    h = int.from_bytes(hashlib.new(name, raw).digest(), 'big')
    return dict(signature, r=r, s=(h - private['x'] * r) * pow(k, -1, p - 1) % (p - 1))


def verify_signature(raw, signature, public, config=None):
    cfg = validate_config(config)
    algorithm, name = cfg['signature'], cfg['signature_hash']
    try:
        _check_algorithm(public, algorithm)
        _check_algorithm(signature, algorithm)
        if algorithm == 'rsa':
            pss.new(RSA.import_key(public['pem'])).verify(HASHES[name].new(raw), un64(signature['value']))
            return True
        if algorithm == 'ecdsa':
            DSS.new(ECC.import_key(public['pem']), 'fips-186-3').verify(
                HASHES[name].new(raw), un64(signature['value']))
            return True
        p, g = public['p'], public['g']
        _integer(g, 2, p - 1)
        r, y = _integer(signature['r'], 1, p), _integer(public['y'], 2, p - 1)
        if algorithm == 'schnorr':
            q = (p - 1) // 2
            s = _integer(signature['s'], 0, q)
            if pow(g, q, p) != 1 or pow(r, q, p) != 1 or pow(y, q, p) != 1:
                return False
            e = _challenge(r, y, raw, name, q)
            return pow(g, s, p) == r * pow(y, e, p) % p
        s = _integer(signature['s'], 0, p - 1)
        h = int.from_bytes(hashlib.new(name, raw).digest(), 'big')
        return pow(g, h, p) == pow(y, r, p) * pow(r, s, p) % p
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, binascii.Error):
        return False


# ==================== ENCRYPTED ARITHMETIC ====================
def generate_numeric_keys(config=None):
    """Generate numeric keys for single-authority release."""
    cfg = validate_config(config)
    algorithm = cfg['homomorphic']
    if algorithm == 'elgamal':
        return _discrete_log_keys('elgamal', cfg['group_bits'])
    if algorithm == 'rsa':
        key = RSA.generate(cfg['rsa_bits'])
        return ({'algorithm': 'rsa', 'n': key.n, 'e': key.e},
                {'algorithm': 'rsa', 'n': key.n, 'd': key.d})
    bits = cfg['paillier_bits']
    while True:
        p, q = getPrime(bits // 2), getPrime(bits - bits // 2)
        n, lam = p * q, lcm(p - 1, q - 1)
        if p != q and gcd(n, lam) == 1 and n.bit_length() == bits:
            return ({'algorithm': 'paillier', 'n': n},
                    {'algorithm': 'paillier', 'n': n, 'lambda': lam, 'mu': pow(lam, -1, n)})


def encrypt_value(value, public, config=None):
    cfg = validate_config(config)
    algorithm = cfg['homomorphic']
    _check_algorithm(public, algorithm)
    if algorithm == 'elgamal':
        # Zero is excluded because multiplicative ElGamal operates on nonzero values.
        return dict(algorithm=algorithm, **_elgamal_encrypt(value, public))
    n = public['n']
    _integer(value, 0, n)
    if algorithm == 'rsa':
        return {'algorithm': algorithm, 'value': pow(value, public['e'], n)}
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            break
    return {'algorithm': algorithm, 'value': (1 + n * value) * pow(r, n, n * n) % (n * n)}


def _check_numeric_ciphertext(box, key, algorithm):
    _check_algorithm(box, algorithm)
    if algorithm == 'elgamal':
        _integer(box.get('c1'), 1, key['p'])
        _integer(box.get('c2'), 1, key['p'])
    else:
        n = key['n']
        _integer(box['value'], 0 if algorithm == 'rsa' else 1, n if algorithm == 'rsa' else n * n)
        if algorithm == 'paillier' and gcd(box['value'], n) != 1:
            raise ValueError('Invalid Paillier ciphertext')


def combine_values(ciphertexts, public, config=None):
    """Combine a fresh list once; caller chooses accepted records and grouping.

    Paillier: plaintext SUM mod n. RSA: plaintext PRODUCT mod n.
    ElGamal: plaintext PRODUCT mod p. No private key is used here.
    Counts are sums of 0/1. Averages divide a decrypted sum by its record count.
    """
    cfg = validate_config(config)
    algorithm = cfg['homomorphic']
    _check_algorithm(public, algorithm)
    if algorithm == 'elgamal':
        c1 = c2 = 1
        for box in ciphertexts:
            _check_numeric_ciphertext(box, public, algorithm)
            c1, c2 = c1 * box['c1'] % public['p'], c2 * box['c2'] % public['p']
        return {'algorithm': algorithm, 'c1': c1, 'c2': c2}
    modulus = public['n'] ** (2 if algorithm == 'paillier' else 1)
    total = 1
    for box in ciphertexts:
        _check_numeric_ciphertext(box, public, algorithm)
        total = total * box['value'] % modulus
    return {'algorithm': algorithm, 'value': total}


def scale_value(box, weight, public, config=None):
    """Paillier only: E(m)^w encrypts public-integer w times private m."""
    cfg = validate_config(config)
    if cfg['homomorphic'] != 'paillier':
        raise ValueError('Public-weight scaling is implemented for Paillier only')
    _check_algorithm(public, 'paillier')
    _check_numeric_ciphertext(box, public, 'paillier')
    _integer(weight, 0, public['n'])
    return {'algorithm': 'paillier', 'value': pow(box['value'], weight, public['n'] ** 2)}


def decrypt_value(box, private, config=None):
    """Low-level primitive. Application RBAC must restrict which totals reach it.

    This crypto layer alone does not enforce aggregate-only decryption.
    Keep plaintext sums/products below the modulus to avoid wraparound.
    """
    cfg = validate_config(config)
    algorithm = cfg['homomorphic']
    _check_algorithm(private, algorithm)
    _check_numeric_ciphertext(box, private, algorithm)
    if algorithm == 'elgamal':
        return _elgamal_decrypt(box, private)
    n, c = private['n'], box['value']
    if algorithm == 'rsa':
        return pow(c, private['d'], n)
    u = pow(c, private['lambda'], n * n)
    if (u - 1) % n:
        raise ValueError('Invalid Paillier decryption')
    return ((u - 1) // n) * private['mu'] % n


# ==================== 2-OF-3 PAILLIER (TRUSTED SETUP) ====================
def threshold_keys(bits):
    """DJN, s=1: distribute f(i); never save p, q, m or the full exponent d.

    https://people.csail.mit.edu/rivest/voting/papers/
    DamgardJurikNielsen-AGeneralizationOfPailliersPublicKeySystemWithApplicationsToElectronicVoting.pdf
    Lab assumption: trustees are honest; partials are signed, without ZK proofs.
    """
    def safe_prime(size):
        # OpenSSL-backed library generates a safe prime, not just any prime.
        return dh.generate_parameters(generator=2, key_size=size).parameter_numbers().p

    if bits < 1024 or bits % 2:
        raise ValueError('Threshold Paillier requires an even size >= 1024')
    while True:
        p, q = safe_prime(bits // 2), safe_prime(bits // 2)
        n, m = p * q, ((p - 1) // 2) * ((q - 1) // 2)
        if p != q and gcd(n, m) == 1 and n.bit_length() == bits:
            break
    d = m * pow(m, -1, n)  # d = 0 mod m; d = 1 mod n.
    a = secrets.randbelow(n * m)
    shares = [{'i': i, 'share': (d + a * i) % (n * m)} for i in (1, 2, 3)]
    return {'algorithm': 'paillier', 'n': n}, shares


def partial_decrypt(box, share, public):
    _check_numeric_ciphertext(box, public, 'paillier')
    return pow(box['value'], 12 * share['share'], public['n'] ** 2)  # 2 * 3!


def combine_partials(partials, public):
    """partials maps trustee number -> partial ciphertext, for any two trustees."""
    if len(partials) < 2 or not set(partials) <= {1, 2, 3}:
        raise ValueError('Need two distinct trustees from 1, 2, 3')
    i, j = sorted(partials)[:2]
    n = public['n']
    u = (pow(_integer(partials[i], 1, n * n), 2 * (6 * j // (j - i)), n * n) *
         pow(_integer(partials[j], 1, n * n), 2 * (6 * i // (i - j)), n * n)) % (n * n)
    if (u - 1) % n:
        raise ValueError('Invalid trustee partials')
    return ((u - 1) // n) * pow(144, -1, n) % n  # inverse of 4 * (3!)^2


# ==================== FILE HANDLING AND KEY SETUP ====================
public_keys = {}
state = {}
current_role = None
current_user = None
tsa_config = {}
collection_closed = False


def write_json(filename, data):
    filename = Path(filename)
    filename.parent.mkdir(parents=True, exist_ok=True)
    filename.write_text(json.dumps(data, indent=2))
    filename.chmod(0o600)


def read_json(filename):
    return json.loads(Path(filename).read_text())


def private_key(owner):
    return read_json(Path(DATA_DIR) / 'private' / (owner + '.json'))


def save_records():
    write_json(Path(DATA_DIR) / 'records.json', state)


def require_permission(action):
    if action not in PERMISSIONS.get(current_role, set()):
        raise PermissionError('Permission denied: ' + action)


def generate_keys():
    print('Generating keys for the first run.')
    wrap_public, wrap_private = generate_wrapping_keys()
    tsa_public, tsa_private = generate_signing_keys(tsa_config)
    if SCENARIO['threshold']:
        numeric_public, shares = threshold_keys(CONFIG['paillier_bits'])
    else:
        numeric_public, numeric_private = generate_numeric_keys()
        write_json(Path(DATA_DIR) / 'private/authority.json', numeric_private)
        shares = [{} for _ in TRUSTEES]
    keys = {'config': CONFIG, 'scenario': SCENARIO, 'wrapping': wrap_public,
            'numeric': numeric_public, 'tsa': tsa_public, 'users': {}}
    for user in EMPLOYEES + TRUSTEES:
        public, private = generate_signing_keys()
        keys['users'][user] = public
        if user in TRUSTEES:
            private.update(shares[TRUSTEES.index(user)])
        write_json(Path(DATA_DIR) / 'private' / (user + '.json'), private)
    index_key = b64(secrets.token_bytes(32))
    write_json(Path(DATA_DIR) / 'private/server.json', {'wrapping': wrap_private, 'index_key': index_key})
    write_json(Path(DATA_DIR) / 'private/auditor.json', {'index_key': index_key})
    write_json(Path(DATA_DIR) / 'private/tsa.json', tsa_private)
    write_json(Path(DATA_DIR) / 'public.json', keys)


def initialize():
    global public_keys, state, tsa_config, current_role, current_user
    global collection_closed
    validate_config()
    if SCENARIO['threshold'] and (CONFIG['homomorphic'] != 'paillier' or len(TRUSTEES) != 3):
        raise ValueError('Threshold mode needs Paillier and three trustees')
    if SCENARIO['choices'] and CONFIG['operation'] != 'count':
        raise ValueError('Voting choices need Paillier with operation=count')
    tsa_config = dict(CONFIG, signature='rsa', signature_hash='sha256')
    if not (Path(DATA_DIR) / 'public.json').exists():
        generate_keys()
    public_keys = read_json(Path(DATA_DIR) / 'public.json')
    if public_keys['config'] != CONFIG:
        raise ValueError('Saved keys use different crypto settings. Restore CONFIG or use a fresh DATA_DIR.')
    saved = public_keys['scenario']
    if saved['threshold'] != SCENARIO['threshold'] or saved['choices'] != SCENARIO['choices']:
        raise ValueError('Saved records use a different release mode or voting choices. Use a fresh DATA_DIR.')
    records_file = Path(DATA_DIR) / 'records.json'
    if not records_file.exists():
        write_json(records_file, {'packages': [], 'accepted': {}, 'index': {}, 'partials': {}})
    state = read_json(records_file)
    collection_closed = False
    current_role = None
    current_user = None


# ==================== CLIENT: CREATE, ENCRYPT, SIGN, SUBMIT ====================
def issue_timestamp(signed_package):
    # Simulated TSA has a separate private key. The employee cannot choose its clock.
    token = {'digest': hashlib.sha256(canonical(signed_package)).hexdigest(),
             'time': int(time.time())}
    return {'token': token, 'signature': sign_data(canonical(token), private_key('tsa'), tsa_config)}


def prepare_record(employee_id, group_id, value, subject_id=None, weight=1):
    require_permission('submit_record')
    if employee_id not in EMPLOYEES:
        raise ValueError('Unknown employee/officer account')
    if employee_id != current_user:
        raise PermissionError('Submit records only for the selected account')
    if collection_closed:
        raise ValueError('Collection is closed')
    subject_id = employee_id if subject_id is None else subject_id
    if not subject_id or group_id not in SCENARIO['groups']:
        raise ValueError('Enter a subject ID and a valid group ID')
    if SCENARIO['subject_is_user'] and subject_id != employee_id:
        raise ValueError('Subject ID must match the employee account')
    if SCENARIO['choices']:
        if value not in SCENARIO['choices']:
            raise ValueError('Unknown choice')
        values = {choice: int(choice == value) for choice in SCENARIO['choices']}
    else:
        if type(value) is not int or value <= 0:
            raise ValueError('Value must be a positive whole number')
        values = {'total': 1 if CONFIG['operation'] == 'count' else value}
    if type(weight) is not int or weight <= 0:
        raise ValueError('Weight must be a positive whole number')
    record = {'record_id': secrets.token_hex(12), 'subject_id': subject_id, 'group_id': group_id,
              'values': {label: encrypt_value(number, public_keys['numeric']) for label, number in values.items()},
              'weight': weight}
    raw = canonical(record)
    session_key = generate_session_key()
    core = {'record_id': record['record_id'], 'user': employee_id, 'hash': hash_data(raw),
            'record': encrypt_record(raw, session_key),
            'wrapped_key': wrap_session_key(session_key, public_keys['wrapping'])}
    signed = {'core': core, 'signature': sign_data(canonical(core), private_key(employee_id))}
    package = dict(signed, timestamp=issue_timestamp(signed))
    print('\nCLIENT CRYPTOGRAPHIC STEPS')
    print('Record:', raw.decode())
    print(CONFIG['hash'].upper() + ' hash (hex):', core['hash'])
    print(CONFIG['symmetric'] + ' session key (hex):', session_key.hex())
    for field in ('iv', 'nonce', 'tag'):
        if field in core['record']:
            print(field.upper() + ' (hex):', un64(core['record'][field]).hex())
    print('Encrypted record (base64):', core['record']['ct'])
    print('Encrypted session key:', json.dumps(core['wrapped_key']))
    print(CONFIG['signature'].upper() + ' signature (hex):', json.dumps(hex_output(signed['signature'])))
    print('Signed TSA timestamp:', json.dumps(hex_output(package['timestamp'])))
    return package


def submit_record(employee_id, group_id, value, subject_id=None, weight=1):
    package = prepare_record(employee_id, group_id, value, subject_id, weight)
    state['packages'].append({'package': package, 'status': 'pending'})
    save_records()
    return package


def view_own_receipts():
    require_permission('view_own_receipts')
    if current_user not in EMPLOYEES:
        raise PermissionError('Select a registered account first')
    return [{'record_id': item['package']['core']['record_id'], 'status': item['status'],
             'timestamp': item['package']['timestamp']}
            for item in state['packages'] if item['package']['core']['user'] == current_user]


def view_all_records():
    require_permission('view_all_records')
    return state['packages']


# ==================== SERVER: VERIFY AND ACCEPT ====================
def accept_record(package):
    require_permission('verify_record')
    core = package['core']
    employee_id = core['user']
    if employee_id not in EMPLOYEES or not verify_signature(canonical(core), package['signature'], public_keys['users'][employee_id]):
        raise ValueError('Invalid employee signature')
    print('\nSERVER VERIFICATION:', core['record_id'])
    print('Employee signature: VALID')
    stamp = package['timestamp']
    if not verify_signature(canonical(stamp['token']), stamp['signature'], public_keys['tsa'], tsa_config):
        raise ValueError('Invalid TSA signature')
    signed = {'core': core, 'signature': package['signature']}
    if stamp['token']['digest'] != hashlib.sha256(canonical(signed)).hexdigest():
        raise ValueError('Timestamp package mismatch')
    issued = stamp['token']['time']
    if type(issued) is not int or not 0 <= issued <= int(time.time()):
        raise ValueError('Invalid or future timestamp')
    print('TSA signature, package binding and timestamp: VALID')
    if core['record_id'] in state['accepted']:
        raise ValueError('Replay: duplicate transaction ID')
    if collection_closed:
        raise ValueError('Collection is closed')
    server_key = private_key('server')
    session_key = unwrap_session_key(core['wrapped_key'], server_key['wrapping'])
    print('Recovered ' + CONFIG['symmetric'] + ' session key (hex):', session_key.hex())
    raw = decrypt_record(core['record'], session_key)
    calculated_hash = hash_data(raw)
    print('Decrypted record:', raw.decode())
    print('Received hash (hex):', core['hash'])
    print('Recomputed ' + CONFIG['hash'].upper() + ' hash (hex):', calculated_hash)
    if not hmac.compare_digest(calculated_hash, core['hash']):
        raise ValueError('Record hash mismatch')
    print('Hash verification: MATCH')
    record = json.loads(raw)
    if record['record_id'] != core['record_id'] or not record['subject_id'] or record['group_id'] not in SCENARIO['groups']:
        raise ValueError('Invalid record identifiers')
    if SCENARIO['subject_is_user'] and record['subject_id'] != employee_id:
        raise ValueError('Subject ID does not match signer')
    if set(record['values']) != set(SCENARIO['choices'] or ['total']):
        raise ValueError('Invalid numeric fields')
    if type(record['weight']) is not int or record['weight'] <= 0:
        raise ValueError('Invalid public weight')
    for box in record['values'].values():
        _check_numeric_ciphertext(box, public_keys['numeric'], CONFIG['homomorphic'])
    index_key = un64(server_key['index_key'])
    tokens = {field: search_token(index_key, field, record[field + '_id']) for field in ('subject', 'group')}
    if SCENARIO['one_per_subject'] and tokens['subject'] in state['index']:
        raise ValueError('Subject already submitted')
    metadata = {'record_id': record['record_id'], 'subject_id': record['subject_id'],
                'group_id': record['group_id'], 'time': issued}
    cipher = AES.new(index_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(canonical(metadata))
    state['accepted'][record['record_id']] = {'group': tokens['group'], 'values': record['values'],
        'weight': record['weight'], 'metadata': {'ct': b64(ct), 'nonce': b64(cipher.nonce), 'tag': b64(tag)}}
    for token in tokens.values():
        state['index'].setdefault(token, []).append(record['record_id'])


def verify_pending(record_id=''):
    require_permission('verify_record')
    results = []
    for item in state['packages']:
        core = item['package'].get('core', {})
        if record_id and core.get('record_id') != record_id:
            continue
        if item['status'] != 'pending':
            continue
        try:
            accept_record(item['package'])
            item['status'] = 'ACCEPTED: signature, timestamp, hash and replay checks passed'
        except (ValueError, KeyError, TypeError, binascii.Error) as error:
            item['status'] = 'REJECTED: ' + str(error)
        results.append({'record_id': core.get('record_id'), 'result': item['status']})
    save_records()
    return results


# ==================== AUDITOR: KEYED ENCRYPTED SEARCH ====================
def search_records(field=None, value='', start=0, end=float('inf')):
    require_permission('search_records')
    if field not in (None, 'subject', 'group') or start > end:
        raise ValueError('Use subject/group and a valid time range')
    key = un64(private_key('auditor')['index_key'])
    record_ids = state['accepted'] if field is None else state['index'].get(search_token(key, field, value), [])
    found = []
    for record_id in record_ids:
        entry = state['accepted'][record_id]
        box = entry['metadata']
        cipher = AES.new(key, AES.MODE_GCM, nonce=un64(box['nonce']))
        metadata = json.loads(cipher.decrypt_and_verify(un64(box['ct']), un64(box['tag'])))
        if start <= metadata['time'] <= end:
            found.append(dict(metadata, encrypted_values=entry['values']))
    return found


# ==================== ENCRYPTED TOTALS AND COLLECTION CLOSURE ====================
def calculate_totals():
    index_key = un64(private_key('server')['index_key'])
    totals = {}
    for group in SCENARIO['groups']:
        token = search_token(index_key, 'group', group)
        records = [record for record in state['accepted'].values() if record['group'] == token]
        for label in SCENARIO['choices'] or ['total']:
            boxes = [record['values'][label] for record in records]
            if CONFIG['operation'] == 'weighted_sum':
                boxes = [scale_value(box, record['weight'], public_keys['numeric']) for box, record in zip(boxes, records)]
            totals[group + ':' + label] = {'ciphertext': combine_values(boxes, public_keys['numeric']), 'count': len(records)}
    return totals


def aggregate_records():
    require_permission('view_encrypted_totals')
    return calculate_totals()


def close_collection():
    global collection_closed
    require_permission('close_collection')
    if any(record['status'] == 'pending' for record in state['packages']):
        raise ValueError('Verify pending submissions first')
    if not collection_closed:
        state['frozen'] = calculate_totals()
        state['snapshot'] = hashlib.sha256(canonical(state['accepted'])).hexdigest()
        state['partials'] = {}
        state.pop('released', None)
        collection_closed = True
        save_records()
    return state['frozen']


# ==================== TRUSTEES: PARTIAL DECRYPTION AND RELEASE ====================
def frozen_digest():
    if not collection_closed:
        raise ValueError('Close collection before releasing totals')
    if state['snapshot'] != hashlib.sha256(canonical(state['accepted'])).hexdigest() or state['frozen'] != calculate_totals():
        raise ValueError('Closed records/totals changed')
    return hashlib.sha256(canonical([state['snapshot'], state['frozen']])).hexdigest()


def generate_partial(trustee):
    require_permission('generate_partial_decryption')
    if not SCENARIO['threshold'] or trustee not in TRUSTEES:
        raise ValueError('Select a registered trustee in threshold mode')
    digest, key = frozen_digest(), private_key(trustee)
    body = {'digest': digest, 'i': key['i'], 'user': trustee,
            'values': {label: partial_decrypt(total['ciphertext'], key, public_keys['numeric']) for label, total in state['frozen'].items()}}
    signed = {'body': body, 'signature': sign_data(canonical(body), key)}
    state['partials'][trustee] = signed
    save_records()
    return signed


def release_totals():
    require_permission('publish_totals')
    digest, partials = frozen_digest(), {}
    if SCENARIO['threshold']:
        for trustee, signed in state['partials'].items():
            body = signed['body']
            if trustee not in TRUSTEES or body['user'] != trustee or body['i'] != TRUSTEES.index(trustee) + 1 or body['digest'] != digest:
                raise ValueError('Invalid or stale trustee partial')
            if not verify_signature(canonical(body), signed['signature'], public_keys['users'][trustee]):
                raise ValueError('Invalid trustee signature')
            partials[body['i']] = body['values']
        if len(partials) < 2:
            raise ValueError('Need two distinct trustee partial decryptions')
    results = {}
    for label, total in state['frozen'].items():
        if SCENARIO['threshold']:
            value = combine_partials({i: values[label] for i, values in partials.items()}, public_keys['numeric'])
        else:
            value = decrypt_value(total['ciphertext'], private_key('authority'))
        if CONFIG['operation'] == 'average':
            value = value / total['count'] if total['count'] else None
        results[label] = value
    state['released'] = results
    save_records()
    return results


# ==================== PLAIN MENUS: EDIT THESE TO MATCH THE QUESTION ====================
def hex_output(value):
    """Format signatures for display without changing signed or saved records."""
    if isinstance(value, list):
        return [hex_output(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: hex_output(item) for key, item in value.items()}
    if value.get('algorithm') in ('rsa', 'ecdsa') and isinstance(value.get('value'), str):
        result['value'] = un64(value['value']).hex()
    elif value.get('algorithm') in ('schnorr', 'elgamal') and 'r' in value and 's' in value:
        result.update(r=format(value['r'], 'x'), s=format(value['s'], 'x'))
    return result


def show_result(result):
    print(json.dumps(hex_output(result), indent=2))


def role_menu():
    global current_user
    if {'submit_record', 'view_own_receipts'} & PERMISSIONS.get(current_role, set()):
        show_result(EMPLOYEES)
        current_user = input('Employee/officer account ID: ').strip()
        if current_user not in EMPLOYEES:
            raise ValueError('Unknown employee/officer account')
    options = [
        ('submit_record', 'Submit record'),
        ('view_own_receipts', 'View own receipts'),
        ('verify_record', 'Verify submissions'),
        ('search_records', 'Search records'),
        ('view_all_records', 'View all submissions'),
        ('close_collection', 'Close collection'),
        ('view_encrypted_totals', 'Encrypted totals'),
        ('publish_totals', 'Publish totals'),
        ('generate_partial_decryption', 'Generate partial decryption'),
    ]
    while True:
        available = [(action, label) for action, label in options
                     if action in PERMISSIONS.get(current_role, set())]
        print('\n' + current_role.upper() + ' MENU:')
        for number, (_, label) in enumerate(available, 1):
            print(number, label)
        print('0 Back')
        choice = input('Choice: ').strip()
        if choice == '0':
            return
        if choice not in {str(number) for number in range(1, len(available) + 1)}:
            print('Invalid choice.')
            continue
        action = available[int(choice) - 1][0]
        try:
            require_permission(action)
            if action == 'submit_record':
                subject = current_user if SCENARIO['subject_is_user'] else input(SCENARIO['subject_label'] + ': ').strip()
                show_result(SCENARIO['groups'])
                group = input(SCENARIO['group_label'] + ': ').strip()
                if SCENARIO['choices']:
                    show_result(SCENARIO['choices'])
                    value = input('Choice: ').strip()
                else:
                    value = int(input(SCENARIO['value_label'] + ': '))
                weight = int(input('Public weight: ')) if CONFIG['operation'] == 'weighted_sum' else 1
                package = submit_record(current_user, group, value, subject, weight)
                show_result(package)
                print('Submitted:', package['core']['record_id'], '| Awaiting verification.')
            elif action == 'view_own_receipts':
                show_result(view_own_receipts())
            elif action == 'verify_record':
                record_id = input('Transaction ID (blank = all pending): ').strip()
                results = verify_pending(record_id)
                show_result(results) if results else print('No pending submissions match this ID.')
            elif action == 'search_records':
                field = input('Search by (group / subject / time): ').strip()
                if field == 'time':
                    start = datetime.strptime(input('From (YYYY-MM-DD HH:MM UTC): '), '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc).timestamp()
                    end = datetime.strptime(input('To (YYYY-MM-DD HH:MM UTC): '), '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc).timestamp()
                    found = search_records(start=start, end=end)
                elif field in ('group', 'subject'):
                    found = search_records(field, input('ID: ').strip())
                else:
                    raise ValueError('Choose group, subject or time')
                show_result(found) if found else print('No matching records.')
            elif action == 'view_all_records':
                show_result(view_all_records())
            elif action == 'close_collection':
                close_collection()
                print('Collection closed. Encrypted totals frozen.')
            elif action == 'view_encrypted_totals':
                show_result(aggregate_records())
            elif action == 'publish_totals':
                show_result(release_totals())
            elif action == 'generate_partial_decryption':
                print('Trustees:', ', '.join(TRUSTEES))
                show_result(generate_partial(input('Trustee ID: ').strip()))
        except (ValueError, KeyError, TypeError, PermissionError) as error:
            print('REJECTED:', error)


def main():
    global current_role, current_user
    initialize()
    print(SCENARIO['title'])
    print('Collection:', 'CLOSED' if collection_closed else 'OPEN')
    while True:
        roles = list(PERMISSIONS)
        print('\nMAIN MENU:')
        for number, role in enumerate(roles, 1):
            print(number, role.title())
        print('0 Exit')
        choice = input('Choice: ').strip()
        if choice == '0':
            return
        if choice not in {str(number) for number in range(1, len(roles) + 1)}:
            print('Invalid choice.')
            continue
        current_role = roles[int(choice) - 1]
        try:
            role_menu()
        except (ValueError, PermissionError) as error:
            print('REJECTED:', error)
        finally:
            current_role = None
            current_user = None


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nExited.')
