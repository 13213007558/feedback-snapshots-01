# -*- coding: utf-8 -*-
"""
SRP 用户名 Unicode 规范化实验（基于本仓库 pysrp 纯 Python 后端）

三个必须区分的值：
  display  : 显示名（仅 UI，不进任何协议计算）
  lookup   : 目录查找键（用来定位 (salt, v) 记录）
  I_trans  : 进入密码学转录的身份（gen_x 的 x 与 calculate_M 的 M 里的 I）
"""
import unicodedata
import srp
import srp._pysrp as p

PASSWORD = 'correct horse battery staple'

def norm_key(u):
    """目录层身份键：NFC + casefold"""
    return unicodedata.normalize('NFC', u).casefold()

def register(username, password=PASSWORD):
    salt, vkey = srp.create_salted_verification_key(username, password)
    return {'salt': salt, 'vkey': vkey, 'reg_username': username}

def mutual_auth(record, client_username, password=PASSWORD,
                server_username=None, label=''):
    """完整双向认证：客户端证明 M，服务端回证 H_AMK。
    server_username=None 表示服务端把客户端发来的 I 原样放进 Verifier。"""
    usr = srp.User(client_username, password)
    uname, A = usr.start_authentication()
    # 服务端：用 uname 查目录得到记录；Verifier 里的 I 可选客户端版或存档版
    svr_I = uname if server_username is None else server_username
    svr = srp.Verifier(svr_I, record['salt'], record['vkey'], A)
    s, B = svr.get_challenge()
    M = usr.process_challenge(s, B)
    if M is None:
        print('  [%s] 客户端安全检查失败' % label); return False
    H_AMK = svr.verify_session(M)
    if H_AMK is None:
        print('  [%s] 服务端拒绝 M：认证失败' % label); return False
    usr.verify_session(H_AMK)
    ok = usr.authenticated() and svr.authenticated()
    same_key = usr.get_session_key() == svr.get_session_key()
    print('  [%s] 双向认证=%s, 会话密钥一致=%s' % (label, ok, same_key))
    return ok

def show_bytes(tag, u):
    b = u if isinstance(u, bytes) else u.encode('utf-8')
    print('  %-22s %r  utf8=%s' % (tag, u if isinstance(u, str) else u, b.hex()))

# ---------- 两组视觉相似、字节不同的用户名 ----------
CAFE_NFC  = 'café'          # é = U+00E9（预组合）
CAFE_NFD  = 'café'         # e + U+0301（组合字符）
ALICE_UP  = 'Alice'
ALICE_LO  = 'alice'

print('== 0. 三组身份键对比 ==')
show_bytes('NFC  café', CAFE_NFC)
show_bytes('NFD  café', CAFE_NFD)
print('  显示层肉眼相同; 目录键 norm_key 相同=%s; 字节相同=%s'
      % (norm_key(CAFE_NFC) == norm_key(CAFE_NFD), CAFE_NFC.encode() == CAFE_NFD.encode()))
show_bytes('大写 Alice', ALICE_UP)
show_bytes('小写 alice', ALICE_LO)
print('  目录键相同=%s; 字节相同=%s'
      % (norm_key(ALICE_UP) == norm_key(ALICE_LO), ALICE_UP.encode() == ALICE_LO.encode()))

print('\n== 1. 默认模式（I 进入 x 与 M）：跨字节形式认证 ==')
srp.no_username_in_x(False)
rec_cafe  = register(CAFE_NFC)
rec_alice = register(ALICE_UP)
mutual_auth(rec_cafe,  CAFE_NFC,  label='café NFC->NFC 基线')
mutual_auth(rec_cafe,  CAFE_NFD,  label='café NFD->NFC记录')
mutual_auth(rec_alice, ALICE_LO,  label='alice->Alice记录')

print('\n== 2. x 的派生对比（为什么失败）==')
x1 = p.gen_x(p._hash_map[srp.SHA1], rec_cafe['salt'], CAFE_NFC, PASSWORD)
x2 = p.gen_x(p._hash_map[srp.SHA1], rec_cafe['salt'], CAFE_NFD, PASSWORD)
print('  x(NFC) == x(NFD): %s  -> 盐相同但 I 不同，x 不同，v 对不上' % (x1 == x2))

print('\n== 3. no_username_in_x 模式：x 与 I 解耦 ==')
srp.no_username_in_x(True)
rec_cafe2  = register(CAFE_NFC)
rec_alice2 = register(ALICE_UP)
mutual_auth(rec_cafe2,  CAFE_NFC, label='café NFC->NFC 基线')
mutual_auth(rec_cafe2,  CAFE_NFD, label='café NFD->NFC记录 (x 不含 I，可过)')
mutual_auth(rec_alice2, ALICE_LO, label='alice->Alice记录 (x 不含 I，可过)')
x3 = p.gen_x(p._hash_map[srp.SHA1], rec_cafe2['salt'], CAFE_NFC, PASSWORD)
x4 = p.gen_x(p._hash_map[srp.SHA1], rec_cafe2['salt'], CAFE_NFD, PASSWORD)
print('  x(NFC) == x(NFD): %s  -> 验证器对字节形式不敏感' % (x3 == x4))

print('\n== 4. no_username_in_x 下 M 仍含 I：服务端用错 I 照样失败 ==')
mutual_auth(rec_cafe2, CAFE_NFD, server_username=rec_cafe2['reg_username'],
            label='服务端用存档I=NFC, 客户端=NFD')

print('\n== 5. 字节用户名（非 UTF-8）：SRP 可用，Unicode 规范化不适用 ==')
srp.no_username_in_x(False)
raw = b'user\xff\xfe'
rec_raw = register(raw)
mutual_auth(rec_raw, raw, label='bytes 用户名基线')
try:
    unicodedata.normalize('NFC', raw)
except TypeError as e:
    print('  unicodedata 拒绝 bytes: %s' % e)
try:
    raw.decode('utf-8')
except UnicodeDecodeError as e:
    print('  无法按 UTF-8 解码: %s -> 这类账号进不了规范化管线' % e)

print('\n== 6. 需要重新绑定的账号判定 ==')
for u in [CAFE_NFC, CAFE_NFD, ALICE_UP, ALICE_LO, 'plainascii']:
    need = unicodedata.normalize('NFC', u).encode('utf-8') != u.encode('utf-8')
    print('  %-12r 注册字节 != NFC 字节 -> 需重新绑定: %s' % (u, need))
