#!/usr/bin/env python3
import base64, time, io  # base64 للترميز/فكّه حتى نرجّع بيانات عبر JSON، time للقياس بالملّي، io نصنع ملف بالذاكرة (PEM) للتنزيل
from collections import defaultdict  # قاموس افتراضي حتى نسوّي rate limit بسيط حسب كل IP
from flask import Flask, render_template, request, jsonify, send_file  # Flask للسيرفر، نعرض index.html، نقرأ الطلب، نرجّع JSON، ونرسل ملف للتنزيل
from Crypto.PublicKey import RSA  # توليد وتحميل مفاتيح RSA
from Crypto.Cipher import PKCS1_OAEP  # تشفير/فك RSA باستخدام OAEP ويا SHA-256
from Crypto.Signature import pss  # توقيع والتحقق باستخدام RSA-PSS
from Crypto.Hash import SHA256  # خوارزمية الهاش اللي نستخدمها
from Crypto import Random  # مولّد عشوائي آمن (CSPRNG) حتى يولّد مفاتيح صحيحة

app = Flask(__name__) 

# ===== state =====
STATE = {"mode":"random","key_bits":3072,"key":None,"pub_pem":None,"pub_obj":None,"created_at":None}
RATE_BUCKET = defaultdict(list)  # نخزّن بكل IP قائمة أوقات طلباته حتى نتحكم بالمعدل

# ===== helpers =====
def rate_limit(ip, limit=40, window=60):
    now=time.time(); b=RATE_BUCKET[ip]
    # ننظّف الطوابع الأقدم من نافذة الزمن
    while b and now-b[0]>window: b.pop(0)
    # إذا تعدّى الحد نوقفه
    if len(b)>=limit: return False
    # غير هذا نسمح ونضيف الطابع الحالي
    b.append(now); return True

def init_random_keys(bits=3072):
    # نولّد زوج مفاتيح جديد بالحجم المطلوب
    key = RSA.generate(bits, randfunc=Random.new().read)
    pub = key.public_key()
    # نحدّث الحالة: الوضع تصير random، نخزّن الخاص والعام (PEM) وكائن العام
    STATE.update({"mode":"random","key_bits":bits,"key":key,"pub_pem":pub.export_key("PEM"),"pub_obj":pub,"created_at":time.time()})

def oaep_max(bits, h=32):  # الصيغة القياسية: mLen ≤ k - 2*hLen - 2  (k بايتات المفتاح، hLen طول الهاش)
    return bits//8 - 2*h - 2

def b64e(b): return base64.b64encode(b).decode()  # ترميز بايتات إلى Base64 (حتى نرسلها نص)
def b64d(s): return base64.b64decode(s.encode())  # نفك Base64 ونرجّع بايتات
def pub():   return STATE["pub_obj"] or RSA.import_key(STATE["pub_pem"])  # نجيب كائن المفتاح العام الجاهز، وإذا ماكو نحمّله من PEM

# ===== hooks =====
@app.before_request
def _prep():
    # أوّل زيارة أو إذا ماكو مفاتيح بالراندوم: نولّد 3072 افتراضي
    if STATE["pub_pem"] is None or (STATE["mode"]=="random" and STATE["key"] is None):
        init_random_keys(3072)
    # rate limit حسب IP: إذا طفر الحد نرجّع 429
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "local"
    if not rate_limit(ip): return jsonify({"error":"Too many requests. Please slow down."}),429

@app.after_request
def _csp(resp):
    # هيدرز أمان: CSP مشدّد (كلّه من نفس الأصل، بدون inline)، منع الإطارات/الأوبجكتات، وهيدرز حماية إضافية
    resp.headers["Content-Security-Policy"]=(
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Frame-Options"]="DENY"
    resp.headers["Referrer-Policy"]="no-referrer"
    resp.headers["X-Content-Type-Options"]="nosniff"
    return resp

# ===== pages =====
@app.get("/")
def index():
    # نرندر الصفحة الرئيسية ونبعتلها بيانات الحالة حتى تنعرض فوق
    return render_template("index.html",
        key_bits=STATE["key_bits"],
        pubkey_pem=STATE["pub_pem"].decode(),
        max_payload=oaep_max(STATE["key_bits"])
    )

# ===== status & mode =====
@app.get("/status")
def status():
    # API ترجع حالة السيستم للواجهة: الوضع، حجم المفتاح، حد OAEP، ويّة إذا متوفر خاص/عام
    return jsonify({
        "mode":STATE["mode"], "bits":STATE["key_bits"],
        "max_payload":oaep_max(STATE["key_bits"]),
        "has_private":STATE["key"] is not None,
        "has_public":STATE["pub_pem"] is not None
    })

@app.post("/regen")
def regen():
    # إعادة توليد مفاتيح بس بوضع Random (حتى ما نكسر مفاتيح مستوردة)
    if STATE["mode"]!="random":
        return jsonify({"error":"Regenerate is available only in Random Keys mode."}),400
    data=request.get_json(silent=True) or {}
    bits=int(data.get("bits",3072))
    if bits not in (2048,3072,4096):
        return jsonify({"error":"Key size must be one of 2048, 3072, 4096."}),400
    init_random_keys(bits)
    return jsonify({"ok":True,"bits":bits,"pubkey_pem":STATE["pub_pem"].decode(),"max_payload":oaep_max(bits)})

@app.post("/apply_keys")
def apply_keys():
    # استيراد مفاتيح: لازم Public PEM، والـ Private اختياري (وإذا موجود لازم يطابق العام بنفس n)
    d=request.get_json(silent=True) or {}
    pub_pem=(d.get("public_pem") or "").strip()
    priv_pem=(d.get("private_pem") or "").strip()
    if not pub_pem: return jsonify({"error":"Public key (PEM) is required."}),400
    try:
        pub_obj=RSA.import_key(pub_pem); pub_n=pub_obj.n
    except Exception:
        return jsonify({"error":"Invalid PUBLIC key PEM."}),400
    key=None
    if priv_pem:
        try:
            priv_obj=RSA.import_key(priv_pem)
            if not priv_obj.has_private(): return jsonify({"error":"Provided private PEM is not a private key."}),400
            if priv_obj.n!=pub_n:          return jsonify({"error":"Public and private keys do not match."}),400
            key=priv_obj
        except Exception:
            return jsonify({"error":"Invalid PRIVATE key PEM."}),400
    # إذا الأمور تمام: نحط الوضع imported ونحدّث حالة المفاتيح ونخمّن key_bits للعرض لأقرب 2048/3072/4096
    STATE.update({"mode":"imported","key":key,"pub_pem":pub_obj.export_key("PEM"),"pub_obj":pub_obj})
    bits=pub_obj.size_in_bits(); nearest=2048 if bits<3072 else (3072 if bits<4096 else 4096)
    STATE["key_bits"]=nearest
    return jsonify({"ok":True,"mode":STATE["mode"],"has_private":STATE["key"] is not None,
                    "bits":STATE["key_bits"],"pubkey_pem":STATE["pub_pem"].decode(),
                    "max_payload":oaep_max(STATE["key_bits"])})

@app.post("/use_random_mode")
def use_random_mode():
    # نرجع لوضع المفاتيح العشوائية ونولّد بالحجم المطلوب
    d=request.get_json(silent=True) or {}
    bits=int(d.get("bits",STATE["key_bits"] or 3072))
    if bits not in (2048,3072,4096): bits=3072
    init_random_keys(bits)
    return jsonify({"ok":True,"mode":STATE["mode"],"has_private":True,"bits":STATE["key_bits"],
                    "pubkey_pem":STATE["pub_pem"].decode(),"max_payload":oaep_max(STATE["key_bits"])})

@app.get("/pubkey")
def pubkey():
    # ننزّل المفتاح العام فقط كملف .pem (آمن للمشاركة)
    return send_file(io.BytesIO(STATE["pub_pem"]), mimetype="application/x-pem-file",
                     as_attachment=True, download_name=f"rsa_pub_{STATE['key_bits']}.pem")

# ===== crypto ops =====
@app.post("/encrypt")
def encrypt():
    # تشفير رسالة قصيرة بـ RSA-OAEP (بالمفتاح العام) + قياس وقت
    d=request.get_json() or {}; msg=d.get("message","")
    if not isinstance(msg,str) or not msg: return jsonify({"error":"Message is required."}),400
    raw=msg.encode(); maxlen=oaep_max(STATE["key_bits"])
    if len(raw)>maxlen: return jsonify({"error":f"Message too long for RSA-OAEP. Max {maxlen} bytes for {STATE['key_bits']}-bit key."}),400
    c=PKCS1_OAEP.new(pub(),hashAlgo=SHA256)
    t0=time.perf_counter(); ct=c.encrypt(raw); t1=time.perf_counter()
    return jsonify({"ciphertext_b64":b64e(ct),"elapsed_ms":round((t1-t0)*1000,2)})

@app.post("/decrypt")
def decrypt():
    # فك التشفير يحتاج مفتاح خاص؛ إذا مو موجود (public-only) نرفض
    if STATE["key"] is None: return jsonify({"error":"Private key not available (imported public-only)."}),400
    d=request.get_json() or {}; ct_b64=d.get("ciphertext_b64","")
    try: ct=b64d(ct_b64)
    except Exception: return jsonify({"error":"Invalid base64 ciphertext."}),400
    try:
        c=PKCS1_OAEP.new(STATE["key"],hashAlgo=SHA256)
        t0=time.perf_counter(); pt=c.decrypt(ct); t1=time.perf_counter()
        return jsonify({"message":pt.decode("utf-8","strict"),"elapsed_ms":round((t1-t0)*1000,2)})
    except Exception:
        return jsonify({"error":"Decryption failed. Check ciphertext/key."}),400

@app.post("/sign")
def sign():
    # توقيع الرسالة بـ RSA-PSS (لازم خاص) + قياس وقت
    if STATE["key"] is None: return jsonify({"error":"Private key not available (imported public-only)."}),400
    d=request.get_json() or {}; msg=d.get("message","")
    if not isinstance(msg,str) or not msg: return jsonify({"error":"Message is required."}),400
    h=SHA256.new(msg.encode()); s=pss.new(STATE["key"])
    t0=time.perf_counter(); sig=s.sign(h); t1=time.perf_counter()
    return jsonify({"signature_b64":b64e(sig),"elapsed_ms":round((t1-t0)*1000,2)})

@app.post("/verify")
def verify():
    # تحقق من التوقيع بـ RSA-PSS (بالمفتاح العام) + قياس وقت
    d=request.get_json() or {}; msg=d.get("message",""); sig_b64=d.get("signature_b64","")
    try: sig=b64d(sig_b64)
    except Exception: return jsonify({"error":"Invalid base64 signature."}),400
    h=SHA256.new(msg.encode()); v=pss.new(pub())
    t0=time.perf_counter()
    try: v.verify(h,sig); ok=True
    except (ValueError,TypeError): ok=False
    t1=time.perf_counter()
    return jsonify({"valid":ok,"elapsed_ms":round((t1-t0)*1000,2)})

# ===== lab (one-click) =====
@app.post("/lab_run")
def lab_run():
    # نمشي الخطوات كلّها بنقرة وحدة: Encrypt -> (Decrypt?) -> (Sign?) -> Verify
    d=request.get_json() or {}; msg=d.get("message","")
    if not isinstance(msg,str) or not msg: return jsonify({"error":"Message is required."}),400
    raw=msg.encode(); maxlen=oaep_max(STATE["key_bits"])
    if len(raw)>maxlen: return jsonify({"error":f"Message too long for RSA-OAEP. Max {maxlen} bytes."}),400
    # encrypt
    enc=PKCS1_OAEP.new(pub(),hashAlgo=SHA256); t0=time.perf_counter(); ct=enc.encrypt(raw); t1=time.perf_counter()
    out={"ciphertext_b64":b64e(ct),"encrypt_ms":round((t1-t0)*1000,2)}
    # decrypt?
    if STATE["key"] is not None:
        dec=PKCS1_OAEP.new(STATE["key"],hashAlgo=SHA256); t2=time.perf_counter(); pt=dec.decrypt(ct); t3=time.perf_counter()
        out.update({"decrypted":pt.decode("utf-8","strict"),"decrypt_ms":round((t3-t2)*1000,2)})
    else: out.update({"decrypted":None,"decrypt_ms":None})
    # sign?
    if STATE["key"] is not None:
        h=SHA256.new(raw); s=pss.new(STATE["key"]); t4=time.perf_counter(); sig=s.sign(h); t5=time.perf_counter()
        out.update({"signature_b64":b64e(sig),"sign_ms":round((t5-t4)*1000,2)})
    else: out.update({"signature_b64":None,"sign_ms":None})
    # verify?
    if out["signature_b64"] is not None:
        sig=base64.b64decode(out["signature_b64"]); h2=SHA256.new(raw); v=pss.new(pub()); t6=time.perf_counter()
        try: v.verify(h2,sig); ok=True
        except (ValueError,TypeError): ok=False
        t7=time.perf_counter(); out.update({"verify_valid":ok,"verify_ms":round((t7-t6)*1000,2)})
    else: out.update({"verify_valid":None,"verify_ms":None})
    return jsonify(out)

if __name__=="__main__":
    # بداية التشغيل: نولّد مفاتيح 3072 ونشتغل Flask بوضعيّة التطوير (ديباك)
    init_random_keys(3072); app.run(debug=True)
