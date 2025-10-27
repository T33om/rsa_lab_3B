// ===== helpers =====
// $ اختيار عنصر، post/get طلبات API، show/hide اظهار/اخفاء، setActive تفعيل تبويب
const $ = (s) => document.querySelector(s);
const post = async (u, d) =>
  (
    await fetch(u, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(d || {}),
    })
  ).json();
const get = async (u) => (await fetch(u)).json();
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");
const setActive = (btn, grp) => {
  grp.forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
};

// ===== status bar =====
// يحدّث وضع المفاتيح وحد OAEP ويعطّل/يفعّل أزرار الراندوم
async function refreshStatus() {
  const s = await get("/status");
  $("#mode").textContent = s.mode;
  $("#keybits").textContent = s.bits + " bits";
  $("#maxpayload").textContent = s.max_payload;
  $("#haspriv").textContent = s.has_private ? "yes" : "no";
  const inRandom = s.mode === "random";
  $("#bits").disabled = !inRandom;
  $("#btnRegen").disabled = !inRandom;
}66

// ===== key source tabs =====
// تبديل بين Random و Import
const tabRandom = $("#tabRandom"),
  tabImport = $("#tabImport");
const panelRandom = $("#panelRandom"),
  panelImport = $("#panelImport");
const groupKey = [tabRandom, tabImport];
tabRandom.onclick = () => {
  setActive(tabRandom, groupKey);
  show(panelRandom);
  hide(panelImport);
};
tabImport.onclick = () => {
  setActive(tabImport, groupKey);
  hide(panelRandom);
  show(panelImport);
};

// ===== random controls =====
// Regenerate + تنزيل العام
const pubpem = $("#pubpem code"),
  bits = $("#bits"),
  keybits = $("#keybits"),
  limit = $("#limit"),
  maxpayload = $("#maxpayload");
$("#btnRegen").onclick = async () => {
  const j = await post("/regen", { bits: parseInt(bits.value, 10) });
  if (j.ok) {
    pubpem.textContent = j.pubkey_pem;
    keybits.textContent = j.bits + " bits";
    limit.textContent = j.max_payload;
    maxpayload.textContent = j.max_payload;
    ["enc_time", "dec_time", "sign_time", "ver_time"].forEach((id) => {
      const e = $("#" + id);
      if (e) e.textContent = "– ms";
    });
    const vs = $("#ver_status");
    if (vs) {
      vs.textContent = "";
      vs.className = "muted";
    }
    await refreshStatus();
  } else alert(j.error || "Error");
};
$("#btnDownload").onclick = () => (window.location.href = "/pubkey");

// ===== import controls =====
// Apply للاستيراد، و BackRandom للرجوع للراندوم
$("#btnApply").onclick = async () => {
  const j = await post("/apply_keys", {
    public_pem: $("#pub_in").value.trim(),
    private_pem: $("#priv_in").value.trim(),
  });
  if (j.ok) {
    pubpem.textContent = j.pubkey_pem;
    keybits.textContent = j.bits + " bits";
    limit.textContent = j.max_payload;
    maxpayload.textContent = j.max_payload;
    await refreshStatus();
    alert("Imported keys applied.");
  } else alert(j.error || "Error");
};
$("#btnBackRandom").onclick = async () => {
  const j = await post("/use_random_mode", { bits: parseInt(bits.value, 10) });
  if (j.ok) {
    pubpem.textContent = j.pubkey_pem;
    keybits.textContent = j.bits + " bits";
    limit.textContent = j.max_payload;
    maxpayload.textContent = j.max_payload;
    await refreshStatus();
    setActive(tabRandom, groupKey);
    show(panelRandom);
    hide(panelImport);
  } else alert(j.error || "Error");
};

// ===== operation mode tabs =====
// Manual (أقسام منفصلة) vs Lab (نقرة وحدة)
const tabManual = $("#tabManual"),
  tabLab = $("#tabLab");
const panelManual = $("#panelManual"),
  panelLab = $("#panelLab");
const groupOp = [tabManual, tabLab];
tabManual.onclick = () => {
  setActive(tabManual, groupOp);
  show(panelManual);
  hide(panelLab);
};
tabLab.onclick = () => {
  setActive(tabLab, groupOp);
  hide(panelManual);
  show(panelLab);
};

// ===== manual ops =====
// Encrypt/Decrypt/Sign/Verify تستدعي API وتعرض النتيجة + ms
$("#btnEncrypt").onclick = async () => {
  const j = await post("/encrypt", { message: $("#enc_input").value });
  $("#enc_out").value = j.ciphertext_b64 || j.error || "";
  if (j.elapsed_ms !== undefined)
    $("#enc_time").textContent = j.elapsed_ms + " ms";
};
$("#btnDecrypt").onclick = async () => {
  const j = await post("/decrypt", {
    ciphertext_b64: $("#dec_input").value.trim(),
  });
  $("#dec_out").value = j.message || j.error || "";
  if (j.elapsed_ms !== undefined)
    $("#dec_time").textContent = j.elapsed_ms + " ms";
};
$("#btnSign").onclick = async () => {
  const j = await post("/sign", { message: $("#sign_input").value });
  $("#sign_out").value = j.signature_b64 || j.error || "";
  if (j.elapsed_ms !== undefined)
    $("#sign_time").textContent = j.elapsed_ms + " ms";
};
$("#btnVerify").onclick = async () => {
  const j = await post("/verify", {
    message: $("#ver_msg").value,
    signature_b64: $("#ver_sig").value.trim(),
  });
  const s = $("#ver_status");
  if (j.valid === true) {
    s.textContent = "✅ Signature is VALID (PSS/SHA-256)";
    s.className = "ok";
  } else if (j.valid === false) {
    s.textContent = "❌ Signature is INVALID";
    s.className = "err";
  } else {
    s.textContent = j.error || "Error";
    s.className = "err";
  }
  if (j.elapsed_ms !== undefined)
    $("#ver_time").textContent = j.elapsed_ms + " ms";
};

// ===== lab mode =====
// Run Demo: يشغّل الأربع خطوات ويرجع كل النتائج
$("#btnLabRun").onclick = async () => {
  const j = await post("/lab_run", { message: $("#lab_msg").value });
  if (j.error) {
    alert(j.error);
    return;
  }
  $("#lab_ct").value = j.ciphertext_b64 || "";
  $("#lab_enc_ms").textContent =
    j.encrypt_ms != null ? j.encrypt_ms + " ms" : "– ms";
  $("#lab_pt").value = j.decrypted != null ? j.decrypted : "";
  $("#lab_dec_ms").textContent =
    j.decrypt_ms != null ? j.decrypt_ms + " ms" : "– ms";
  $("#lab_sig").value = j.signature_b64 != null ? j.signature_b64 : "";
  $("#lab_sign_ms").textContent =
    j.sign_ms != null ? j.sign_ms + " ms" : "– ms";
  const v = $("#lab_verify");
  if (j.verify_valid == null) {
    v.textContent = "Verify: (skipped — no private key)";
    v.className = "muted";
  } else if (j.verify_valid === true) {
    v.textContent = "Verify: ✅ VALID";
    v.className = "ok";
  } else {
    v.textContent = "Verify: ❌ INVALID";
    v.className = "err";
  }
  $("#lab_ver_ms").textContent =
    j.verify_ms != null ? j.verify_ms + " ms" : "– ms";
};

// init: تهيئة أولية للتبويبات وشريط الحالة
refreshStatus();
setActive(tabRandom, [tabRandom, tabImport]);
show(panelRandom);
hide(panelImport);
setActive(tabManual, [tabManual, tabLab]);
show(panelManual);
hide(panelLab);
