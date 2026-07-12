(function () {
  "use strict";

  var state = {
    secret: "JBSWY3DPEHPK3PXP",
    issuer: "Google",
    account: "用户",
    digits: 6,
    period: 30,
    code: "",
    lastCounter: -1
  };

  function $(selector) { return document.querySelector(selector); }
  var dialog = $("#secretDialog");
  var secretInput = $("#secretInput");
  var fieldError = $("#fieldError");
  var toast = $("#toast");
  var toastTimer;

  function base32ToBytes(value) {
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var clean = String(value || "").toUpperCase().replace(/[\s=-]/g, "");
    if (!clean) throw new Error("请输入有效的 Base32 密钥");
    var bits = "";
    for (var i = 0; i < clean.length; i += 1) {
      var index = alphabet.indexOf(clean.charAt(i));
      if (index < 0) throw new Error("密钥包含无效字符");
      bits += index.toString(2).padStart(5, "0");
    }
    var bytes = [];
    for (var bit = 0; bit + 8 <= bits.length; bit += 8) bytes.push(parseInt(bits.slice(bit, bit + 8), 2));
    if (!bytes.length) throw new Error("密钥长度不足");
    return bytes;
  }

  function rotateLeft(value, shift) { return (value << shift) | (value >>> (32 - shift)); }

  function sha1(input) {
    var bytes = input.slice();
    var bitLength = bytes.length * 8;
    bytes.push(128);
    while ((bytes.length % 64) !== 56) bytes.push(0);
    var high = Math.floor(bitLength / 4294967296);
    var low = bitLength >>> 0;
    for (var h = 3; h >= 0; h -= 1) bytes.push((high >>> (h * 8)) & 255);
    for (var l = 3; l >= 0; l -= 1) bytes.push((low >>> (l * 8)) & 255);

    var h0 = 0x67452301;
    var h1 = 0xefcdab89;
    var h2 = 0x98badcfe;
    var h3 = 0x10325476;
    var h4 = 0xc3d2e1f0;
    var words = new Array(80);

    for (var offset = 0; offset < bytes.length; offset += 64) {
      for (var w = 0; w < 16; w += 1) {
        var p = offset + w * 4;
        words[w] = ((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) | 0;
      }
      for (var next = 16; next < 80; next += 1) words[next] = rotateLeft(words[next - 3] ^ words[next - 8] ^ words[next - 14] ^ words[next - 16], 1);

      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for (var round = 0; round < 80; round += 1) {
        var f, k;
        if (round < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999; }
        else if (round < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (round < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        var temp = (rotateLeft(a, 5) + f + e + k + words[round]) | 0;
        e = d; d = c; c = rotateLeft(b, 30); b = a; a = temp;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }

    var output = [];
    [h0, h1, h2, h3, h4].forEach(function (word) {
      output.push((word >>> 24) & 255, (word >>> 16) & 255, (word >>> 8) & 255, word & 255);
    });
    return output;
  }

  function hmacSha1(key, message) {
    var normalized = key.length > 64 ? sha1(key) : key.slice();
    while (normalized.length < 64) normalized.push(0);
    var inner = [], outer = [];
    for (var i = 0; i < 64; i += 1) {
      inner.push(normalized[i] ^ 0x36);
      outer.push(normalized[i] ^ 0x5c);
    }
    return sha1(outer.concat(sha1(inner.concat(message))));
  }

  function generateTotp(timestamp) {
    var counter = Math.floor(timestamp / 1000 / state.period);
    var high = Math.floor(counter / 4294967296);
    var low = counter >>> 0;
    var message = [];
    for (var h = 3; h >= 0; h -= 1) message.push((high >>> (h * 8)) & 255);
    for (var l = 3; l >= 0; l -= 1) message.push((low >>> (l * 8)) & 255);
    var digest = hmacSha1(base32ToBytes(state.secret), message);
    var offset = digest[digest.length - 1] & 15;
    var binary = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) >>> 0;
    return String(binary % Math.pow(10, state.digits)).padStart(state.digits, "0");
  }

  function parseInput(raw) {
    var value = String(raw || "").trim();
    if (!value) throw new Error("请输入密钥或设置链接");
    if (value.toLowerCase().indexOf("otpauth://") !== 0) {
      base32ToBytes(value);
      return { secret: value.toUpperCase().replace(/[\s=-]/g, ""), issuer: "Google", account: "个人账户", digits: 6, period: 30 };
    }
    var url;
    try { url = new URL(value); } catch (error) { throw new Error("设置链接格式不正确"); }
    if (url.hostname.toLowerCase() !== "totp") throw new Error("当前仅支持 TOTP 设置链接");
    var algorithm = String(url.searchParams.get("algorithm") || "SHA1").toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (algorithm !== "SHA1") throw new Error("当前版本仅支持常用的 SHA-1 验证码");
    var secret = url.searchParams.get("secret") || "";
    base32ToBytes(secret);
    var label = decodeURIComponent(url.pathname.replace(/^\//, ""));
    var parts = label.split(":");
    var issuer = url.searchParams.get("issuer") || (parts.length > 1 ? parts[0] : "Google");
    var account = parts.length > 1 ? parts.slice(1).join(":") : label || "个人账户";
    var digits = Number(url.searchParams.get("digits") || 6);
    var period = Number(url.searchParams.get("period") || 30);
    if ([6, 7, 8].indexOf(digits) < 0 || period < 5 || period > 300) throw new Error("验证码位数或刷新周期无效");
    return { secret: secret.toUpperCase().replace(/[\s=-]/g, ""), issuer: issuer, account: account, digits: digits, period: period };
  }

  function updateCode() {
    var now = Date.now();
    var epoch = Math.floor(now / 1000);
    var cycleMs = state.period * 1000;
    var remainingMs = cycleMs - (now % cycleMs);
    var remaining = Math.ceil(remainingMs / 1000);
    var counter = Math.floor(epoch / state.period);
    $("#secondsValue").textContent = String(remaining);
    $("#timerRing").style.setProperty("--progress", remainingMs / cycleMs);
    if (counter === state.lastCounter) return;
    try {
      state.code = generateTotp(now);
      state.lastCounter = counter;
      var midpoint = Math.ceil(state.code.length / 2);
      $("#codeLeft").textContent = state.code.slice(0, midpoint);
      $("#codeRight").textContent = state.code.slice(midpoint);
      $("#inlineError").hidden = true;
      $("#codeDisplay").classList.remove("is-refreshing");
      setTimeout(function () { $("#codeDisplay").classList.add("is-refreshing"); }, 0);
    } catch (error) {
      $("#inlineError").textContent = error.message || "验证码生成失败";
      $("#inlineError").hidden = false;
    }
  }

  function buildLink() {
    var label = encodeURIComponent(state.issuer + ":" + state.account);
    return "otpauth://totp/" + label + "?secret=" + encodeURIComponent(state.secret) + "&issuer=" + encodeURIComponent(state.issuer) + "&algorithm=SHA1&digits=" + state.digits + "&period=" + state.period;
  }

  function showToast(message) {
    $("#toastText").textContent = message;
    toast.classList.add("is-visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.classList.remove("is-visible"); }, 2100);
  }

  function feedback(button, message) {
    var label = button.querySelector(".button-label");
    if (!label) return;
    var original = label.textContent;
    label.textContent = message;
    button.classList.add("is-success");
    setTimeout(function () { label.textContent = original; button.classList.remove("is-success"); }, 1600);
  }

  function copyText(text, button, successMessage) {
    function success() { feedback(button, successMessage); showToast(successMessage); }
    function fallback() {
      var helper = document.createElement("textarea");
      helper.value = text;
      helper.setAttribute("readonly", "");
      helper.style.position = "fixed";
      helper.style.opacity = "0";
      document.body.appendChild(helper);
      helper.select();
      var copied = false;
      try { copied = document.execCommand("copy"); } catch (error) { copied = false; }
      document.body.removeChild(helper);
      if (copied) success();
      else {
        window.prompt("浏览器未允许自动复制，请手动复制：", text);
        showToast("请在弹窗中手动复制");
      }
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(success).catch(fallback);
    else fallback();
  }

  function openDialog() {
    secretInput.value = "";
    fieldError.hidden = true;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    setTimeout(function () { secretInput.focus(); }, 30);
  }

  function closeDialog() {
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  }

  $("#copyCode").addEventListener("click", function () { copyText(state.code, this, "验证码已复制"); });
  $("#copyLink").addEventListener("click", function () { copyText(buildLink(), this, "完整链接已复制"); });
  $("#openSecret").addEventListener("click", openDialog);
  $("#supportButton").addEventListener("click", function () { copyText("Cedars8", this, "客服名称已复制"); });
  $("#closeDialog").addEventListener("click", closeDialog);
  $("#cancelDialog").addEventListener("click", closeDialog);
  dialog.addEventListener("click", function (event) { if (event.target === dialog) closeDialog(); });
  $("#secretForm").addEventListener("submit", function (event) {
    event.preventDefault();
    try {
      var next = parseInput(secretInput.value);
      state.secret = next.secret;
      state.issuer = next.issuer;
      state.account = next.account;
      state.digits = next.digits;
      state.period = next.period;
      state.lastCounter = -1;
      updateCode();
      closeDialog();
      showToast("新密钥已生效");
    } catch (error) {
      fieldError.textContent = error.message || "无法识别此密钥";
      fieldError.hidden = false;
      secretInput.focus();
    }
  });

  function animationLoop() {
    updateCode();
    window.requestAnimationFrame(animationLoop);
  }

  updateCode();
  window.requestAnimationFrame(animationLoop);
})();
