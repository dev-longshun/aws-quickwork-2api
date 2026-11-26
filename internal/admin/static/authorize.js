"use strict";

const token = location.pathname.split("/")[2] || "";
const base = `/authorize/${encodeURIComponent(token)}`;
const $ = id => document.getElementById(id);
let busy = false;

const statusText = {
  pending: "等待开始：点下面的「开始登录」。",
  authorizing: "登录进行中：按下面的步骤操作。",
  completed: "这个链接已经完成授权。",
  expired: "这个链接已过期，请找管理员要一个新链接。"
};

function formatTime(epoch) {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toLocaleString("zh-CN", { hour12: false });
}

function showError(message) {
  $("error").textContent = message || "";
  $("error").hidden = !message;
}

async function call(path, body) {
  const options = { method: body ? "POST" : "GET", headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" };
  if (body) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(`${base}${path}`, options);
  } catch {
    throw new Error("网络错误，请检查网络后重试。");
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(translateError(data?.error) || `请求失败（HTTP ${response.status}）`);
    error.code = data?.error?.code || "";
    throw error;
  }
  return data;
}

function translateError(error) {
  if (!error) return "";
  const map = {
    ticket_not_found: "这个授权链接不存在或已被删除。",
    ticket_completed: "这个链接已经用过了。",
    ticket_expired: "这个链接已过期，请找管理员要一个新链接。",
    ticket_exhausted: "这个链接的尝试次数用完了，请找管理员要一个新链接。",
    login_limit: "同时登录的人太多，请过几分钟再试。",
    login_not_found: "登录会话已失效，请点「开始登录」重新开始。",
    invalid_proxy: "这个链接配置的出口代理已失效，请找管理员要一个新链接。"
  };
  if (map[error.code]) return map[error.code];
  if (error.code === "callback_failed") return `提交失败：${callbackError(error.message)}`;
  return error.message || "";
}

function callbackError(message) {
  const map = {
    "invalid callback URL": "这不是有效的地址，请复制浏览器地址栏的完整内容。",
    "discovery nonce mismatch": "这个地址不属于当前这次登录，请点「开始登录」重新来。",
    "OAuth state mismatch": "这个地址不属于当前这次登录，请点「开始登录」重新来。",
    "submit the discovery callback before the authorization callback": "请先提交第一次跳转的地址（带 nonce= 的那个）。",
    "open the authorize URL in the browser, then submit its callback URL": "你贴的是授权页面地址，请先在浏览器打开它完成授权，再贴跳转后的地址。",
    "open the discovery URL in the browser, then submit its callback URL": "你贴的是登录页面地址，请先在浏览器打开它完成登录，再贴跳转后的地址。",
    "upstream sign-in was rejected": "官方拒绝了这次登录，请重新开始。",
    "browser login expired; start a new login": "登录会话已超时，请点「开始登录」重新开始。",
    "a callback is already being processed": "上一次提交还在处理中，请稍等。",
    "upstream login or account persistence failed; start a new login if the code was consumed": "换取登录凭证失败，多半是授权码已过期。请点「开始登录」从头再来一遍，最后一步拿到地址马上贴回来。"
  };
  return map[message] || message;
}

function safeURL(raw) {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" ? url.href : "";
  } catch {
    return "";
  }
}

function render(s) {
  queueMicrotask(() => focusPasteOnStageChange(s));
  $("status").textContent = statusText[s.status] || s.status;
  $("label").hidden = !s.label;
  $("label").textContent = s.label || "";
  $("ticket-expires").textContent = formatTime(s.expires_at);
  $("attempts").textContent = String(s.activations_left ?? "—");

  const done = s.status === "completed";
  $("final-alert").hidden = !(s.status === "authorizing" && s.flow_stage === "authorize");
  $("done-panel").hidden = !done;
  $("steps-panel").hidden = done || s.status === "expired";
  if (done) {
    $("done-account").textContent = s.account ? `已授权账号：${s.account}` : "";
    return;
  }

  const stage = s.status === "authorizing" ? s.flow_stage : "";
  const link = safeURL(s.flow_url || "");
  $("start").hidden = Boolean(stage);
  $("start").disabled = s.activations_left <= 0;
  $("open-link").hidden = !link;
  $("copy-link").hidden = !link;
  if (link) $("open-link").href = link;
  $("open-link").textContent = stage === "authorize" ? "打开授权页面" : "打开官方登录页面";
  $("callback-form").hidden = !stage;
  $("flow-expires").textContent = formatTime(s.flow_expires_at);

  const current = !stage ? 1 : stage === "discovery" ? 2 : 4;
  for (let i = 1; i <= 4; i++) {
    const li = $(`step-${i}`);
    li.className = i < current ? "done" : i === current || (stage === "authorize" && i === 3) ? "current" : "";
  }
  if (stage === "discovery") $("status").textContent = "第 1 步：打开官方登录页面登录，然后把跳转后的地址贴到下面。";
  if (stage === "authorize") $("status").textContent = "第 2 步：打开授权页面确认授权，然后把跳转后打不开的 127.0.0.1 页面地址贴到下面。";
}

async function refresh() {
  try {
    render(await call("/status"));
    showError("");
  } catch (error) {
    $("status").textContent = "无法使用这个链接。";
    $("steps-panel").hidden = true;
    showError(error.message);
  }
}

let lastStage = "";
function focusPasteOnStageChange(s) {
  const stage = s.status === "authorizing" ? s.flow_stage || "" : "";
  if (stage && stage !== lastStage) $("callback").focus({ preventScroll: true });
  if (stage === "authorize" && lastStage !== "authorize") $("final-alert").scrollIntoView({ behavior: "smooth", block: "start" });
  lastStage = stage;
}

$("start").addEventListener("click", async () => {
  if (busy) return;
  busy = true;
  $("start").disabled = true;
  showError("");
  try {
    render(await call("/start", {}));
  } catch (error) {
    showError(error.message);
    await refresh();
  } finally {
    busy = false;
  }
});

$("copy-link").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("open-link").href);
    $("copy-link").textContent = "已复制";
    setTimeout(() => { $("copy-link").textContent = "复制链接"; }, 1500);
  } catch {
    showError("复制失败，请右键「打开官方登录页面」按钮复制链接。");
  }
});

$("callback-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (busy) return;
  const url = $("callback").value.trim();
  if (!url) return;
  busy = true;
  $("submit").disabled = true;
  $("submit").textContent = "提交中…";
  showError("");
  try {
    const data = await call("/callback", { url });
    $("callback").value = "";
    render(data);
  } catch (error) {
    showError(error.message);
    if (error.code !== "callback_failed") await refresh();
  } finally {
    busy = false;
    $("submit").disabled = false;
    $("submit").textContent = "提交地址";
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && !busy) refresh();
});

refresh();
