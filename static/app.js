"use strict";
const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  const data = res.status === 204 ? {} : await res.json();
  if (!res.ok) throw new Error(data.error || "request failed (" + res.status + ")");
  return data;
}

function say(text) { $("msg").textContent = text || ""; }

async function render() {
  try {
    const me = await api("GET", "/api/me");
    $("who").textContent = "Signed in as " + me.username;
    $("auth").hidden = true; $("app").hidden = false;
    const { tasks } = await api("GET", "/api/tasks");
    const list = $("tasks");
    list.replaceChildren();
    for (const t of tasks) {
      const li = document.createElement("li");
      if (t.done) li.className = "done";
      const box = document.createElement("input");
      box.type = "checkbox"; box.checked = t.done; box.style.width = "auto";
      box.onchange = () => act(() => api("PATCH", "/api/tasks/" + t.id, { done: box.checked }));
      const span = document.createElement("span");
      span.textContent = t.title;           // textContent: never inject user text as HTML
      const del = document.createElement("button");
      del.textContent = "Delete";
      del.onclick = () => act(() => api("DELETE", "/api/tasks/" + t.id));
      li.append(box, span, del);
      list.append(li);
    }
  } catch (e) {
    $("auth").hidden = false; $("app").hidden = true;
  }
}

async function act(fn) {
  try { say(""); await fn(); await render(); } catch (e) { say(e.message); }
}

const creds = () => ({ username: $("username").value, password: $("password").value });
$("login").onclick = () => act(() => api("POST", "/api/login", creds()));
$("register").onclick = () => act(async () => {
  await api("POST", "/api/register", creds());
  await api("POST", "/api/login", creds());
});
$("logout").onclick = () => act(() => api("POST", "/api/logout"));
$("add").onsubmit = (ev) => {
  ev.preventDefault();
  act(async () => { await api("POST", "/api/tasks", { title: $("title").value }); $("title").value = ""; });
};
render();
