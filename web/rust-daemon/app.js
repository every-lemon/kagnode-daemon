/* KagNode. Daemon — host workflows; Core owns presentation and interaction. */
(() => {
  let csrf = "";
  const content = document.querySelector("#content"),
    status = document.querySelector("#page-status");
  const el = (tag, text, cls) => {
    const n = document.createElement(tag);
    if (text !== undefined) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  };
  async function api(path, body, extra = {}) {
    const r = await fetch("/api/v1/" + path, {
      method: body === undefined ? "GET" : "POST",
      headers:
        body === undefined
          ? {}
          : {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrf,
              ...extra,
            },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (r.status === 401) {
      location.assign("/login");
      throw Error("Sign in again");
    }
    let v = {};
    if (r.status !== 204) {
      try {
        v = await r.json();
      } catch {
        const unreadable = Error("The server's reply could not be read.");
        unreadable.uncertain = true;
        throw unreadable;
      }
    }
    if (!r.ok) throw Error(v.error || "The request failed");
    return v;
  }
  function link(label, url, icon) {
    const a = el("a", undefined, "card");
    a.href = url;
    const i = el("span");
    i.dataset.coreIcon = icon;
    const name = el("strong", label);
    a.append(i, name);
    return a;
  }
  function field(form, label, name, value = "", type = "text") {
    const row = el("label", label),
      input = el("input");
    input.name = name;
    input.type = type;
    input.value = value;
    input.required = true;
    row.append(input);
    form.append(row);
    return input;
  }
  /* ---------- Backups: local administrator pages over the JSON contract in
     docs/BACKUP-SERVER.md. Nothing here restores data or claims a restore test. */
  const BACKUP = "backup-server/";
  const NAME = /^[A-Za-z0-9_-]{1,64}$/;
  const HASH = /^[0-9a-f]{64}$/;
  const SAFE = (n) => Number.isSafeInteger(n) && n >= 0;
  function bytes(n) {
    if (!Number.isFinite(n)) return "—";
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let v = n,
      i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return (i ? v.toFixed(v >= 100 ? 0 : 1) : String(v)) + " " + units[i];
  }
  function seconds(n) {
    if (!Number.isFinite(n)) return "—";
    if (n < 60) return n + " s";
    const parts = [];
    for (const [unit, size] of [
      ["d", 86400],
      ["h", 3600],
      ["min", 60],
    ]) {
      if (n >= size) {
        parts.push(Math.floor(n / size) + " " + unit);
        n %= size;
      }
    }
    return parts.slice(0, 2).join(" ");
  }
  function when(t) {
    if (!Number.isFinite(t) || t <= 0) return "—";
    const d = new Date(t * 1000),
      n = el("time", d.toLocaleString());
    n.dateTime = d.toISOString();
    n.title = d.toISOString();
    return n;
  }
  function badge(text, tone) {
    return el("span", text, "badge" + (tone ? " " + tone : ""));
  }
  function table(caption, headers, rows, actions) {
    const wrap = el("div", undefined, "table-wrap"),
      t = el(
        "table",
        undefined,
        "data-table" + (actions ? " has-actions" : ""),
      ),
      head = el("tr");
    t.append(el("caption", caption));
    for (const h of headers) {
      const th = el("th", h);
      th.scope = "col";
      head.append(th);
    }
    const thead = el("thead"),
      body = el("tbody");
    thead.append(head);
    for (const cells of rows) {
      const tr = el("tr");
      for (const [i, c] of cells.entries()) {
        const td = el("td");
        td.dataset.label = headers[i] || "";
        td.append(c instanceof Node ? c : document.createTextNode(String(c)));
        tr.append(td);
      }
      body.append(tr);
    }
    t.append(thead, body);
    wrap.append(t);
    return wrap;
  }
  function facts(pairs) {
    const dl = el("dl", undefined, "facts");
    for (const [k, v] of pairs) {
      const row = el("div");
      row.append(el("dt", k));
      const dd = el("dd");
      dd.append(v instanceof Node ? v : document.createTextNode(String(v)));
      row.append(dd);
      dl.append(row);
    }
    return dl;
  }
  /* Pages rebuild their panels after every action, which destroys the button
     that opened a dialog; remember it and restore focus to its equivalent. */
  let returnTo = null;
  function rememberOpener() {
    const b = document.activeElement;
    returnTo =
      b && b !== document.body
        ? {
            key: b.getAttribute("aria-label") || b.textContent.trim(),
            section: b.closest("section")?.querySelector("h2")?.textContent,
          }
        : null;
  }
  function restoreFocus(root) {
    const r = returnTo;
    returnTo = null;
    if (!r) return;
    const match = [...root.querySelectorAll("button, select")].find(
      (n) => (n.getAttribute("aria-label") || n.textContent.trim()) === r.key,
    );
    const target =
      match ||
      [...root.querySelectorAll("h2")].find((h) => h.textContent === r.section);
    if (!target) return;
    if (!target.matches("button, select")) target.tabIndex = -1;
    target.focus();
  }
  /* A modal form. onSubmit may throw to show an error and keep the dialog open.
     Typed values are cleared from the DOM whenever the dialog closes. */
  function formDialog({ title, intro, fields, submit, danger, onSubmit }) {
    return new Promise((resolve) => {
      const dialog = el("dialog"),
        form = el("form", undefined, "stack"),
        inputs = {},
        alert = el("p", undefined, "form-error"),
        actions = el("div", undefined, "actions"),
        cancel = el("button", "Cancel", "button"),
        ok = el("button", submit, "button " + (danger ? "danger" : "primary"));
      let done = false;
      rememberOpener();
      dialog.setAttribute("aria-label", title);
      alert.setAttribute("role", "alert");
      cancel.type = "button";
      form.append(el("h2", title));
      if (intro) form.append(el("p", intro, "muted"));
      const rows = [];
      for (const f of fields) {
        const row = el("label", f.label);
        let input;
        if (f.options) {
          input = el("select");
          for (const [value, text] of f.options) {
            const o = el("option", text);
            o.value = value;
            input.append(o);
          }
          input.value = f.value ?? f.options[0][0];
        } else {
          input = el("input");
          input.type = f.type || "text";
          input.required = f.required !== false;
          input.autocomplete = f.autocomplete || "off";
          if (f.pattern) input.pattern = f.pattern;
          if (f.placeholder) input.placeholder = f.placeholder;
          if (f.spellcheck === false) input.spellcheck = false;
          if (f.value !== undefined) input.value = f.value;
          if (f.readonly) input.readOnly = true;
        }
        input.name = f.name;
        row.append(input);
        if (f.hint) row.append(el("small", f.hint));
        form.append(row);
        inputs[f.name] = input;
        rows.push([f, row]);
      }
      // A field can depend on another field's value (grants only for Managers).
      const refreshRows = () => {
        for (const [f, row] of rows)
          row.hidden =
            !!f.showWhen && inputs[f.showWhen[0]].value !== f.showWhen[1];
      };
      form.addEventListener("change", refreshRows);
      refreshRows();
      actions.append(cancel, ok);
      form.append(alert, actions);
      form.onsubmit = async (e) => {
        e.preventDefault();
        ok.disabled = true;
        alert.textContent = "";
        try {
          const values = {};
          for (const f of fields) values[f.name] = inputs[f.name].value;
          await onSubmit(values);
          done = true;
          dialog.close();
        } catch (error) {
          alert.textContent = error.message;
        } finally {
          ok.disabled = false;
        }
      };
      cancel.onclick = () => dialog.close();
      dialog.addEventListener(
        "close",
        () => {
          for (const input of Object.values(inputs))
            if (input.tagName === "INPUT") input.value = "";
          dialog.remove();
          resolve(done);
        },
        { once: true },
      );
      dialog.append(form);
      document.body.append(dialog);
      dialog.showModal();
      Object.values(inputs)[0]?.focus();
    });
  }
  /* Password confirmation, then the identical typed request with the one-use
     confirmation header. Network failures are reported as uncertain, never retried. */
  async function confirmed({
    route,
    request,
    title,
    intro,
    submit,
    danger,
    extra = [],
    after,
    explain,
  }) {
    let result,
      uncertain = false;
    const done = await formDialog({
      title,
      intro,
      submit,
      danger,
      fields: [
        ...extra,
        {
          name: "password",
          label: "Your Daemon password",
          type: "password",
          autocomplete: "current-password",
          hint: "Entered locally to confirm this action. It is not stored.",
        },
      ],
      onSubmit: async (v) => {
        const req = typeof request === "function" ? request(v) : request;
        try {
          const c = await api(BACKUP + "confirm", {
            password: v.password,
            request: req,
          });
          result = await api(BACKUP + route, req, {
            "x-backup-confirmation": c.confirmation,
          });
        } catch (error) {
          if (error instanceof TypeError || error.uncertain) {
            uncertain = true;
            throw Error(
              "The connection failed or the reply could not be read. The action may or may not have completed. Check the current status before trying again.",
            );
          }
          const message = explain && explain(error);
          if (message) throw Error(message);
          throw error;
        }
        if (after) await after(result, req);
      },
    });
    return { done, result, uncertain };
  }
  function actionButton(label, context, onclick, danger) {
    const b = el("button", label, "button small" + (danger ? " danger" : ""));
    b.type = "button";
    b.setAttribute("aria-label", label + " " + context);
    b.onclick = onclick;
    return b;
  }
  const AGENT = {
    not_observed:
      "No backup agent status has been recorded on this host yet. This page shows the last worker observation, not a new probe.",
    disabled:
      "This host is not set up to send backups. Create the private backup-agent.json described in the backup documentation to enable scheduled transfers.",
    paused: "Scheduled transfers are paused in the local configuration.",
    deferred:
      "Transfers are waiting because the host is busy, stale or not ready. They continue automatically when readiness returns.",
    transferring: "A snapshot is being sent to a backup server.",
    scheduled: "The next snapshot is scheduled. Nothing is transferring now.",
    source_blocked:
      "The prepared snapshot or its configuration needs attention before the next job can be queued.",
    blocked:
      "The agent configuration or queue needs review. Check the private agent configuration and the queue below.",
  };
  const POLICY_FIELDS = [
    ["interval_seconds", "Backup interval", "seconds", false],
    ["recovery_point_seconds", "Recovery point goal", "seconds", false],
    ["keep_snapshots", "Snapshots to keep", "count", false],
    ["reserve_bytes", "Reserve space", "bytes", false],
    ["max_deferral_seconds", "Longest allowed deferral", "seconds", false],
    ["bandwidth_percent", "Bandwidth share", "percent", false],
    ["monthly_node_bytes", "Monthly limit per node", "bytes", true],
    ["monthly_server_bytes", "Monthly limit for the server", "bytes", true],
    ["required_copies", "Required copies", "count", false],
  ];
  function hintFor(unit, v) {
    if (v === null || v === undefined || v === "") return "";
    const n = Number(v);
    if (!Number.isFinite(n)) return "";
    return unit === "seconds"
      ? "= " + seconds(n)
      : unit === "bytes"
        ? "= " + bytes(n)
        : unit === "percent"
          ? "= " + n + " % of the available link"
          : "";
  }
  async function backupPage() {
    document.querySelector("h1").textContent = "Backups";
    const root = el("div", undefined, "stack");
    content.append(root);
    let selected = "",
      generation = 0;
    const notify = (text) => (status.textContent = text);
    const settle = (promise) =>
      promise.then(
        (value) => ({ ok: true, value }),
        (error) => ({ ok: false, error }),
      );
    function failure(title, error, meaning) {
      const p = el("section", undefined, "panel stack"),
        retry = el("button", "Try again", "button small");
      retry.type = "button";
      retry.onclick = () => refresh();
      p.append(
        el("h2", title),
        el("p", error.message, "form-error"),
        el("p", meaning, "muted"),
        retry,
      );
      return p;
    }
    async function refresh() {
      const mine = ++generation;
      try {
        await load(mine);
      } catch (error) {
        // An unexpected reply shape must never leave a blank or half-built page.
        if (mine === generation)
          notify("This page could not be updated: " + error.message);
      } finally {
        restoreFocus(root);
      }
    }
    /* Every response is checked against the latest refresh; an older reply can
       never replace a newer view, and each panel fails on its own. */
    async function load(mine) {
      const [server, agent] = await Promise.all([
        settle(api(BACKUP + "status")),
        settle(api("backup-agent/status")),
      ]);
      if (mine !== generation) return;
      const top = [
        server.ok
          ? summary(server.value)
          : failure(
              "Backup server",
              server.error,
              "The server status could not be read, so nothing here about the server is current. This is not a sign that backups are healthy.",
            ),
        agent.ok
          ? agentPanel(agent.value)
          : failure(
              "Sending from this host",
              agent.error,
              "The last agent observation could not be read; the server panel is unaffected.",
            ),
      ];
      if (!server.ok || server.value.enabled === false) {
        root.replaceChildren(...top);
        return;
      }
      const [nodes, policy] = await Promise.all([
        settle(api(BACKUP + "nodes")),
        settle(api(BACKUP + "policy")),
      ]);
      if (mine !== generation) return;
      const panels = [];
      if (nodes.ok && Array.isArray(nodes.value.nodes)) {
        const list = nodes.value.nodes;
        if (!list.some((n) => n.node === selected))
          selected = list[0]?.node || "";
        const node = selected; // this render's immutable identity
        const snaps = node
          ? await settle(api(BACKUP + "snapshots/" + encodeURIComponent(node)))
          : null;
        if (mine !== generation) return;
        panels.push(nodesPanel(list), snapshotsPanel(list, node, snaps));
      } else
        panels.push(
          failure(
            "Nodes and snapshots",
            nodes.ok ? Error("The server returned no node list.") : nodes.error,
            "The node list could not be read, so nodes and snapshots are not shown.",
          ),
        );
      panels.push(
        policy.ok && policy.value.policy
          ? policyPanel(policy.value.policy)
          : failure(
              "Policy",
              policy.ok
                ? Error("The server returned no policy.")
                : policy.error,
              "The current policy could not be read, so it cannot be edited here.",
            ),
      );
      // One atomic swap: the previous view (and its node selector) stays in
      // place until this render is complete and still the latest.
      root.replaceChildren(...top, ...panels);
    }
    function summary(s) {
      const p = el("section", undefined, "panel stack");
      p.append(el("h2", "Backup server"));
      if (s.enabled === false) {
        p.append(
          el(
            "p",
            "This host is not configured as a backup server. Nothing is being stored here.",
          ),
        );
        return p;
      }
      const total = Number(s.storage_total_bytes),
        free = Number(s.storage_available_bytes),
        used = total - free;
      const meter = el("progress");
      meter.max = total || 1;
      meter.value = Number.isFinite(used) ? used : 0;
      meter.setAttribute("aria-label", "Backup storage used");
      p.append(
        facts([
          ["Site", s.site],
          ["Server", s.server],
          ["Process", s.process_id],
          ["Storage", bytes(free) + " free of " + bytes(total)],
        ]),
        meter,
      );
      if (total && free / total < 0.1)
        p.append(
          badge("Low free space", "warn"),
          el(
            "p",
            "Less than 10% of the backup volume is free. Review retention before new snapshots are refused.",
            "muted",
          ),
        );
      if (s.pending_catalog_cleanups > 0)
        p.append(
          badge(s.pending_catalog_cleanups + " cleanup pending", "warn"),
          el(
            "p",
            "Data for deleted snapshots is still being removed; the server retries this automatically.",
            "muted",
          ),
        );
      if (s.verification) p.append(el("p", String(s.verification), "muted"));
      return p;
    }
    function agentPanel(a) {
      const p = el("section", undefined, "panel stack"),
        st = a.status || {},
        state = st.state || "not_observed";
      p.append(el("h2", "Sending from this host"));
      const tone =
        state === "blocked" || state === "source_blocked"
          ? "bad"
          : state === "deferred" || state === "paused"
            ? "warn"
            : state === "transferring" || state === "scheduled"
              ? "ok"
              : "";
      p.append(badge(state.replace("_", " "), tone));
      p.append(el("p", AGENT[state] || "Unknown state: " + state));
      if (st.error) p.append(el("p", String(st.error), "form-error"));
      // A failed new snapshot is reported separately from older work that may
      // still be running, so neither message hides the other.
      if (st.source_error)
        p.append(
          el(
            "p",
            (state === "deferred" || state === "transferring"
              ? "Older work is still in progress, but the next backup cannot be queued: "
              : "The next backup cannot be queued: ") + String(st.source_error),
            "form-error",
          ),
        );
      const queue = (st.queue && st.queue.transfers) || [];
      if (queue.length)
        p.append(
          table(
            "Latest transfers (most recent 64)",
            [
              "Snapshot",
              "State",
              "Attempts",
              "Next attempt",
              "Receipt",
              "Notes",
            ],
            queue.map((t) => [
              t.snapshot,
              badge(
                t.state,
                t.state === "completed"
                  ? "ok"
                  : t.state === "blocked"
                    ? "bad"
                    : "",
              ),
              t.attempts,
              t.state === "pending" ? when(t.next_attempt) : "—",
              t.receipt
                ? el(
                    "span",
                    "Ciphertext verified " +
                      new Date(t.receipt.verified_at * 1000).toLocaleString() +
                      " · not a restore test",
                  )
                : "—",
              t.error || "",
            ]),
          ),
        );
      const history = st.queue && st.queue.history;
      if (history && history.compacted_identities)
        p.append(
          el(
            "p",
            history.compacted_identities +
              " compacted, latest " +
              history.completed_job_limit +
              " kept",
            "muted",
          ),
        );
      return p;
    }
    function nodesPanel(nodes) {
      const p = el("section", undefined, "panel stack");
      p.append(el("h2", "Nodes"));
      if (!nodes.length) p.append(el("p", "No nodes have been approved yet."));
      else
        p.append(
          table(
            "Nodes allowed to send backups",
            ["Node", "Certificate", "State", "Actions"],
            nodes.map((n) => {
              const cert = el("code", n.certificate_sha256.slice(0, 16) + "…");
              cert.title = n.certificate_sha256;
              const act = el("div", undefined, "actions");
              // Rotation needs an enrolled node; a pending approval can only be revoked.
              if (!n.revoked) {
                if (n.enrolled)
                  act.append(
                    actionButton("Rotate certificate", n.node, () => rotate(n)),
                  );
                act.append(
                  actionButton("Revoke", n.node, () => revoke(n), true),
                );
              }
              return [
                n.node,
                cert,
                n.revoked
                  ? badge("Revoked", "bad")
                  : n.enrolled
                    ? badge("Enrolled", "ok")
                    : badge("Waiting for enrollment", "warn"),
                act,
              ];
            }),
            true,
          ),
        );
      const add = el("button", "Approve a node", "button primary");
      add.type = "button";
      add.onclick = approve;
      p.append(add);
      return p;
    }
    async function approve() {
      let token;
      const { done } = await confirmed({
        route: "approve",
        title: "Approve a node",
        intro:
          "The node sends you its public key and certificate fingerprint. Approving creates a one-use enrollment token that expires in 10 minutes.",
        submit: "Approve node",
        extra: [
          {
            name: "node",
            label: "Node name",
            pattern: "[A-Za-z0-9_\\-]{1,64}",
            hint: "Letters, numbers, - and _ (up to 64).",
          },
          {
            name: "public_key",
            label: "Node signing public key",
            pattern: "[0-9a-f]{64}",
            spellcheck: false,
            hint: "64 lowercase hexadecimal characters.",
          },
          {
            name: "certificate_sha256",
            label: "Node certificate fingerprint (SHA-256)",
            pattern: "[0-9a-f]{64}",
            spellcheck: false,
            hint: "64 lowercase hexadecimal characters.",
          },
        ],
        request: (v) => {
          if (!NAME.test(v.node)) throw Error("Use a valid node name.");
          if (!HASH.test(v.public_key) || !HASH.test(v.certificate_sha256))
            throw Error(
              "Keys and fingerprints are 64 lowercase hex characters.",
            );
          return {
            action: "approve",
            node: v.node,
            public_key: v.public_key,
            certificate_sha256: v.certificate_sha256,
          };
        },
        after: (r) => (token = r),
      });
      if (done && token) await showToken(token);
      await refresh();
    }
    function showToken(result) {
      return new Promise((resolve) => {
        const dialog = el("dialog"),
          box = el("div", undefined, "stack"),
          field = el("input"),
          close = el("button", "I have copied it", "button primary");
        dialog.setAttribute("aria-label", "Enrollment token");
        field.readOnly = true;
        field.value = result.token;
        field.setAttribute("aria-label", "One-use enrollment token");
        field.onfocus = () => field.select();
        close.onclick = () => dialog.close();
        box.append(
          el("h2", "Enrollment token for " + result.node),
          el(
            "p",
            "Give this one-use token to the node administrator privately. It is shown only now and expires in " +
              Math.round(result.expires_in / 60) +
              " minutes.",
          ),
          field,
          close,
        );
        dialog.append(box);
        document.body.append(dialog);
        dialog.addEventListener(
          "close",
          () => {
            field.value = "";
            dialog.remove();
            resolve();
          },
          { once: true },
        );
        dialog.showModal();
        field.focus();
      });
    }
    async function revoke(n) {
      const r = await confirmed({
        route: "revoke",
        title: "Revoke " + n.node,
        intro:
          "The node's certificate stops working immediately. Existing snapshots are kept.",
        submit: "Revoke node",
        danger: true,
        request: { action: "revoke", node: n.node },
      });
      if (r.done) notify("Revoked " + n.node + ".");
      await refresh();
    }
    async function rotate(n) {
      const r = await confirmed({
        route: "rotate-certificate",
        title: "Rotate certificate for " + n.node,
        intro:
          "Switch this node to its new certificate. The old certificate stops working and can never be approved again.",
        submit: "Rotate certificate",
        extra: [
          {
            name: "certificate_sha256",
            label: "New certificate fingerprint (SHA-256)",
            pattern: "[0-9a-f]{64}",
            spellcheck: false,
            hint:
              "Current: " +
              n.certificate_sha256.slice(0, 16) +
              "… · 64 lowercase hexadecimal characters.",
          },
        ],
        request: (v) => {
          if (!HASH.test(v.certificate_sha256))
            throw Error("The fingerprint is 64 lowercase hex characters.");
          return {
            action: "rotate_certificate",
            node: n.node,
            expected_sha256: n.certificate_sha256,
            certificate_sha256: v.certificate_sha256,
          };
        },
      });
      if (r.done) notify("Certificate rotated for " + n.node + ".");
      await refresh();
    }
    /* `node` is the identity this panel was rendered for; every label and action
       below uses it, never the mutable `selected` value. */
    function snapshotsPanel(nodes, node, snaps) {
      const p = el("section", undefined, "panel stack");
      p.append(el("h2", "Snapshots"));
      if (!nodes.length) {
        p.append(el("p", "Snapshots appear here once a node has sent one."));
        return p;
      }
      const pick = el("select");
      pick.setAttribute("aria-label", "Node");
      for (const n of nodes) {
        const o = el("option", n.node);
        o.value = n.node;
        pick.append(o);
      }
      pick.value = node;
      pick.onchange = () => {
        selected = pick.value;
        refresh();
      };
      p.append(pick);
      if (!snaps || !snaps.ok) {
        p.append(
          el(
            "p",
            (snaps && snaps.error.message) || "Snapshots could not be read.",
            "form-error",
          ),
        );
        return p;
      }
      const data = snaps.value;
      const protectedIds = new Set(data.protected || []);
      if (!data.snapshots.length)
        p.append(el("p", "This node has not sent a snapshot yet."));
      else
        p.append(
          table(
            "Snapshots for " + node + " (newest received first)",
            ["Snapshot", "Received", "Claimed creation", "Status", "Actions"],
            data.snapshots.map((s) => {
              const state = el("div", undefined, "badges"),
                act = el("div", undefined, "actions");
              if (s.pinned) state.append(badge("Pinned", "ok"));
              if (protectedIds.has(s.id)) state.append(badge("Protected"));
              state.append(
                s.restore_tested
                  ? badge("Restore tested", "ok")
                  : badge("Not restore tested", "warn"),
              );
              act.append(
                actionButton(s.pinned ? "Unpin" : "Pin", s.id, () =>
                  pin(node, s),
                ),
              );
              if (!protectedIds.has(s.id) && !s.pinned)
                act.append(
                  actionButton("Delete", s.id, () => remove(node, s), true),
                );
              return [s.id, when(s.received_at), when(s.created), state, act];
            }),
            true,
          ),
        );
      const gc = el("button", "Remove unreferenced data", "button");
      gc.type = "button";
      gc.onclick = collect;
      p.append(
        gc,
        el(
          "small",
          "Frees storage no snapshot refers to. This is not a restore test.",
        ),
      );
      return p;
    }
    async function pin(node, s) {
      const want = !s.pinned;
      try {
        if (want)
          await api(BACKUP + "pin", {
            action: "pin",
            node,
            snapshot: s.id,
            pinned: true,
          });
        else
          await confirmed({
            route: "pin",
            title: "Unpin " + s.id,
            intro: "An unpinned snapshot can be removed by retention.",
            submit: "Unpin",
            request: { action: "pin", node, snapshot: s.id, pinned: false },
          });
      } catch (error) {
        notify(error.message);
      }
      await refresh();
    }
    async function remove(node, s) {
      const phrase = "delete " + node + "/" + s.id;
      const r = await confirmed({
        route: "delete",
        title: "Delete " + s.id,
        intro:
          "This permanently removes the snapshot from this backup server. Protected snapshots are refused.",
        submit: "Delete snapshot",
        danger: true,
        extra: [
          {
            name: "confirm",
            label: "Type “" + phrase + "” to confirm",
            hint: "Exactly as shown.",
          },
        ],
        request: (v) => {
          if (v.confirm !== phrase)
            throw Error("The confirmation text does not match.");
          return { action: "delete", node, snapshot: s.id, confirm: phrase };
        },
      });
      if (r.done) notify("Deleted " + s.id + ".");
      await refresh();
    }
    async function collect() {
      let removed;
      const r = await confirmed({
        route: "garbage-collection",
        title: "Remove unreferenced data",
        intro:
          "Deletes stored objects that no snapshot uses. Snapshots are not changed.",
        submit: "Remove data",
        request: { action: "collect_garbage", confirm: true },
        after: (res) => (removed = res.objects_removed),
      });
      if (r.done) notify(String(removed) + " unreferenced objects removed.");
      await refresh();
    }
    function policyPanel(policy) {
      const p = el("section", undefined, "panel stack"),
        f = el("form", undefined, "stack"),
        inputs = {};
      const grid = el("div", undefined, "form-grid");
      p.append(el("h2", "Policy"), f);
      let editable = true;
      for (const [key, label, unit, nullable] of POLICY_FIELDS) {
        const row = el("label", label),
          input = el("input"),
          hint = el("small");
        input.type = "number";
        input.name = key;
        input.min = "0";
        input.step = "1";
        input.inputMode = "numeric";
        input.required = !nullable;
        const v = policy[key];
        if (v !== null && v !== undefined && !SAFE(v)) editable = false;
        input.value = v === null || v === undefined ? "" : String(v);
        hint.textContent = hintFor(unit, input.value);
        input.oninput = () => (hint.textContent = hintFor(unit, input.value));
        row.append(input, hint);
        if (nullable)
          row.append(el("small", "Leave empty for no limit.", "muted"));
        grid.append(row);
        inputs[key] = input;
      }
      const save = el("button", "Review and save", "button primary");
      f.append(grid, save);
      if (!editable) {
        for (const i of Object.values(inputs)) i.disabled = true;
        save.disabled = true;
        f.append(
          el(
            "p",
            "A value is larger than this page can edit exactly. Use the command line to change it.",
            "form-error",
          ),
        );
      }
      f.onsubmit = async (e) => {
        e.preventDefault();
        let conflicted = false;
        const next = { revision: policy.revision + 1 };
        for (const [key, , , nullable] of POLICY_FIELDS) {
          const raw = inputs[key].value.trim();
          if (raw === "" && nullable) next[key] = null;
          else {
            const n = Number(raw);
            if (!SAFE(n)) {
              notify("Use whole numbers of zero or more for every field.");
              inputs[key].focus();
              return;
            }
            next[key] = n;
          }
        }
        const r = await confirmed({
          route: "policy",
          title: "Save backup policy",
          intro:
            "Saves revision " +
            next.revision +
            ". If another administrator changed the policy meanwhile, you will be asked to review it first.",
          submit: "Save policy",
          request: { action: "set_policy", policy: next },
          explain: (error) =>
            /conflict|revision/i.test(error.message)
              ? ((conflicted = true),
                "Another administrator changed the policy. Close this window to see the current values, review them, then save again.")
              : null,
        });
        if (r.done) notify("Policy saved as revision " + next.revision + ".");
        await refresh();
        if (conflicted)
          notify(
            "The policy changed while you were editing. The form now shows the current values; review them before saving again.",
          );
      };
      return p;
    }
    await refresh();
  }
  /* ---------------------------------------------------------------- Administration
     Accounts, roles and settings. Sign-in here uses the Daemon's role API with its
     own session cookie, so Managers and Viewers can sign in too. The page only
     shows what the signed-in role may use; the Daemon enforces every request. */
  const PRODUCT_NAMES = {
    "proxy-manager": "Proxy",
    vpn: "VPN",
    entropy: "Entropy",
    media: "Media",
    passwords: "Passwords",
    mail: "Mail",
    httpboot: "HTTP Boot",
    netctl: "Network",
    backup: "Backups",
  };
  const ROLE_TEXT = {
    operator: "Everything, including users and Daemon settings",
    manager: "Chosen services, each at a chosen level",
    viewer: "Read-only server analytics; no logs or actions",
  };
  async function adminPage() {
    const ROLES = "/api/v1/roles/";
    let rcsrf = "",
      me = null;
    const heading = document.querySelector("h1");
    const requestId = () =>
      [...crypto.getRandomValues(new Uint8Array(16))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    async function rapi(suffix, payload, confirmation = null, challenge) {
      const post = payload !== undefined;
      let r;
      r = await fetch(ROLES + suffix, {
        method: post ? "POST" : "GET",
        headers: post
          ? {
              "Content-Type": "application/json",
              "X-CSRF-Token": challenge || rcsrf,
            }
          : {},
        body: post
          ? JSON.stringify({ request_id: requestId(), confirmation, payload })
          : undefined,
      });
      let v = {};
      try {
        v = await r.json();
      } catch {
        const unreadable = Error("The server's reply could not be read.");
        unreadable.uncertain = true;
        throw unreadable;
      }
      if (r.status === 401 && me) {
        me = null;
        signIn("Your session ended. Sign in again.");
        throw Error("Sign in again");
      }
      if (!r.ok) {
        const e = Error(v.error || "The request failed");
        e.status = r.status;
        throw e;
      }
      return v;
    }
    /* Password confirmation, then the identical typed request with the one-use
       confirmation. Network failures are reported as uncertain, never retried. */
    async function rconfirmed({
      route,
      payload,
      title,
      intro,
      submit,
      danger,
      extra = [],
      build,
    }) {
      let result;
      const done = await formDialog({
        title,
        intro,
        submit,
        danger,
        fields: [
          ...extra,
          {
            name: "password",
            label: "Your Daemon password",
            type: "password",
            autocomplete: "current-password",
            hint: "Entered locally to confirm this action. It is not stored.",
          },
        ],
        onSubmit: async (v) => {
          const target = build ? build(v) : payload;
          try {
            const c = await rapi("confirm", {
              action: "reauthenticate",
              password: v.password,
              target,
            });
            result = await rapi(route, target, c.confirmation);
          } catch (error) {
            if (error instanceof TypeError || error.uncertain)
              throw Error(
                "The connection failed or the reply could not be read. The action may or may not have completed. Check the current state before trying again.",
              );
            if (error.status === 409)
              throw Error(
                "This changed since you opened it. Close this and reload the list.",
              );
            throw error;
          }
        },
      });
      return { done, result };
    }
    const grantFields = (current = {}) =>
      Object.entries(PRODUCT_NAMES).map(([id, name]) => ({
        name: "grant:" + id,
        label: name,
        options: [
          ["", "No access"],
          ["view", "View"],
          ["operate", "Operate"],
          ["manage", "Manage"],
        ],
        value: current[id] || "",
        showWhen: ["role", "manager"],
      }));
    const grantsOf = (v) => {
      const g = {};
      if (v.role === "manager")
        for (const id of Object.keys(PRODUCT_NAMES))
          if (v["grant:" + id]) g[id] = v["grant:" + id];
      return g;
    };
    const roleOptions = [
      ["viewer", "Viewer — read-only analytics"],
      ["manager", "Manager — chosen services"],
      ["operator", "Operator — everything"],
    ];
    function servicesText(u) {
      if (u.role === "operator") return "all services";
      if (u.role === "viewer") return "analytics only";
      const g = Object.entries(u.grants || {});
      return g.length
        ? g.map(([p, l]) => (PRODUCT_NAMES[p] || p) + ": " + l).join(", ")
        : "none";
    }

    function signIn(message) {
      heading.textContent = "Administration";
      content.replaceChildren();
      const form = el("form", undefined, "panel stack sign-in");
      form.append(el("h2", "Sign in"));
      const account = field(form, "Account", "account", "", "email"),
        password = field(form, "Password", "password", "", "password");
      account.autocomplete = "username";
      password.autocomplete = "current-password";
      const alert = el("p", message || "", "form-error"),
        go = el("button", "Sign in", "button primary");
      alert.setAttribute("role", "alert");
      form.append(alert, go);
      form.onsubmit = async (e) => {
        e.preventDefault();
        go.disabled = true;
        alert.textContent = "";
        try {
          const challenge = await rapi("auth");
          const r = await rapi(
            "login",
            {
              action: "login",
              account: account.value,
              password: password.value,
            },
            null,
            challenge.csrf,
          );
          rcsrf = r.csrf;
          me = r.whoami;
          password.value = "";
          shell();
        } catch (error) {
          password.value = "";
          alert.textContent = error.message;
        } finally {
          go.disabled = false;
        }
      };
      content.append(form);
      account.focus();
    }

    // ------------------------------------------------------------ signed in
    const can = (a) => (me?.capabilities?.global || []).includes(a);
    let tab = "overview";
    function shell() {
      heading.textContent = "Administration";
      content.replaceChildren();
      const bar = el("div", undefined, "admin-bar");
      const who = el("span", undefined, "admin-who");
      who.append(
        el("strong", me.user.account),
        document.createTextNode(" "),
        badge(me.user.role),
      );
      if (me.protection === "unprotected")
        who.append(document.createTextNode(" "), badge("unprotected", "warn"));
      const out = el("button", "Sign out", "button small");
      out.type = "button";
      out.onclick = async () => {
        try {
          await rapi("logout", { action: "logout" });
        } catch {
          /* the session may already be gone */
        }
        me = null;
        signIn();
      };
      bar.append(who, out);
      const tabs = el("div", undefined, "tabs"),
        panel = el("section", undefined, "panel stack");
      tabs.setAttribute("role", "tablist");
      const items = [["overview", "Overview", true]];
      items.push(["services", "Services", me.user.role === "manager"]);
      items.push(["users", "Users", can("user_list")]);
      items.push(["security", "Settings", can("security_get")]);
      items.push(["audit", "Activity", can("audit")]);
      items.push(["account", "My account", can("change_password")]);
      for (const [id, label, shown] of items) {
        if (!shown) continue;
        const b = el("button", label, "tab");
        b.type = "button";
        b.setAttribute("role", "tab");
        b.setAttribute("aria-selected", String(tab === id));
        b.onclick = () => {
          tab = id;
          shell();
        };
        tabs.append(b);
      }
      content.append(bar, tabs, panel);
      panel.setAttribute("role", "tabpanel");
      ({ overview, services, users, security, audit, account })
        [tab](panel)
        .catch((e) => {
          panel.replaceChildren(el("p", e.message, "form-error"));
          if (e.status === 403 && /disabled/i.test(e.message))
            panel.append(
              el(
                "p",
                "Web administration is off. An Operator turns it on from the terminal (kagnode, then a, Web administration).",
                "muted",
              ),
            );
        });
      restoreFocus(content);
    }
    async function overview(panel) {
      const o = await rapi("overview");
      const node = o.nodes?.[0] || {},
        v = node.last_sample?.values || {};
      const num = (k, unit = "") =>
        typeof v[k] === "number" ? v[k].toFixed(1) + unit : "—";
      panel.append(
        el("h2", "Server"),
        facts([
          [
            "Daemon",
            badge(
              node.health || "unknown",
              node.health === "online" ? "ok" : "warn",
            ),
          ],
          ["CPU", num("cpu.percent", "%")],
          ["Memory", num("memory.used_percent", "%")],
          ["Load", num("load.1")],
        ]),
      );
      panel.append(el("h2", "Your access"));
      const grants = Object.entries(me.user.grants || {});
      panel.append(
        facts([
          ["Role", me.user.role],
          ["Allowed", ROLE_TEXT[me.user.role]],
          ...(me.user.role === "manager"
            ? [
                [
                  "Services",
                  grants.length
                    ? grants
                        .map(([p, l]) => (PRODUCT_NAMES[p] || p) + ": " + l)
                        .join(", ")
                    : "none granted yet",
                ],
              ]
            : []),
        ]),
      );
      if (me.protection === "unprotected")
        panel.append(
          el(
            "p",
            "Unprotected: anyone using this machine's terminal is the Operator.",
            "muted",
          ),
        );
    }
    const LEVEL_TEXT = {
      view: "See status and health.",
      operate:
        "View, plus read logs and start, stop or restart through a reviewed plan.",
      manage:
        "Operate, plus enable or disable at boot, Core updates and product actions.",
    };
    async function services(panel) {
      const ids = (me.capabilities?.products || []).map((x) => x.product);
      panel.append(el("h2", "Your services"));
      if (!ids.length) {
        panel.append(
          el(
            "p",
            "No services have been granted to you yet. Ask an Operator to give you a service and a level.",
            "muted",
          ),
        );
        return;
      }
      const grid = el("div", undefined, "service-grid");
      for (const id of ids) {
        const level = (me.user.grants || {})[id] || "view";
        const card = el("article", undefined, "panel stack");
        let state = "Status available";
        try {
          const r = await rapi("products/" + encodeURIComponent(id));
          state = r.native_actions_enabled
            ? "Actions enabled"
            : "Read-only (actions not enabled)";
        } catch (e) {
          state = e.message;
        }
        card.append(
          el("h3", PRODUCT_NAMES[id] || id),
          facts([
            ["Your level", badge(level, level === "manage" ? "info" : "ok")],
            ["Allows", LEVEL_TEXT[level] || ""],
            ["State", state],
          ]),
        );
        grid.append(card);
      }
      panel.append(grid);
    }
    async function users(panel) {
      const data = await rapi("users");
      const add = el("button", "New user", "button primary");
      add.type = "button";
      add.onclick = () =>
        rconfirmed({
          route: "users-create",
          title: "New user",
          intro: "Choose a role. Managers get services at a level you pick.",
          submit: "Create user",
          extra: [
            {
              name: "account",
              label: "Account (email)",
              type: "email",
              autocomplete: "off",
            },
            {
              name: "newpassword",
              label: "Password",
              type: "password",
              autocomplete: "new-password",
              hint: "At least 12 characters.",
            },
            { name: "role", label: "Role", options: roleOptions },
            ...grantFields(),
          ],
          build: (v) => ({
            action: "user_create",
            account: v.account,
            password: v.newpassword,
            role: v.role,
            grants: grantsOf(v),
          }),
        }).then((r) => r.done && shell());
      const rows = data.users.map((u) => {
        const edit = actionButton("Edit role", u.account, () =>
          rconfirmed({
            route: "users-update",
            title: "Change role and services",
            intro: u.account,
            submit: "Save",
            extra: [
              {
                name: "role",
                label: "Role",
                options: roleOptions,
                value: u.role,
              },
              ...grantFields(u.grants),
            ],
            build: (v) => ({
              action: "user_update",
              id: u.id,
              expected_revision: u.auth_revision,
              role: v.role,
              grants: grantsOf(v),
              disabled: u.disabled,
            }),
          }).then((r) => r.done && shell()),
        );
        const toggle = actionButton(
          u.disabled ? "Enable" : "Disable",
          u.account,
          () =>
            rconfirmed({
              route: "users-update",
              title: (u.disabled ? "Enable " : "Disable ") + u.account,
              intro: u.disabled
                ? "They can sign in again."
                : "They are signed out now and cannot sign in. History is kept.",
              submit: u.disabled ? "Enable" : "Disable",
              danger: !u.disabled,
              build: () => ({
                action: "user_update",
                id: u.id,
                expected_revision: u.auth_revision,
                role: u.role,
                grants: u.grants || {},
                disabled: !u.disabled,
              }),
            }).then((r) => r.done && shell()),
          !u.disabled,
        );
        const reset = actionButton("Reset password", u.account, () =>
          rconfirmed({
            route: "users-reset-password",
            title: "Reset password",
            intro: u.account + " signs in again with the new password.",
            submit: "Reset password",
            danger: true,
            extra: [
              {
                name: "newpassword",
                label: "New password",
                type: "password",
                autocomplete: "new-password",
                hint: "At least 12 characters.",
              },
            ],
            build: (v) => ({
              action: "user_reset_password",
              id: u.id,
              expected_revision: u.auth_revision,
              password: v.newpassword,
            }),
          }).then((r) => r.done && shell()),
        );
        const actions = el("span", undefined, "row-actions");
        actions.append(edit, toggle, reset);
        return [
          u.account + (u.id === me.user.id ? " (you)" : ""),
          badge(u.role),
          servicesText(u),
          badge(u.disabled ? "disabled" : "active", u.disabled ? "bad" : "ok"),
          actions,
        ];
      });
      panel.append(
        el("h2", "Users"),
        table(
          "Daemon users",
          ["Account", "Role", "Services", "Status", "Actions"],
          rows,
          true,
        ),
        add,
      );
    }
    async function security(panel) {
      const s = await rapi("security");
      panel.append(
        el("h2", "Web administration"),
        facts([
          [
            "Protection",
            badge(
              s.mode === "owner"
                ? "unprotected (owner mode)"
                : "password protected",
              s.mode === "owner" ? "warn" : "ok",
            ),
          ],
          [
            "Web administration",
            badge(s.admin_enabled ? "on" : "off", s.admin_enabled ? "ok" : ""),
          ],
        ]),
      );
      if (s.mode !== "owner") {
        const b = el(
          "button",
          s.admin_enabled
            ? "Turn web administration off"
            : "Turn web administration on",
          "button" + (s.admin_enabled ? " danger" : " primary"),
        );
        b.type = "button";
        b.onclick = () =>
          rconfirmed({
            route: "security",
            title: s.admin_enabled
              ? "Turn web administration off"
              : "Turn web administration on",
            intro: s.admin_enabled
              ? "Users and settings can then only be changed from the terminal."
              : "Operators can manage users and settings from the web.",
            submit: s.admin_enabled ? "Turn off" : "Turn on",
            danger: s.admin_enabled,
            build: () => ({
              action: "security_set",
              expected_revision: s.revision,
              admin_enabled: !s.admin_enabled,
            }),
          }).then((r) => r.done && shell());
        panel.append(b);
      }
    }
    async function audit(panel) {
      const data = await rapi("audit");
      panel.append(el("h2", "Recent security activity"));
      if (!data.events.length) {
        panel.append(el("p", "No activity yet.", "muted"));
        return;
      }
      panel.append(
        table(
          "Recent security activity",
          ["When", "Action", "Detail"],
          data.events.map((e) => [when(e.at), e.action, e.detail]),
        ),
      );
    }
    async function account(panel) {
      panel.append(
        el("h2", "My account"),
        facts([
          ["Account", me.user.account],
          ["Role", me.user.role],
        ]),
      );
      const b = el("button", "Change my password", "button");
      b.type = "button";
      b.onclick = async () => {
        const done = await formDialog({
          title: "Change my password",
          intro: "You sign in again afterwards.",
          submit: "Change password",
          fields: [
            {
              name: "current",
              label: "Current password",
              type: "password",
              autocomplete: "current-password",
            },
            {
              name: "next",
              label: "New password",
              type: "password",
              autocomplete: "new-password",
              hint: "At least 12 characters.",
            },
          ],
          onSubmit: (v) =>
            rapi("password", {
              action: "change_password",
              current_password: v.current,
              password: v.next,
            }),
        });
        if (done) {
          me = null;
          signIn("Password changed. Sign in with the new password.");
        }
      };
      panel.append(b);
    }
    try {
      me = await rapi("whoami");
      shell();
    } catch {
      signIn();
    }
  }
  async function render() {
    if (!content) return;
    if (location.pathname === "/admin") return adminPage();
    try {
      const session = await api("session");
      csrf = session.user.csrf;
      document
        .querySelector("#sign-out")
        ?.addEventListener("click", async () => {
          await api("logout", {});
          location.assign("/login");
        });
      content.replaceChildren();
      const path = location.pathname;
      if (path === "/settings") {
        document.querySelector("h1").textContent = "Settings";
        const s = await api("settings"),
          f = el("form", undefined, "panel stack");
        f.append(el("h2", "Installation"), el("p", "Profile: " + s.profile));
        const row = el("label", undefined, "setting-row"),
          check = el("input");
        check.type = "checkbox";
        check.dataset.coreSwitch = "";
        check.checked = s.web_enabled;
        row.append(check, el("span", "Enable the Daemon web dashboard"));
        f.append(row);
        const save = el("button", "Save preferences", "button primary");
        f.append(save);
        f.onsubmit = async (e) => {
          e.preventDefault();
          save.disabled = true;
          try {
            const next = await api("settings", {
              ...s,
              web_enabled: check.checked,
            });
            Object.assign(s, next);
            status.textContent = check.checked
              ? "Preferences saved."
              : "Dashboard disabled. Your terminal management remains available.";
          } catch (e) {
            status.textContent = e.message;
          } finally {
            save.disabled = false;
          }
        };
        content.append(f);
        const appearance = el("section", undefined, "panel");
        appearance.dataset.corePreferencesHost = "";
        content.append(appearance);
      } else if (path === "/backup") {
        await backupPage();
      } else if (path === "/audit") {
        document.querySelector("h1").textContent = "Activity";
        const data = await api("audit");
        if (!data.events.length)
          content.append(el("p", "No administration activity yet."));
        for (const event of data.events) {
          const row = el("article", undefined, "panel");
          row.append(
            el("strong", event.action),
            el("p", event.detail),
            el(
              "small",
              event.actor + " · " + new Date(event.at * 1000).toLocaleString(),
            ),
          );
          content.append(row);
        }
      } else if (path === "/ha") {
        document.querySelector("h1").textContent = "High availability";
        const data = await api("ha/configuration");
        const f = el("form", undefined, "panel stack");
        f.append(
          el(
            "p",
            "Review an active/passive cluster. Saving a declaration does not activate networking, storage or failover.",
          ),
        );
        const c = data.configuration || {};
        field(f, "Cluster name", "name", c.name || "");
        for (const role of ["primary", "standby", "witness"]) {
          const group = el("fieldset", undefined, "stack");
          group.append(el("legend", role[0].toUpperCase() + role.slice(1)));
          for (const [key, label] of [
            ["name", "Node name"],
            ["address", "Node IP address"],
            ["failure_domain", "Independent failure domain"],
          ])
            field(group, label, role + "_" + key, c[role]?.[key] || "");
          f.append(group);
        }
        field(f, "HA VLAN ID", "vlan", c.vlan || "", "number").min = "1";
        f.elements.vlan.max = "4094";
        field(
          f,
          "Parent interface",
          "parent_interface",
          c.parent_interface || "",
        );
        field(f, "Virtual service IP", "service_ip", c.service_ip || "");
        field(
          f,
          "Local fencing credential reference",
          "fencing_credential",
          c.fencing_credential || "",
        );
        const products = el("fieldset");
        products.append(el("legend", "Applications"));
        for (const p of (await api("applications")).applications.filter(
          (p) => p.product.id !== "netctl",
        )) {
          const label = el("label", undefined, "setting-row"),
            box = el("input");
          box.type = "checkbox";
          box.name = "products";
          box.value = p.product.id;
          box.checked = c.products?.includes(box.value) || false;
          label.append(box, el("span", p.product.name));
          products.append(label);
        }
        f.append(products);
        const output = el("section", undefined, "panel"),
          review = el("button", "Review cluster plan", "button primary"),
          save = el("button", "Save declaration", "button");
        save.type = "button";
        save.disabled = true;
        f.append(review, save);
        let reviewed;
        f.onsubmit = async (e) => {
          e.preventDefault();
          save.disabled = true;
          try {
            const v = Object.fromEntries(new FormData(f));
            const input = {
              name: v.name,
              vlan: Number(v.vlan),
              parent_interface: v.parent_interface,
              service_ip: v.service_ip,
              fencing_credential: v.fencing_credential,
              products: new FormData(f).getAll("products"),
            };
            for (const role of ["primary", "standby", "witness"])
              input[role] = {
                name: v[role + "_name"],
                address: v[role + "_address"],
                failure_domain: v[role + "_failure_domain"],
              };
            const result = await api("ha/plan", input);
            reviewed = input;
            output.replaceChildren(el("h2", "Readiness checks"));
            for (const message of result.blockers)
              output.append(el("p", message));
            save.disabled = false;
            status.textContent =
              "Plan reviewed. Automatic HA remains blocked until the displayed checks pass.";
          } catch (e) {
            status.textContent = e.message;
          }
        };
        f.addEventListener("input", () => {
          save.disabled = true;
          reviewed = null;
        });
        save.onclick = async () => {
          if (!reviewed) return;
          try {
            const result = await api("ha/configuration", {
              revision: data.revision,
              configuration: reviewed,
            });
            data.revision = result.revision;
            status.textContent =
              "Declaration saved. No infrastructure was changed.";
            save.disabled = true;
          } catch (e) {
            status.textContent = e.message;
          }
        };
        content.append(f, output);
      } else {
        const apps = (await api("applications")).applications;
        const id = path.split("/").at(-1),
          app = apps.find((a) => a.product.id === id);
        if (app) {
          document.querySelector("h1").textContent =
            "KagNode. " + app.product.name;
          content.append(link("Back to applications", "/", "arrow-left"));
          const panel = el("section", undefined, "panel");
          panel.append(
            el("h2", "Installation"),
            el(
              "p",
              app.installed
                ? "Existing installation detected. Its project-owned runtime and data are retained."
                : "Not installed on this node.",
            ),
            el("h3", "High availability"),
            el("p", app.product.ha_state),
            link("Review HA configuration", "/ha", "shield"),
          );
          content.append(panel);
          const services = await api(
            "applications/" + app.product.id + "/services",
          );
          const management = el("section", undefined, "panel stack");
          management.append(el("h2", "Native services"));
          if (services.native_actions_enabled) {
            for (const [unit, state] of Object.entries(services.states))
              management.append(el("p", unit + " · " + state));
            const controls = el("div", undefined, "actions");
            for (const operation of ["start", "stop", "restart"]) {
              const button = el(
                "button",
                operation[0].toUpperCase() + operation.slice(1),
                "button",
              );
              button.onclick = async () => {
                button.disabled = true;
                try {
                  const plan = await api(
                    "applications/" + app.product.id + "/service-plan",
                    { operation },
                  );
                  const dialog = el("dialog"),
                    box = el("div", undefined, "stack");
                  box.append(
                    el("h2", "Review " + operation),
                    el("p", plan.effect),
                  );
                  for (const unit of Object.keys(plan.units))
                    box.append(el("p", unit));
                  const confirm = el(
                      "button",
                      "Confirm " + operation,
                      "button primary",
                    ),
                    cancel = el("button", "Cancel", "button");
                  const request_id = crypto.randomUUID().replaceAll("-", "");
                  cancel.onclick = () => dialog.close();
                  confirm.onclick = async () => {
                    confirm.disabled = true;
                    try {
                      const job = await api(
                        "applications/" + app.product.id + "/service-apply",
                        { operation, expected_sha256: plan.sha256, request_id },
                      );
                      status.textContent =
                        job.state === "completed"
                          ? "Native operation completed."
                          : "The operation needs inspection before further changes.";
                      dialog.close();
                    } catch (error) {
                      box.append(el("p", error.message));
                    } finally {
                      confirm.disabled = false;
                    }
                  };
                  box.append(confirm, cancel);
                  dialog.append(box);
                  document.body.append(dialog);
                  dialog.addEventListener("close", () => dialog.remove(), {
                    once: true,
                  });
                  dialog.showModal();
                } catch (error) {
                  status.textContent = error.message;
                } finally {
                  button.disabled = false;
                }
              };
              controls.append(button);
            }
            management.append(controls);
            const refresh = el("button", "Refresh operation history", "button"),
              history = el("div");
            refresh.onclick = async () => {
              try {
                const data = await api(
                  "applications/" + app.product.id + "/operations",
                );
                history.replaceChildren();
                for (const job of data.operations)
                  history.append(el("p", job.id + " · " + job.state));
              } catch (error) {
                status.textContent = error.message;
              }
            };
            management.append(refresh, history);
          } else {
            management.append(
              el(
                "p",
                services.message || "Native service control is unavailable.",
              ),
            );
          }
          content.append(management);
        } else {
          const grid = el("div", undefined, "cards");
          for (const app of apps) {
            const card = link(app.product.name, app.url, app.product.icon);
            card.append(
              el(
                "small",
                app.installed ? "Installation detected" : "Not installed",
              ),
            );
            grid.append(card);
          }
          content.append(grid);
        }
      }
      if (
        !status.textContent.includes("saved") &&
        !status.textContent.includes("reviewed")
      )
        status.textContent = "";
      window.KagNodeControls?.enhance();
      window.KagNodeCore?.refresh();
    } catch (e) {
      if (status) status.textContent = e.message;
    }
  }
  render();
})();
