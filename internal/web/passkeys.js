// Passkeys on the login and account pages. Without this script, or in a
// browser without WebAuthn, the pages work as before: password only.
(() => {
  "use strict";
  if (!window.PublicKeyCredential || !navigator.credentials) return;

  const $ = (sel) => document.querySelector(sel);
  const bytes = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const b64 = (buf) => {
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const csrf = () => $("input[name=csrf]").value;

  // post sends a form to one of the passkey endpoints and returns its
  // JSON answer. A failure has an error message to show.
  const post = async (path, fields) => {
    const body = new URLSearchParams({ csrf: csrf(), ...fields });
    let res;
    try {
      res = await fetch(path, { method: "POST", body, credentials: "same-origin" });
    } catch {
      return { error: "Couldn't reach the server. Check your connection and try again." };
    }
    try {
      return await res.json();
    } catch {
      return { error: "Something went wrong. Reload the page and try again." };
    }
  };

  const show = (el, msg) => {
    el.textContent = msg;
    el.hidden = !msg;
  };

  const ids = (list) => (list || []).map((c) => ({ ...c, id: bytes(c.id) }));

  const credentialJSON = (cred, response) => JSON.stringify({
    id: cred.id,
    rawId: b64(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response,
  });

  // A user who cancels sees nothing; other failures show a message.
  const cancelled = (e) => e && (e.name === "NotAllowedError" || e.name === "AbortError");

  // ---- Login page ----
  const login = $("#passkey-login");
  if (login) {
    const error = $("#passkey-error");
    const authz = $("input[name=authz]");
    let pending = null;

    const signIn = async (mediation) => {
      const opts = await post("/passkey/login/options", {});
      if (opts.error) throw new Error(opts.error);
      const pk = opts.publicKey;
      pk.challenge = bytes(pk.challenge);
      pk.allowCredentials = ids(pk.allowCredentials);
      const ctl = new AbortController();
      pending = ctl;
      const cred = await navigator.credentials.get({ publicKey: pk, mediation, signal: ctl.signal });
      const r = cred.response;
      const out = await post("/passkey/login", {
        challenge: opts.challenge,
        authz: authz ? authz.value : "",
        credential: credentialJSON(cred, {
          clientDataJSON: b64(r.clientDataJSON),
          authenticatorData: b64(r.authenticatorData),
          signature: b64(r.signature),
          userHandle: r.userHandle ? b64(r.userHandle) : undefined,
        }),
      });
      if (out.error) throw new Error(out.error);
      window.location.assign(out.redirect);
    };

    login.hidden = false;
    $("#passkey-login-button").addEventListener("click", async () => {
      if (pending) pending.abort();
      show(error, "");
      try {
        await signIn(undefined);
      } catch (e) {
        if (!cancelled(e)) show(error, e.message);
      }
    });

    // Offer passkeys in the email field's autofill, where supported.
    if (PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable().then((ok) => {
        if (ok) signIn("conditional").catch((e) => { if (!cancelled(e)) show(error, e.message); });
      });
    }
  }

  // ---- Account page ----
  const add = $("#passkey-add");
  if (add) {
    const error = $("#passkey-add-error");
    const password = $("#passkey-password-field");
    add.hidden = false;
    add.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      show(error, "");
      const button = add.querySelector("button");
      button.disabled = true;
      try {
        const opts = await post("/passkey/register/options", { password: add.elements.password.value });
        if (opts.password) password.hidden = false;
        if (opts.error) throw new Error(opts.error);
        const pk = opts.publicKey;
        pk.challenge = bytes(pk.challenge);
        pk.user.id = bytes(pk.user.id);
        pk.excludeCredentials = ids(pk.excludeCredentials);
        const cred = await navigator.credentials.create({ publicKey: pk });
        const r = cred.response;
        const out = await post("/passkey/register", {
          challenge: opts.challenge,
          name: add.elements.name.value,
          credential: credentialJSON(cred, {
            clientDataJSON: b64(r.clientDataJSON),
            attestationObject: b64(r.attestationObject),
            transports: r.getTransports ? r.getTransports() : [],
          }),
        });
        if (out.error) throw new Error(out.error);
        window.location.assign(out.redirect);
      } catch (e) {
        if (e && e.name === "InvalidStateError") show(error, "This device already has a passkey for your account.");
        else if (!cancelled(e)) show(error, e.message);
      } finally {
        button.disabled = false;
      }
    });
  }
})();
