// Passkey sign-in/registration and Turnstile reset. Native WebAuthn JSON helpers, no dependencies.
(function () {
  var hx = { 'HX-Request': 'true' };

  function post(url, body, type) {
    var h = Object.assign({}, hx);
    if (type) h['Content-Type'] = type;
    return fetch(url, { method: 'POST', headers: h, body: body, credentials: 'same-origin' });
  }

  async function failText(res) {
    var t = await res.text();
    var d = document.createElement('div');
    d.innerHTML = t;
    return d.textContent || ('Error ' + res.status);
  }

  var login = document.getElementById('passkey-login');
  if (login) {
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseRequestOptionsFromJSON) {
      login.hidden = true;
    }
    login.addEventListener('click', async function () {
      var msg = document.getElementById('msg');
      msg.textContent = '';
      try {
        var begin = await post('/login/passkey/begin');
        if (!begin.ok) throw new Error(await failText(begin));
        var b = await begin.json();
        var cred = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(b.options) });
        var fin = await post('/login/passkey/finish?id=' + encodeURIComponent(b.id), JSON.stringify(cred.toJSON()), 'application/json');
        if (fin.status === 204) {
          location.href = fin.headers.get('HX-Redirect') || '/';
          return;
        }
        throw new Error(await failText(fin));
      } catch (e) {
        msg.textContent = e && e.name === 'NotAllowedError' ? 'Passkey sign-in was cancelled.' : (e.message || 'Passkey sign-in failed.');
      }
    });
  }

  var add = document.getElementById('passkey-add-form');
  if (add) {
    add.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      var msg = document.getElementById('passkey-msg');
      msg.textContent = '';
      var data = new FormData(add);
      try {
        var begin = await post('/security/passkeys/begin', new URLSearchParams(data), 'application/x-www-form-urlencoded');
        if (!begin.ok) throw new Error(await failText(begin));
        var b = await begin.json();
        var cred = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(b.options) });
        var q = '?id=' + encodeURIComponent(b.id) + '&name=' + encodeURIComponent(data.get('name') || '');
        var fin = await post('/security/passkeys/finish' + q, JSON.stringify(cred.toJSON()), 'application/json');
        if (!fin.ok) throw new Error(await failText(fin));
        location.reload();
      } catch (e) {
        msg.textContent = e && e.name === 'NotAllowedError' ? 'Passkey setup was cancelled.' : (e.message || 'Passkey setup failed.');
      }
    });
  }

  // A Turnstile token is single use: get a fresh one after every failed sign-in.
  document.body.addEventListener('htmx:afterRequest', function (ev) {
    if (ev.detail.elt.id === 'login-form' && !ev.detail.successful && window.turnstile) window.turnstile.reset();
  });
})();
