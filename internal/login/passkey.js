// base64url for WebAuthn ceremonies — the byte fields of options and
// responses — shared by the hosted login page and the account center SPA,
// which load this file from the same origin. No WebAuthn library (issue
// #106): the browser's own API is enough.
window.polaris ??= {};
polaris.b64url = {
  encode(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  },
  decode(s) {
    const bin = atob(s.replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  },
};
