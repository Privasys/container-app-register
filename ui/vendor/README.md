# Vendored browser client

`privasys-auth-client.iife.js` is the Privasys sign-in and sealed-transport client, the IIFE build of the Privasys auth SDK (`window.Privasys.AuthFrame`).

| | |
|---|---|
| Source | github.com/Privasys/auth, `sdk/`, SDK 0.16.1 (tag `sdk-v0.16.1`; byte-identical to the build published at privasys.id/auth/) |
| Build | `npm run build` in `sdk/`, output `dist/privasys-auth-client.iife.js` |
| SHA-256 | `0ae963c8e71bbab4309e57e921b6ea1d27771851131143991f69162f3a1d640b` |

It is vendored rather than installed from a registry so the image carries one reviewed file instead of a package dependency. The client holds no keys: the session key lives in the Privasys ID iframe it opens, and the page exchanges plaintext with that iframe over `postMessage`.

To update: rebuild at a tagged SDK release, replace the file, and update this table.
