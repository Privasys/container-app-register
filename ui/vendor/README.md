# Vendored browser client

`privasys-auth-client.iife.js` is the Privasys sign-in and sealed-transport client, the IIFE build of the Privasys auth SDK (`window.Privasys.AuthFrame`).

| | |
|---|---|
| Source | github.com/Privasys/auth, `sdk/`, SDK 0.15.0 (tag `sdk-v0.15.0`; byte-identical to the build published at privasys.id/auth/) |
| Build | `npm run build` in `sdk/`, output `dist/privasys-auth-client.iife.js` |
| SHA-256 | `9e2af66111d5bbf814ab202f608470fe483ed31c647a01b3b8c067ec93517144` |

It is vendored rather than installed from a registry so the image carries one reviewed file instead of a package dependency. The client holds no keys: the session key lives in the Privasys ID iframe it opens, and the page exchanges plaintext with that iframe over `postMessage`.

To update: rebuild at a tagged SDK release, replace the file, and update this table.
