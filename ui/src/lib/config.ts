// Runtime configuration.
//
// The register serves /app-config.js with the host it is being served as.
// On a custom domain the page's own address is the adopter's name, but the
// sealed session must be attested against the platform hostname, so the page
// never derives it from its own location.

declare global {
    interface Window {
        __REGISTER__?: {
            appHost: string;
            environment: 'test' | 'production';
            version?: string;
            name?: string;
            clientId?: string;
            /** Whether the register is on the platform, where people sign in
             *  with their wallet and every request is sealed. */
            session?: boolean;
        };
    }
}

const runtime = window.__REGISTER__;
const onTest = runtime ? runtime.environment === 'test' : location.hostname.endsWith('.test.privasys.org');

/** On the platform people sign in with their wallet. Anywhere else the
 *  register is a development instance and takes a stand-in token. */
export const sealed = runtime?.session === true;

export const authConfig = {
    apiBase: onTest ? 'https://api-test.privasys.org' : 'https://api.privasys.org',
    authOrigin: 'https://privasys.id',
    rpId: 'privasys.id',
    // The register's own client at the identity provider: the subject it
    // sees for a person is its own, shared with no other service.
    clientId: runtime?.clientId || 'register',
    appName: 'Register',
    brokerUrl: 'wss://relay.privasys.org/relay',
    appHost: runtime?.appHost ?? location.host
};

export const appVersion = runtime?.version ?? 'dev';
export const instanceName = runtime?.name ?? 'register';

/** Where anyone can check the attestation of the enclave serving this page. */
export const verifyUrl = sealed
    ? `https://explorer.privasys.org/?app=${encodeURIComponent(authConfig.appHost.split('.')[0])}${onTest ? '&env=test' : ''}`
    : '';
