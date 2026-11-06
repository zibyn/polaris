import { createPolaris } from "@zibyn/polaris";

// The defaults point at the fake Polaris that examples/smoke.ts starts.
export const polaris = createPolaris({
	issuer: process.env.POLARIS_ISSUER ?? "http://127.0.0.1:4999",
	clientId: process.env.POLARIS_CLIENT_ID ?? "web-app",
	clientSecret: process.env.POLARIS_CLIENT_SECRET ?? "s3cret",
	baseURL: process.env.BASE_URL ?? "http://localhost:3000",
	secret: process.env.POLARIS_SECRET ?? "dev-only-secret-of-at-least-32-chars",
});
