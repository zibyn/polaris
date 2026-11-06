// The SDK's session cookie: encrypted with the integrator's secret, split
// into numbered chunks when it outgrows one cookie.
import { EncryptJWT, type JWTPayload, jwtDecrypt } from "jose";

// A browser keeps about 4096 bytes per cookie, name and attributes included.
const chunkSize = 3800;

export type CookieOptions = { secure: boolean; path: string };

export async function deriveKey(secret: string) {
	if (secret.length < 32)
		throw new Error("polaris: secret must be at least 32 characters");
	const raw = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		"HKDF",
		false,
		["deriveBits"],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(),
			info: new TextEncoder().encode("polaris session cookie"),
		},
		raw,
		256,
	);
	return new Uint8Array(bits);
}

export const seal = (payload: JWTPayload, key: Uint8Array, maxAge: number) =>
	new EncryptJWT(payload)
		.setProtectedHeader({ alg: "dir", enc: "A256GCM" })
		.setExpirationTime(Math.floor(Date.now() / 1000) + maxAge)
		.encrypt(key);

/** The payload, or null when the value is missing, tampered with, from another secret or expired. */
export async function unseal<T>(
	value: string | undefined,
	key: Uint8Array,
): Promise<T | null> {
	if (!value) return null;
	try {
		return (await jwtDecrypt(value, key)).payload as T;
	} catch {
		return null;
	}
}

export function parseCookies(header: string | null) {
	const jar = new Map<string, string>();
	for (const part of (header ?? "").split(";")) {
		const i = part.indexOf("=");
		if (i > 0) jar.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
	}
	return jar;
}

const isChunk = (name: string, cookie: string) =>
	cookie === name ||
	new RegExp(`^${name.replaceAll(".", "\\.")}\\.\\d+$`).test(cookie);

/** Reads name, whole or reassembled from name.0, name.1, … */
export function readChunked(jar: Map<string, string>, name: string) {
	if (jar.has(name)) return jar.get(name);
	let value = "";
	for (let i = 0; jar.has(`${name}.${i}`); i++)
		value += jar.get(`${name}.${i}`);
	return value || undefined;
}

export function serialize(
	name: string,
	value: string,
	maxAge: number,
	o: CookieOptions,
) {
	return `${name}=${value}; Path=${o.path}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${o.secure ? "; Secure" : ""}`;
}

/**
 * The Set-Cookie values that store value (or, when null, clear it) under
 * name, also clearing the chunks of it the request had that are not reused.
 */
export function writeChunked(
	jar: Map<string, string>,
	name: string,
	value: string | null,
	maxAge: number,
	o: CookieOptions,
) {
	const out = new Map<string, string>();
	for (const cookie of jar.keys())
		if (isChunk(name, cookie)) out.set(cookie, serialize(cookie, "", 0, o));
	if (value !== null) {
		if (value.length <= chunkSize)
			out.set(name, serialize(name, value, maxAge, o));
		else
			for (let i = 0; i * chunkSize < value.length; i++) {
				out.set(
					`${name}.${i}`,
					serialize(
						`${name}.${i}`,
						value.slice(i * chunkSize, (i + 1) * chunkSize),
						maxAge,
						o,
					),
				);
			}
	}
	return [...out.values()];
}

/** The Cookie request header after applying setCookies to jar. */
export function applyToJar(jar: Map<string, string>, setCookies: string[]) {
	const next = new Map(jar);
	for (const c of setCookies) {
		const [pair] = c.split(";");
		const i = pair.indexOf("=");
		const value = pair.slice(i + 1);
		if (/Max-Age=0(;|$)/.test(c)) next.delete(pair.slice(0, i));
		else next.set(pair.slice(0, i), value);
	}
	return [...next].map(([k, v]) => `${k}=${v}`).join("; ");
}
