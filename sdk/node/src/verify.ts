// For API backends: Polaris access tokens (RFC 9068) checked locally against
// the JWKS; permissions come from entitlements only (ADR 0035).
import { createRemoteJWKSet, type JWTPayload, jwtVerify } from "jose";

export type AccessTokenClaims = JWTPayload & {
	sub: string;
	client_id: string;
	/** The Entitlements held at this API; empty when none, as for most M2M tokens. */
	entitlements: string[];
	sid?: string;
	roles?: string[];
};

/** 401: no valid access token. 403: valid, but missing an Entitlement. */
export class PolarisAuthError extends Error {
	readonly status: 401 | 403;
	constructor(status: 401 | 403, message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "PolarisAuthError";
		this.status = status;
	}
}

/**
 * Makes verifyAccessToken for one API. audience is the API's identifier;
 * tokens for any other API are refused.
 */
export function accessTokenVerifier({
	issuer,
	audience,
}: {
	issuer: string;
	audience: string;
}) {
	let jwks: Promise<ReturnType<typeof createRemoteJWKSet>> | undefined;
	const keys = () => {
		jwks ??= fetch(
			new URL(
				".well-known/openid-configuration",
				`${issuer.replace(/\/$/, "")}/`,
			),
		)
			.then(async (res) => {
				if (!res.ok) throw new Error(`polaris: discovery: ${res.status}`);
				return createRemoteJWKSet(new URL((await res.json()).jwks_uri));
			})
			.catch((err) => {
				jwks = undefined; // try again on the next token
				throw err;
			});
		return jwks;
	};

	/** The token's claims; throws PolarisAuthError(401) when it is not valid. */
	return async function verifyAccessToken(
		token: string | null | undefined,
	): Promise<AccessTokenClaims> {
		if (!token) throw new PolarisAuthError(401, "no access token");
		const jwks = await keys();
		try {
			const { payload } = await jwtVerify(token, jwks, {
				issuer,
				audience,
				typ: "at+jwt",
				algorithms: ["RS256"],
				requiredClaims: ["sub", "client_id"],
			});
			const entitlements = Array.isArray(payload.entitlements)
				? payload.entitlements
				: [];
			return { ...payload, entitlements } as AccessTokenClaims;
		} catch (err) {
			throw new PolarisAuthError(401, "invalid access token", { cause: err });
		}
	};
}

/** Throws PolarisAuthError(403) unless claims hold every one of names. */
export function requireEntitlements(
	claims: AccessTokenClaims,
	...names: string[]
) {
	const missing = names.filter((n) => !claims.entitlements.includes(n));
	if (missing.length)
		throw new PolarisAuthError(
			403,
			`missing entitlements: ${missing.join(", ")}`,
		);
}
