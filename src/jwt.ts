import { DecodeResult, EncodeResult, PartialSession, Session } from "./types";
// import { Context } from "hono";
// import { Environment } from "hono/dist/types";
// import { Schema } from "hono/dist/validator/schema";
import { decodeJwt, jwtVerify, SignJWT } from "jose";

// extend JWTClaimVerificationOptions to include csrf token
declare module "jose" {
    interface JWTClaimVerificationOptions {
        csrt: string;
    }
}

export const encodeSession = async (secretKey: CryptoKey | Uint8Array, partialSession: PartialSession, issuer: string, audience: string): Promise<EncodeResult> => {
    const issued = Date.now();
    const fifteenMinutesInMs = 15 * 60 * 1000;
    const expires = issued + fifteenMinutesInMs;

    const csrt = crypto.randomUUID();

    const encodedToken = await new SignJWT({
        sub: partialSession.userId,
        jti: partialSession.sessionId,
        csrt
    })
        .setProtectedHeader({ alg: "HS512" })
        .setIssuedAt(issued)
        .setIssuer(issuer)
        .setAudience(audience)
        .setExpirationTime(expires)
        .sign(secretKey);


    return {
        token: encodedToken,
        issued: issued,
        expires: expires,
        csrt: csrt
    };
}

export const decodeSession = async (secretKey: CryptoKey | Uint8Array, token: string, issuer: string, audience: string): Promise<DecodeResult> => {
    let result: Session;

    try {
        const partial = decodeJwt(token);

        const csrt = partial.csrf as string;

        const decoded = await jwtVerify(token, secretKey, {
            issuer,
            audience,
            csrt,
            algorithms: ["HS512"]
        });

        const session: Partial<Session> = {
            userId: decoded.payload.sub,
            sessionId: decoded.payload.jti,
            issued: decoded.payload.iat,
            expires: decoded.payload.exp,
            csrt: decoded.payload.csrt as string
        }

        result = session as Session;
    } catch (e) {
        return {
            valid: false,
            expired: true
        };
    }

    const isExpired = result.expires < Date.now();

    return {
        valid: true,
        expired: isExpired,
        session: result
    };
}

