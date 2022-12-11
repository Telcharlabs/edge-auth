import { Context } from 'hono';
import { Environment } from "hono/dist/types";
import { Schema } from 'hono/dist/validator/schema';
import { StatusCode } from 'hono/utils/http-status';
import { decodeJwt } from 'jose';
import { decodeSession } from '../jwt';
import { PartialSession } from '../types';

export const getIssuer = (c: Context<string, Environment>) => {
    const issuer = c.env.ISSUER;

    if (!issuer) {
        throw new Error('ISSUER enviroment variable not set');
    }

    return issuer;
}

export const getAudience = (c: Context<string, Environment>) => {
    return c.req.headers.get('Host');
}

export const getSessionPartial = async (c: Context<string, Environment, unknown>): Promise<PartialSession | undefined> => {
    const cookies = c.req.headers.get('Cookie')?.split(';');
    const jwt = cookies?.find(c => c.trim().startsWith('jwt='))?.split('=')[1];

    if (!jwt) {
        return undefined;
    }

    const session = decodeJwt(jwt);

    if (!session || !session.sub || !session.jti) {
        return undefined;
    }

    return {
        sub: session.sub,
        sessionId: session.jti
    }
}


export const jwtMiddleware = async (c: Context<string, Environment, Schema>, next: () => Promise<void>): Promise<void | Response> => {


    const cookies = c.req.headers.get('Cookie')?.split(';');

    const jwt = cookies?.find(c => c.trim().startsWith('jwt='))?.split('=')[1];

    const csrt = c.req.headers.get('X-CSRF-Token');

    if (!jwt || !csrt) {
        // Not authorized
        return c.text('Not authorized', 401);
    }

    // get orign of request
    const issuer = getIssuer(c);

    // get host of request
    const audience = getAudience(c);


    if (!audience) {
        return c.text('Not authorized', 401);
    }

    // decode jwt
    const decoded = await decodeSession(
        new TextEncoder().encode(c.env.JWT_SECRET),
        jwt,
        issuer,
        audience
    )

    if (!decoded.valid || !decoded.session || decoded.session.csrt !== csrt) {
        return c.text('Not authorized', 401);
    }

    if (decoded.expired) {
        return c.text('Session expired', 440 as StatusCode);
    }


    return await next()
}

