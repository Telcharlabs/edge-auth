import { Context } from 'hono';
import { Environment } from "hono/dist/types";
import { Schema } from "hono/dist/validator/schema";
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

export const getSessionPartial = async (c: Context<string, Environment, Schema>): Promise<PartialSession | undefined> => {
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
        userId: session.sub,
        sessionId: session.jti
    }
}


export const jwtMiddleware = async (c: Context<string, Environment, Schema>, next: () => Promise<void>): Promise<void | Response> => {


    const cookies = c.req.headers.get('Cookie')?.split(';');

    const jwt = cookies?.find(c => c.trim().startsWith('jwt='))?.split('=')[1];

    const csrt = c.req.headers.get('X-CSRF-Token');

    if (!jwt || !csrt) {
        // Not authorized
        return new Response('Not authorized', { status: 401 });
    }

    // get orign of request
    const issuer = getIssuer(c);

    // get host of request
    const audience = getAudience(c);


    if (!audience) {

        return new Response('Not Authorized', { status: 400 });
    }

    // decode jwt
    const decoded = await decodeSession(
        new TextEncoder().encode(c.env.JWT_SECRET),
        jwt,
        issuer,
        audience
    )

    console.log('decoded', decoded);

    if (!decoded.valid || !decoded.session || decoded.session.csrt !== csrt) {
        return new Response('Not authorized', { status: 401 });
    }

    console.log('here')

    if (decoded.expired) {
        return new Response('Session expired', { status: 440 });
    }

    console.log('here')


    return await next()
}

