import { User } from "../types";
import { D1Database } from "@cloudflare/workers-types"

export const getUser = async (username: string, db: D1Database) => {
    const { results } = await db.prepare(
        'SELECT * FROM users WHERE username = ?'
    ).bind(username).all();

    return results?.[0] as User;
}

export const createUser = async (username: string, password: string, db: D1Database) => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const saltString = new TextDecoder().decode(salt);

    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + saltString));

    const hashString = new TextDecoder().decode(hash);

    const userInfo: Omit<User, 'userId'> = {
        username,
        password: hashString,
        salt: saltString
    }

    await db.prepare(
        'INSERT INTO users (username, password, salt) VALUES (?, ?, ?)'
    ).bind(userInfo.username, userInfo.password, userInfo.salt).run();

    return userInfo;
}