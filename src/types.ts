export interface Session {
    sessionId: string
    sub: string // id of user / subject
    issued: number
    expires: number
    csrt: string
}

export type PartialSession = Omit<Session, 'issued' | 'expires' | 'csrt'>

export interface EncodeResult {
    token: string,
    expires: number,
    issued: number
    csrt: string
}

export interface DecodeResult {
    valid: boolean
    expired: boolean
    session?: Session;
}

