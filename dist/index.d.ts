/**
 * @affectively/auth
 *
 * Capability-based authorization using UCAN and Zero-Knowledge proofs.
 *
 * @example
 * ```typescript
 * import { createAuth } from '@affectively/auth';
 *
 * // Basic setup (fallback mode)
 * const auth = createAuth({ fallbackToSimple: true });
 *
 * // Create a token
 * const token = await auth.createToken({
 *   userId: 'user-123',
 *   capabilities: [
 *     { can: 'read', with: '*' },
 *     { can: 'write', with: '/blog/*' },
 *   ],
 *   expiresIn: 3600,
 * });
 *
 * // Verify capability
 * const canEdit = await auth.verifyCapability({
 *   capability: 'write',
 *   resource: '/blog/my-post',
 *   token,
 * });
 * ```
 */
/**
 * Standard capability types
 * Use generic types or define your own
 */
export type DefaultCapability = 'read' | 'write' | 'delete' | 'admin' | '*';
/**
 * Capability with resource pattern
 */
export interface CapabilityGrant<T extends string = DefaultCapability> {
    /** The capability being granted */
    can: T;
    /** Resource pattern (e.g., "/blog/*", "*") */
    with: string;
    /** Optional constraints */
    constraints?: {
        /** Time-based expiry */
        expiresAt?: string;
        /** IP restrictions */
        allowedIPs?: string[];
        /** Rate limits */
        rateLimit?: {
            requests: number;
            window: number;
        };
    };
}
/**
 * UCAN token payload
 */
export interface UCANPayload<T extends string = DefaultCapability> {
    /** Issuer DID */
    iss: string;
    /** Audience */
    aud: string;
    /** Expiration timestamp */
    exp: number;
    /** Not before timestamp */
    nbf?: number;
    /** Nonce for replay protection */
    nnc?: string;
    /** Capabilities granted */
    att: CapabilityGrant<T>[];
    /** Proof chain (delegated capabilities) */
    prf?: string[];
    /** Facts (additional claims) */
    fct?: Record<string, unknown>;
}
/**
 * Authorization context
 */
export interface AuthContext<T extends string = DefaultCapability> {
    /** User or agent ID */
    userId: string;
    /** User role */
    role: 'user' | 'assistant' | 'monitor' | 'admin';
    /** Granted capabilities */
    capabilities: CapabilityGrant<T>[];
    /** Original token */
    token: string;
    /** ZK proof (if using private auth) */
    zkProof?: unknown;
}
/**
 * Auth configuration
 */
export interface AuthConfig<T extends string = DefaultCapability> {
    /** UCAN client instance */
    ucan?: unknown;
    /** ZK prover instance */
    zk?: unknown;
    /** Fallback to simple token auth */
    fallbackToSimple?: boolean;
    /** Custom capability resolver */
    resolveCapabilities?: (token: string) => Promise<CapabilityGrant<T>[]>;
}
/**
 * Create auth handler
 *
 * Integrates with @affectively/ucan and @affectively/zk when available,
 * falls back to simple token verification otherwise.
 */
export declare function createAuth<T extends string = DefaultCapability>(config?: AuthConfig<T>): {
    /**
     * Verify a capability for a given resource
     */
    verifyCapability(params: {
        capability: T;
        resource: string;
        token: string;
    }): Promise<boolean>;
    /**
     * Create a capability token for a user
     */
    createToken(params: {
        userId: string;
        capabilities: CapabilityGrant<T>[];
        expiresIn?: number;
    }): Promise<string>;
    /**
     * Create a ZK proof for private capability verification
     */
    createPrivateProof(params: {
        capability: T;
        resource: string;
        token: string;
    }): Promise<unknown>;
    /**
     * Verify a ZK proof without revealing the token
     */
    verifyPrivateProof(params: {
        capability: T;
        resource: string;
        proof: unknown;
    }): Promise<boolean>;
    /**
     * Extract auth context from request
     */
    extractContext(request: Request): Promise<AuthContext<T> | null>;
};
/**
 * Middleware for protecting routes
 */
export declare function createAuthMiddleware<T extends string = DefaultCapability>(auth: ReturnType<typeof createAuth<T>>): (request: Request, requiredCapability: T, resource: string) => Promise<{
    authorized: boolean;
    context: AuthContext<T> | null;
}>;
export declare const createAeonAuth: typeof createAuth;
export type AeonAuthConfig = AuthConfig;
//# sourceMappingURL=index.d.ts.map