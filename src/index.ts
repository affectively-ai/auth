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
export type DefaultCapability =
  | 'read'     // View content
  | 'write'    // Edit content
  | 'delete'   // Remove content
  | 'admin'    // Administrative access
  | '*';       // Full access

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
    rateLimit?: { requests: number; window: number };
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
  ucan?: unknown; // UCANClient when @affectively/ucan is available

  /** ZK prover instance */
  zk?: unknown; // ZKProver when @affectively/zk is available

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
export function createAuth<T extends string = DefaultCapability>(config: AuthConfig<T> = {}) {
  return {
    /**
     * Verify a capability for a given resource
     */
    async verifyCapability(params: {
      capability: T;
      resource: string;
      token: string;
    }): Promise<boolean> {
      const { capability, resource, token } = params;

      // If UCAN client is available, use it
      if (config.ucan) {
        // TODO: Use @affectively/ucan when available
        // return await config.ucan.verify(token, { can: capability, with: resource });
      }

      // Fallback to custom resolver
      if (config.resolveCapabilities) {
        const caps = await config.resolveCapabilities(token);
        return matchCapability(caps, capability, resource);
      }

      // Simple fallback - parse JWT-like token
      if (config.fallbackToSimple) {
        try {
          const payload = parseSimpleToken<T>(token);
          return matchCapability(payload.att || [], capability, resource);
        } catch {
          return false;
        }
      }

      return false;
    },

    /**
     * Create a capability token for a user
     */
    async createToken(params: {
      userId: string;
      capabilities: CapabilityGrant<T>[];
      expiresIn?: number;
    }): Promise<string> {
      const { userId, capabilities, expiresIn = 3600 } = params;

      // If UCAN client is available, use it
      if (config.ucan) {
        // TODO: Use @affectively/ucan when available
        // return await config.ucan.issue({ sub: userId, att: capabilities, exp: ... });
      }

      // Simple fallback - create basic token
      const payload: UCANPayload<T> = {
        iss: userId,
        aud: 'affectively-auth',
        exp: Math.floor(Date.now() / 1000) + expiresIn,
        att: capabilities,
      };

      // Base64 encode (NOT secure - just for dev fallback)
      return btoa(JSON.stringify(payload));
    },

    /**
     * Create a ZK proof for private capability verification
     */
    async createPrivateProof(params: {
      capability: T;
      resource: string;
      token: string;
    }): Promise<unknown> {
      if (!config.zk) {
        throw new Error('ZK prover not configured. Install @affectively/zk');
      }

      // TODO: Use @affectively/zk when available
      // return await config.zk.prove({
      //   circuit: 'capability-verify',
      //   inputs: { capability: params.capability, resource: params.resource },
      //   witness: params.token,
      // });

      throw new Error('ZK proofs not yet implemented');
    },

    /**
     * Verify a ZK proof without revealing the token
     */
    async verifyPrivateProof(params: {
      capability: T;
      resource: string;
      proof: unknown;
    }): Promise<boolean> {
      if (!config.zk) {
        throw new Error('ZK prover not configured. Install @affectively/zk');
      }

      // TODO: Use @affectively/zk when available
      // return await config.zk.verify(params.proof, {
      //   circuit: 'capability-verify',
      //   publicInputs: { capability: params.capability, resource: params.resource },
      // });

      throw new Error('ZK verification not yet implemented');
    },

    /**
     * Extract auth context from request
     */
    async extractContext(request: Request): Promise<AuthContext<T> | null> {
      const authHeader = request.headers.get('Authorization');
      if (!authHeader?.startsWith('Bearer ')) {
        return null;
      }

      const token = authHeader.slice(7);

      try {
        const payload = parseSimpleToken<T>(token);
        return {
          userId: payload.iss,
          role: inferRole(payload.att || []),
          capabilities: payload.att || [],
          token,
        };
      } catch {
        return null;
      }
    },
  };
}

/**
 * Match a capability against granted capabilities
 */
function matchCapability<T extends string>(
  grants: CapabilityGrant<T>[],
  required: T,
  resource: string
): boolean {
  for (const grant of grants) {
    // Check capability match
    if (grant.can !== required && grant.can !== '*') {
      continue;
    }

    // Check resource pattern match
    if (matchResourcePattern(grant.with, resource)) {
      // Check constraints
      if (grant.constraints?.expiresAt) {
        if (new Date(grant.constraints.expiresAt) < new Date()) {
          continue; // Expired
        }
      }

      return true;
    }
  }

  return false;
}

/**
 * Match resource pattern (supports wildcards)
 */
function matchResourcePattern(pattern: string, resource: string): boolean {
  if (pattern === '*') return true;

  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1);
    return resource.startsWith(prefix);
  }

  return pattern === resource;
}

/**
 * Infer role from capabilities
 */
function inferRole<T extends string>(caps: CapabilityGrant<T>[]): AuthContext['role'] {
  const hasAdmin = caps.some((c) => c.can === 'admin' || c.can === '*');
  if (hasAdmin) return 'admin';

  const hasWrite = caps.some((c) => c.can === 'write');
  if (hasWrite) return 'user';

  return 'monitor';
}

/**
 * Parse simple base64 token (fallback only)
 */
function parseSimpleToken<T extends string>(token: string): UCANPayload<T> {
  try {
    return JSON.parse(atob(token));
  } catch {
    throw new Error('Invalid token format');
  }
}

/**
 * Middleware for protecting routes
 */
export function createAuthMiddleware<T extends string = DefaultCapability>(
  auth: ReturnType<typeof createAuth<T>>
) {
  return async (
    request: Request,
    requiredCapability: T,
    resource: string
  ): Promise<{ authorized: boolean; context: AuthContext<T> | null }> => {
    const context = await auth.extractContext(request);

    if (!context) {
      return { authorized: false, context: null };
    }

    const token = request.headers.get('Authorization')?.slice(7) || '';
    const authorized = await auth.verifyCapability({
      capability: requiredCapability,
      resource,
      token,
    });

    return { authorized, context };
  };
}

// Legacy alias for backwards compatibility
export const createAeonAuth = createAuth;
export type AeonAuthConfig = AuthConfig;
