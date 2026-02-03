// @bun
// src/index.ts
function createAuth(config = {}) {
  return {
    async verifyCapability(params) {
      const { capability, resource, token } = params;
      if (config.ucan) {}
      if (config.resolveCapabilities) {
        const caps = await config.resolveCapabilities(token);
        return matchCapability(caps, capability, resource);
      }
      if (config.fallbackToSimple) {
        try {
          const payload = parseSimpleToken(token);
          return matchCapability(payload.att || [], capability, resource);
        } catch {
          return false;
        }
      }
      return false;
    },
    async createToken(params) {
      const { userId, capabilities, expiresIn = 3600 } = params;
      if (config.ucan) {}
      const payload = {
        iss: userId,
        aud: "affectively-auth",
        exp: Math.floor(Date.now() / 1000) + expiresIn,
        att: capabilities
      };
      return btoa(JSON.stringify(payload));
    },
    async createPrivateProof(params) {
      if (!config.zk) {
        throw new Error("ZK prover not configured. Install @affectively/zk");
      }
      throw new Error("ZK proofs not yet implemented");
    },
    async verifyPrivateProof(params) {
      if (!config.zk) {
        throw new Error("ZK prover not configured. Install @affectively/zk");
      }
      throw new Error("ZK verification not yet implemented");
    },
    async extractContext(request) {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return null;
      }
      const token = authHeader.slice(7);
      try {
        const payload = parseSimpleToken(token);
        return {
          userId: payload.iss,
          role: inferRole(payload.att || []),
          capabilities: payload.att || [],
          token
        };
      } catch {
        return null;
      }
    }
  };
}
function matchCapability(grants, required, resource) {
  for (const grant of grants) {
    if (grant.can !== required && grant.can !== "*") {
      continue;
    }
    if (matchResourcePattern(grant.with, resource)) {
      if (grant.constraints?.expiresAt) {
        if (new Date(grant.constraints.expiresAt) < new Date) {
          continue;
        }
      }
      return true;
    }
  }
  return false;
}
function matchResourcePattern(pattern, resource) {
  if (pattern === "*")
    return true;
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -1);
    return resource.startsWith(prefix);
  }
  return pattern === resource;
}
function inferRole(caps) {
  const hasAdmin = caps.some((c) => c.can === "admin" || c.can === "*");
  if (hasAdmin)
    return "admin";
  const hasWrite = caps.some((c) => c.can === "write");
  if (hasWrite)
    return "user";
  return "monitor";
}
function parseSimpleToken(token) {
  try {
    return JSON.parse(atob(token));
  } catch {
    throw new Error("Invalid token format");
  }
}
function createAuthMiddleware(auth) {
  return async (request, requiredCapability, resource) => {
    const context = await auth.extractContext(request);
    if (!context) {
      return { authorized: false, context: null };
    }
    const token = request.headers.get("Authorization")?.slice(7) || "";
    const authorized = await auth.verifyCapability({
      capability: requiredCapability,
      resource,
      token
    });
    return { authorized, context };
  };
}
var createAeonAuth = createAuth;
export {
  createAuthMiddleware,
  createAuth,
  createAeonAuth
};
