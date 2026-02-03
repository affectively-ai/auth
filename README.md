# @affectively/auth

Capability-based authorization using UCAN and Zero-Knowledge proofs.

## Features

- **UCAN Integration** - Decentralized capability-based authorization
- **ZK Proofs** - Verify capabilities without revealing tokens
- **Resource Patterns** - Wildcard support (`/blog/*`, `*`)
- **Fallback Mode** - Works without UCAN/ZK libraries installed
- **TypeScript First** - Full type safety

## Installation

```bash
bun add @affectively/auth

# Optional: For full UCAN support
bun add @affectively/ucan

# Optional: For ZK proof support
bun add @affectively/zk
```

## Quick Start

```typescript
import { createAuth } from '@affectively/auth';

// Basic setup (fallback mode)
const auth = createAuth({
  fallbackToSimple: true,
});

// Create a token
const token = await auth.createToken({
  userId: 'user-123',
  capabilities: [
    { can: 'read', with: '*' },
    { can: 'write', with: '/blog/*' },
  ],
  expiresIn: 3600, // 1 hour
});

// Verify capability
const canEdit = await auth.verifyCapability({
  capability: 'write',
  resource: '/blog/my-post',
  token,
});

console.log(canEdit); // true
```

## With UCAN Library

```typescript
import { createAuth } from '@affectively/auth';
import { createUCANClient } from '@affectively/ucan';

const auth = createAuth({
  ucan: createUCANClient({
    issuer: 'did:key:z6Mk...',
  }),
});

// Now uses proper UCAN tokens
const token = await auth.createToken({
  userId: 'did:key:z6Mk...',
  capabilities: [
    { can: 'admin', with: '/settings' },
  ],
});
```

## With ZK Proofs

Zero-knowledge proofs let you verify capabilities without revealing the full token:

```typescript
import { createAuth } from '@affectively/auth';
import { createUCANClient } from '@affectively/ucan';
import { createZKProver } from '@affectively/zk';

const auth = createAuth({
  ucan: createUCANClient({ issuer: myDID }),
  zk: createZKProver({ circuit: 'capability-verify' }),
});

// Create a ZK proof
const proof = await auth.createPrivateProof({
  capability: 'read',
  resource: '/private/document',
  token: userToken,
});

// Verify without seeing the token
const isValid = await auth.verifyPrivateProof({
  capability: 'read',
  resource: '/private/document',
  proof,
});
```

## Custom Capabilities

Define your own capability types:

```typescript
type MyCapability = 'read' | 'write' | 'delete' | 'admin' | '*';

const auth = createAuth<MyCapability>({
  fallbackToSimple: true,
});

await auth.verifyCapability({
  capability: 'delete',
  resource: '/posts/123',
  token,
});
```

## Resource Patterns

```typescript
// Exact match
{ can: 'write', with: '/blog/my-post' }

// Wildcard (all under /blog/)
{ can: 'write', with: '/blog/*' }

// Global (everything)
{ can: 'read', with: '*' }
```

## Middleware

Protect your routes with the auth middleware:

```typescript
import { createAuth, createAuthMiddleware } from '@affectively/auth';

const auth = createAuth({ /* config */ });
const middleware = createAuthMiddleware(auth);

// In your request handler
async function handler(request: Request) {
  const { authorized, context } = await middleware(
    request,
    'write',
    '/blog/my-post'
  );

  if (!authorized) {
    return new Response('Forbidden', { status: 403 });
  }

  // context.userId, context.role, context.capabilities available
  return handleRequest(request, context);
}
```

## Extract Auth Context

```typescript
const auth = createAuth({ /* config */ });

async function handler(request: Request) {
  const context = await auth.extractContext(request);

  if (!context) {
    return new Response('Unauthorized', { status: 401 });
  }

  console.log(context.userId);       // 'user-123'
  console.log(context.role);         // inferred from capabilities
  console.log(context.capabilities); // [{ can: 'write', with: '/blog/*' }]
}
```

## API Reference

### `createAuth(config)`

Create an auth handler instance.

**Config options:**
- `ucan` - UCAN client instance (from `@affectively/ucan`)
- `zk` - ZK prover instance (from `@affectively/zk`)
- `fallbackToSimple` - Use simple base64 tokens when UCAN unavailable
- `resolveCapabilities` - Custom capability resolver function

### `auth.verifyCapability({ capability, resource, token })`

Verify if a token grants a capability for a resource.

### `auth.createToken({ userId, capabilities, expiresIn })`

Create a new capability token.

### `auth.createPrivateProof({ capability, resource, token })`

Create a ZK proof for private verification.

### `auth.verifyPrivateProof({ capability, resource, proof })`

Verify a ZK proof without seeing the original token.

### `auth.extractContext(request)`

Extract auth context from a Request's Authorization header.

### `createAuthMiddleware(auth)`

Create middleware for protecting routes.

## License

MIT - AFFECTIVELY
