import { describe, test, expect, beforeEach } from 'bun:test';
import {
  createAuth,
  createAuthMiddleware,
  type CapabilityGrant,
  type AuthContext,
  type DefaultCapability,
} from './index';

describe('@affectively/auth', () => {
  describe('createAuth', () => {
    describe('with fallbackToSimple mode', () => {
      const auth = createAuth({ fallbackToSimple: true });

      test('creates a valid token', async () => {
        const token = await auth.createToken({
          userId: 'user-123',
          capabilities: [
            { can: 'read', with: '*' },
            { can: 'write', with: '/blog/*' },
          ],
        });

        expect(token).toBeDefined();
        expect(typeof token).toBe('string');
        expect(token.length).toBeGreaterThan(0);
      });

      test('token contains correct payload', async () => {
        const token = await auth.createToken({
          userId: 'user-456',
          capabilities: [{ can: 'admin', with: '*' }],
          expiresIn: 7200,
        });

        const payload = JSON.parse(atob(token));
        expect(payload.iss).toBe('user-456');
        expect(payload.aud).toBe('affectively-auth');
        expect(payload.att).toHaveLength(1);
        expect(payload.att[0].can).toBe('admin');
        expect(payload.att[0].with).toBe('*');
        expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
      });

      test('verifies exact capability match', async () => {
        const token = await auth.createToken({
          userId: 'user-123',
          capabilities: [{ can: 'write', with: '/posts/123' }],
        });

        const canWrite = await auth.verifyCapability({
          capability: 'write',
          resource: '/posts/123',
          token,
        });

        expect(canWrite).toBe(true);
      });

      test('rejects non-matching capability', async () => {
        const token = await auth.createToken({
          userId: 'user-123',
          capabilities: [{ can: 'read', with: '/posts/123' }],
        });

        const canWrite = await auth.verifyCapability({
          capability: 'write',
          resource: '/posts/123',
          token,
        });

        expect(canWrite).toBe(false);
      });

      test('rejects non-matching resource', async () => {
        const token = await auth.createToken({
          userId: 'user-123',
          capabilities: [{ can: 'write', with: '/posts/123' }],
        });

        const canWrite = await auth.verifyCapability({
          capability: 'write',
          resource: '/posts/456',
          token,
        });

        expect(canWrite).toBe(false);
      });
    });

    describe('resource pattern matching', () => {
      const auth = createAuth({ fallbackToSimple: true });

      test('matches global wildcard (*)', async () => {
        const token = await auth.createToken({
          userId: 'admin',
          capabilities: [{ can: 'read', with: '*' }],
        });

        const canRead1 = await auth.verifyCapability({
          capability: 'read',
          resource: '/any/path/here',
          token,
        });

        const canRead2 = await auth.verifyCapability({
          capability: 'read',
          resource: '/completely/different',
          token,
        });

        expect(canRead1).toBe(true);
        expect(canRead2).toBe(true);
      });

      test('matches path wildcard (/path/*)', async () => {
        const token = await auth.createToken({
          userId: 'editor',
          capabilities: [{ can: 'write', with: '/blog/*' }],
        });

        const canWriteBlog = await auth.verifyCapability({
          capability: 'write',
          resource: '/blog/my-post',
          token,
        });

        const canWriteNested = await auth.verifyCapability({
          capability: 'write',
          resource: '/blog/drafts/new-post',
          token,
        });

        const canWriteOther = await auth.verifyCapability({
          capability: 'write',
          resource: '/pages/about',
          token,
        });

        expect(canWriteBlog).toBe(true);
        expect(canWriteNested).toBe(true);
        expect(canWriteOther).toBe(false);
      });

      test('matches capability wildcard (*)', async () => {
        const token = await auth.createToken({
          userId: 'superadmin',
          capabilities: [{ can: '*', with: '/settings' }],
        });

        const canRead = await auth.verifyCapability({
          capability: 'read',
          resource: '/settings',
          token,
        });

        const canWrite = await auth.verifyCapability({
          capability: 'write',
          resource: '/settings',
          token,
        });

        const canDelete = await auth.verifyCapability({
          capability: 'delete',
          resource: '/settings',
          token,
        });

        expect(canRead).toBe(true);
        expect(canWrite).toBe(true);
        expect(canDelete).toBe(true);
      });
    });

    describe('multiple capabilities', () => {
      const auth = createAuth({ fallbackToSimple: true });

      test('checks all granted capabilities', async () => {
        const token = await auth.createToken({
          userId: 'user',
          capabilities: [
            { can: 'read', with: '*' },
            { can: 'write', with: '/blog/*' },
            { can: 'admin', with: '/settings' },
          ],
        });

        expect(
          await auth.verifyCapability({ capability: 'read', resource: '/anything', token })
        ).toBe(true);
        expect(
          await auth.verifyCapability({ capability: 'write', resource: '/blog/post', token })
        ).toBe(true);
        expect(
          await auth.verifyCapability({ capability: 'admin', resource: '/settings', token })
        ).toBe(true);
        expect(
          await auth.verifyCapability({ capability: 'write', resource: '/pages/home', token })
        ).toBe(false);
        expect(
          await auth.verifyCapability({ capability: 'admin', resource: '/other', token })
        ).toBe(false);
      });
    });

    describe('extractContext', () => {
      const auth = createAuth({ fallbackToSimple: true });

      test('extracts context from valid Authorization header', async () => {
        const token = await auth.createToken({
          userId: 'user-789',
          capabilities: [
            { can: 'read', with: '*' },
            { can: 'write', with: '/blog/*' },
          ],
        });

        const request = new Request('https://example.com/api', {
          headers: { Authorization: `Bearer ${token}` },
        });

        const context = await auth.extractContext(request);

        expect(context).not.toBeNull();
        expect(context!.userId).toBe('user-789');
        expect(context!.capabilities).toHaveLength(2);
        expect(context!.token).toBe(token);
      });

      test('returns null for missing Authorization header', async () => {
        const request = new Request('https://example.com/api');
        const context = await auth.extractContext(request);

        expect(context).toBeNull();
      });

      test('returns null for non-Bearer token', async () => {
        const request = new Request('https://example.com/api', {
          headers: { Authorization: 'Basic dXNlcjpwYXNz' },
        });

        const context = await auth.extractContext(request);

        expect(context).toBeNull();
      });

      test('returns null for invalid token', async () => {
        const request = new Request('https://example.com/api', {
          headers: { Authorization: 'Bearer invalid-token' },
        });

        const context = await auth.extractContext(request);

        expect(context).toBeNull();
      });

      test('infers admin role from admin capability', async () => {
        const token = await auth.createToken({
          userId: 'admin-user',
          capabilities: [{ can: 'admin', with: '*' }],
        });

        const request = new Request('https://example.com/api', {
          headers: { Authorization: `Bearer ${token}` },
        });

        const context = await auth.extractContext(request);

        expect(context!.role).toBe('admin');
      });

      test('infers admin role from wildcard capability', async () => {
        const token = await auth.createToken({
          userId: 'super-admin',
          capabilities: [{ can: '*', with: '*' }],
        });

        const request = new Request('https://example.com/api', {
          headers: { Authorization: `Bearer ${token}` },
        });

        const context = await auth.extractContext(request);

        expect(context!.role).toBe('admin');
      });

      test('infers user role from write capability', async () => {
        const token = await auth.createToken({
          userId: 'editor',
          capabilities: [{ can: 'write', with: '/blog/*' }],
        });

        const request = new Request('https://example.com/api', {
          headers: { Authorization: `Bearer ${token}` },
        });

        const context = await auth.extractContext(request);

        expect(context!.role).toBe('user');
      });

      test('infers monitor role from read-only capability', async () => {
        const token = await auth.createToken({
          userId: 'viewer',
          capabilities: [{ can: 'read', with: '*' }],
        });

        const request = new Request('https://example.com/api', {
          headers: { Authorization: `Bearer ${token}` },
        });

        const context = await auth.extractContext(request);

        expect(context!.role).toBe('monitor');
      });
    });

    describe('without fallback mode', () => {
      const auth = createAuth({ fallbackToSimple: false });

      test('returns false when no verification method available', async () => {
        const token = 'some-token';

        const result = await auth.verifyCapability({
          capability: 'read',
          resource: '/test',
          token,
        });

        expect(result).toBe(false);
      });
    });

    describe('with custom resolver', () => {
      test('uses custom capability resolver', async () => {
        const mockCapabilities: CapabilityGrant[] = [
          { can: 'read', with: '*' },
          { can: 'write', with: '/custom/*' },
        ];

        const auth = createAuth({
          resolveCapabilities: async () => mockCapabilities,
        });

        const canRead = await auth.verifyCapability({
          capability: 'read',
          resource: '/anything',
          token: 'custom-token',
        });

        const canWrite = await auth.verifyCapability({
          capability: 'write',
          resource: '/custom/path',
          token: 'custom-token',
        });

        const canWriteOther = await auth.verifyCapability({
          capability: 'write',
          resource: '/other/path',
          token: 'custom-token',
        });

        expect(canRead).toBe(true);
        expect(canWrite).toBe(true);
        expect(canWriteOther).toBe(false);
      });
    });

    describe('ZK proofs', () => {
      const auth = createAuth({ fallbackToSimple: true });

      test('throws error when ZK not configured for createPrivateProof', async () => {
        await expect(
          auth.createPrivateProof({
            capability: 'read',
            resource: '/private',
            token: 'some-token',
          })
        ).rejects.toThrow('ZK prover not configured');
      });

      test('throws error when ZK not configured for verifyPrivateProof', async () => {
        await expect(
          auth.verifyPrivateProof({
            capability: 'read',
            resource: '/private',
            proof: {},
          })
        ).rejects.toThrow('ZK prover not configured');
      });
    });

    describe('capability constraints', () => {
      const auth = createAuth({ fallbackToSimple: true });

      test('respects expired constraint', async () => {
        const pastDate = new Date(Date.now() - 1000).toISOString();

        // Manually create token with expired constraint
        const payload = {
          iss: 'user',
          aud: 'affectively-auth',
          exp: Math.floor(Date.now() / 1000) + 3600,
          att: [
            {
              can: 'write',
              with: '/blog/*',
              constraints: { expiresAt: pastDate },
            },
          ],
        };
        const token = btoa(JSON.stringify(payload));

        const canWrite = await auth.verifyCapability({
          capability: 'write',
          resource: '/blog/post',
          token,
        });

        expect(canWrite).toBe(false);
      });

      test('allows non-expired constraint', async () => {
        const futureDate = new Date(Date.now() + 60000).toISOString();

        const payload = {
          iss: 'user',
          aud: 'affectively-auth',
          exp: Math.floor(Date.now() / 1000) + 3600,
          att: [
            {
              can: 'write',
              with: '/blog/*',
              constraints: { expiresAt: futureDate },
            },
          ],
        };
        const token = btoa(JSON.stringify(payload));

        const canWrite = await auth.verifyCapability({
          capability: 'write',
          resource: '/blog/post',
          token,
        });

        expect(canWrite).toBe(true);
      });
    });
  });

  describe('createAuthMiddleware', () => {
    const auth = createAuth({ fallbackToSimple: true });
    const middleware = createAuthMiddleware(auth);

    test('returns authorized=true for valid capability', async () => {
      const token = await auth.createToken({
        userId: 'user-123',
        capabilities: [{ can: 'write', with: '/posts/*' }],
      });

      const request = new Request('https://example.com/api/posts/1', {
        headers: { Authorization: `Bearer ${token}` },
      });

      const result = await middleware(request, 'write', '/posts/1');

      expect(result.authorized).toBe(true);
      expect(result.context).not.toBeNull();
      expect(result.context!.userId).toBe('user-123');
    });

    test('returns authorized=false for invalid capability', async () => {
      const token = await auth.createToken({
        userId: 'user-123',
        capabilities: [{ can: 'read', with: '/posts/*' }],
      });

      const request = new Request('https://example.com/api/posts/1', {
        headers: { Authorization: `Bearer ${token}` },
      });

      const result = await middleware(request, 'write', '/posts/1');

      expect(result.authorized).toBe(false);
      expect(result.context).not.toBeNull(); // Context is still extracted
    });

    test('returns authorized=false and null context for missing auth', async () => {
      const request = new Request('https://example.com/api/posts/1');

      const result = await middleware(request, 'write', '/posts/1');

      expect(result.authorized).toBe(false);
      expect(result.context).toBeNull();
    });
  });

  describe('custom capability types', () => {
    type CustomCapability = 'view' | 'edit' | 'publish' | 'moderate' | '*';

    test('works with custom capability type', async () => {
      const auth = createAuth<CustomCapability>({ fallbackToSimple: true });

      const token = await auth.createToken({
        userId: 'editor',
        capabilities: [
          { can: 'view', with: '*' },
          { can: 'edit', with: '/drafts/*' },
          { can: 'publish', with: '/articles/*' },
        ],
      });

      expect(
        await auth.verifyCapability({ capability: 'view', resource: '/anything', token })
      ).toBe(true);
      expect(
        await auth.verifyCapability({ capability: 'edit', resource: '/drafts/new', token })
      ).toBe(true);
      expect(
        await auth.verifyCapability({ capability: 'publish', resource: '/articles/1', token })
      ).toBe(true);
      expect(
        await auth.verifyCapability({ capability: 'moderate', resource: '/comments', token })
      ).toBe(false);
    });
  });

  describe('edge cases', () => {
    const auth = createAuth({ fallbackToSimple: true });

    test('handles empty capabilities array', async () => {
      const token = await auth.createToken({
        userId: 'user',
        capabilities: [],
      });

      const canRead = await auth.verifyCapability({
        capability: 'read',
        resource: '/test',
        token,
      });

      expect(canRead).toBe(false);
    });

    test('handles root resource path', async () => {
      const token = await auth.createToken({
        userId: 'user',
        capabilities: [{ can: 'read', with: '/' }],
      });

      const canRead = await auth.verifyCapability({
        capability: 'read',
        resource: '/',
        token,
      });

      expect(canRead).toBe(true);
    });

    test('handles deeply nested paths', async () => {
      const token = await auth.createToken({
        userId: 'user',
        capabilities: [{ can: 'write', with: '/a/b/c/d/*' }],
      });

      const canWrite = await auth.verifyCapability({
        capability: 'write',
        resource: '/a/b/c/d/e/f/g',
        token,
      });

      expect(canWrite).toBe(true);
    });

    test('wildcard does not match partial paths incorrectly', async () => {
      const token = await auth.createToken({
        userId: 'user',
        capabilities: [{ can: 'write', with: '/blog/*' }],
      });

      // /blogger should NOT match /blog/*
      const canWrite = await auth.verifyCapability({
        capability: 'write',
        resource: '/blogger/post',
        token,
      });

      expect(canWrite).toBe(false);
    });
  });
});
