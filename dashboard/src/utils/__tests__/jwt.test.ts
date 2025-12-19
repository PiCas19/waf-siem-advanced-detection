import { describe, it, expect } from 'vitest';
import { parseJWT } from '../jwt';

describe('jwt', () => {
  describe('parseJWT', () => {
    it('should parse a valid JWT token', () => {
      // Create a valid JWT token (header.payload.signature)
      const payload = { userId: '123', email: 'test@example.com', exp: 1234567890 };
      const encodedPayload = btoa(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      const result = parseJWT(token);
      expect(result).toEqual(payload);
      expect(result.userId).toBe('123');
      expect(result.email).toBe('test@example.com');
      expect(result.exp).toBe(1234567890);
    });

    it('should parse JWT with different payload structures', () => {
      const payload = {
        sub: 'user-456',
        name: 'John Doe',
        admin: true,
        iat: 1516239022,
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      const result = parseJWT(token);
      expect(result).toEqual(payload);
      expect(result.sub).toBe('user-456');
      expect(result.name).toBe('John Doe');
      expect(result.admin).toBe(true);
    });

    it('should return null for invalid JWT format', () => {
      expect(parseJWT('invalid.token')).toBeNull();
      expect(parseJWT('not-a-jwt')).toBeNull();
      expect(parseJWT('')).toBeNull();
    });

    it('should return null for malformed base64', () => {
      const token = 'header.invalid-base64!@#.signature';
      const result = parseJWT(token);
      expect(result).toBeNull();
    });

    it('should return null for non-JSON payload', () => {
      const invalidPayload = btoa('not json data');
      const token = `header.${invalidPayload}.signature`;
      const result = parseJWT(token);
      expect(result).toBeNull();
    });

    it('should handle JWT with nested objects', () => {
      const payload = {
        user: {
          id: '789',
          roles: ['admin', 'user'],
          metadata: {
            created: '2025-01-01',
            verified: true,
          },
        },
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      const result = parseJWT(token);
      expect(result).toEqual(payload);
      expect(result.user.id).toBe('789');
      expect(result.user.roles).toEqual(['admin', 'user']);
      expect(result.user.metadata.verified).toBe(true);
    });

    it('should handle JWT with ASCII special characters in payload', () => {
      const payload = {
        message: 'Hello, World!',
        symbols: '!@#$%^&*()',
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      const result = parseJWT(token);
      expect(result).toEqual(payload);
    });

    it('should return null for token with missing parts', () => {
      expect(parseJWT('only-one-part')).toBeNull();
      expect(parseJWT('two.parts')).toBeNull();
    });

    it('should handle empty payload', () => {
      const payload = {};
      const encodedPayload = btoa(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      const result = parseJWT(token);
      expect(result).toEqual({});
    });

    it('should handle payload with null values', () => {
      const payload = { value: null, data: null };
      const encodedPayload = btoa(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      const result = parseJWT(token);
      expect(result).toEqual(payload);
      expect(result.value).toBeNull();
    });
  });
});
