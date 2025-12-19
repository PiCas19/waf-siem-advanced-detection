import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { formatDate, formatBytes } from '../formatters';

describe('formatters', () => {
  describe('formatDate', () => {
    beforeEach(() => {
      // Mock Date.prototype.toLocaleString to have consistent output
      vi.spyOn(Date.prototype, 'toLocaleString').mockReturnValue('12/11/2025, 10:30:00 AM');
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should format a valid date string', () => {
      const dateString = '2025-12-11T10:30:00Z';
      const result = formatDate(dateString);
      expect(result).toBe('12/11/2025, 10:30:00 AM');
    });

    it('should handle ISO 8601 date format', () => {
      const dateString = '2025-01-15T14:45:30.000Z';
      const result = formatDate(dateString);
      expect(result).toBe('12/11/2025, 10:30:00 AM');
    });

    it('should handle different date formats', () => {
      const dateString = 'Mon Dec 11 2025 10:30:00 GMT+0000';
      const result = formatDate(dateString);
      expect(result).toBe('12/11/2025, 10:30:00 AM');
    });
  });

  describe('formatBytes', () => {
    it('should format bytes less than 1KB', () => {
      expect(formatBytes(0)).toBe('0 B');
      expect(formatBytes(512)).toBe('512 B');
      expect(formatBytes(1023)).toBe('1023 B');
    });

    it('should format bytes in KB range', () => {
      expect(formatBytes(1024)).toBe('1.0 KB');
      expect(formatBytes(2048)).toBe('2.0 KB');
      expect(formatBytes(1536)).toBe('1.5 KB');
      expect(formatBytes(102400)).toBe('100.0 KB');
    });

    it('should format bytes in MB range', () => {
      expect(formatBytes(1048576)).toBe('1.0 MB');
      expect(formatBytes(2097152)).toBe('2.0 MB');
      expect(formatBytes(5242880)).toBe('5.0 MB');
      expect(formatBytes(1572864)).toBe('1.5 MB');
    });

    it('should handle large file sizes', () => {
      expect(formatBytes(104857600)).toBe('100.0 MB');
      expect(formatBytes(1073741824)).toBe('1024.0 MB');
    });

    it('should round to one decimal place', () => {
      expect(formatBytes(1536)).toBe('1.5 KB');
      expect(formatBytes(2560)).toBe('2.5 KB');
      expect(formatBytes(1610612736)).toBe('1536.0 MB');
    });

    it('should handle edge cases', () => {
      expect(formatBytes(1)).toBe('1 B');
      expect(formatBytes(1023.9)).toBe('1023.9 B');
      expect(formatBytes(1024.1)).toBe('1.0 KB');
    });
  });
});
