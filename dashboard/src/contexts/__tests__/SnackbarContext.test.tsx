import { describe, it, expect, vi, beforeEach, afterEach} from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { ToastProvider, useToast, useSnackbar } from '../SnackbarContext';

describe('SnackbarContext', () => {
  let mockTime = 1000000;

  beforeEach(() => {
    vi.clearAllMocks();
    mockTime = 1000000;
    vi.spyOn(Date, 'now').mockImplementation(() => mockTime++);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Initial State', () => {
    it('should provide initial state with empty toasts', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      expect(result.current.toasts).toEqual([]);
    });

    it('should provide showToast function', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      expect(typeof result.current.showToast).toBe('function');
    });

    it('should provide removeToast function', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      expect(typeof result.current.removeToast).toBe('function');
    });
  });

  describe('showToast', () => {
    it('should add a toast with default type and duration', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Test message', 'info');
      });

      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].message).toBe('Test message');
      expect(result.current.toasts[0].type).toBe('info');
      expect(result.current.toasts[0].duration).toBe(4000);
      expect(result.current.toasts[0].id).toBeDefined();
    });

    it('should add a toast with custom type', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Success message', 'success');
      });

      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].type).toBe('success');
    });

    it('should add a toast with custom duration', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Custom duration', 'info', 2000);
      });

      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].duration).toBe(2000);
    });

    it('should add multiple toasts', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('First toast', 'info');
        result.current.showToast('Second toast', 'info');
        result.current.showToast('Third toast', 'info');
      });

      expect(result.current.toasts).toHaveLength(3);
      expect(result.current.toasts[0].message).toBe('First toast');
      expect(result.current.toasts[1].message).toBe('Second toast');
      expect(result.current.toasts[2].message).toBe('Third toast');
    });

    it('should generate unique IDs for each toast', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Toast 1', 'info');
        result.current.showToast('Toast 2', 'info');
      });

      expect(result.current.toasts[0].id).not.toBe(result.current.toasts[1].id);
    });

    it('should add error toast', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Error message', 'error');
      });

      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].type).toBe('error');
    });

    it('should add warning toast', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Warning message', 'warning');
      });

      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].type).toBe('warning');
    });
  });

  describe('removeToast', () => {
    it('should remove a toast by ID', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Toast to remove','info');
      });

      const toastId = result.current.toasts[0].id;

      act(() => {
        result.current.removeToast(toastId);
      });

      expect(result.current.toasts).toHaveLength(0);
    });

    it('should remove only the specified toast', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Toast 1', 'info');
        result.current.showToast('Toast 2', 'info');
        result.current.showToast('Toast 3', 'info');
      });

      const toast2Id = result.current.toasts[1].id;

      act(() => {
        result.current.removeToast(toast2Id);
      });

      expect(result.current.toasts).toHaveLength(2);
      expect(result.current.toasts[0].message).toBe('Toast 1');
      expect(result.current.toasts[1].message).toBe('Toast 3');
    });

    it('should do nothing if toast ID does not exist', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Toast 1', 'info');
        result.current.showToast('Toast 2', 'info');
      });

      act(() => {
        result.current.removeToast('non-existent-id');
      });

      expect(result.current.toasts).toHaveLength(2);
    });

    it('should handle removing all toasts one by one', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      act(() => {
        result.current.showToast('Toast 1', 'info');
        result.current.showToast('Toast 2', 'info');
        result.current.showToast('Toast 3', 'info');
      });

      const ids = result.current.toasts.map((t) => t.id);

      act(() => {
        ids.forEach((id) => result.current.removeToast(id));
      });

      expect(result.current.toasts).toHaveLength(0);
    });
  });

  describe('useSnackbar alias', () => {
    it('should work the same as useToast', () => {
      const { result } = renderHook(() => useSnackbar(), {
        wrapper: ToastProvider,
      });

      expect(result.current.toasts).toEqual([]);

      act(() => {
        result.current.showToast('Test with useSnackbar', 'info');
      });

      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].message).toBe('Test with useSnackbar');
    });
  });

  describe('useToast hook error', () => {
    it('should throw error when used outside ToastProvider', () => {
      expect(() => {
        renderHook(() => useToast());
      }).toThrow('useToast must be used within a ToastProvider');
    });
  });

  describe('useSnackbar hook error', () => {
    it('should throw error when used outside ToastProvider', () => {
      expect(() => {
        renderHook(() => useSnackbar());
      }).toThrow('useToast must be used within a ToastProvider');
    });
  });

  describe('Toast lifecycle', () => {
    it('should handle add and remove operations in sequence', () => {
      const { result } = renderHook(() => useToast(), {
        wrapper: ToastProvider,
      });

      // Add first toast
      act(() => {
        result.current.showToast('Toast 1', 'info');
      });
      expect(result.current.toasts).toHaveLength(1);

      const toast1Id = result.current.toasts[0].id;

      // Add second toast
      act(() => {
        result.current.showToast('Toast 2', 'info');
      });
      expect(result.current.toasts).toHaveLength(2);

      // Remove first toast
      act(() => {
        result.current.removeToast(toast1Id);
      });
      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].message).toBe('Toast 2');

      // Add third toast
      act(() => {
        result.current.showToast('Toast 3', 'info');
      });
      expect(result.current.toasts).toHaveLength(2);

      const toast2Id = result.current.toasts[0].id;

      // Remove second toast
      act(() => {
        result.current.removeToast(toast2Id);
      });
      expect(result.current.toasts).toHaveLength(1);
      expect(result.current.toasts[0].message).toBe('Toast 3');
    });
  });
});
