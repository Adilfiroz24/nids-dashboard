// @vitest-environment jsdom
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('expired authentication', () => {
  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    window.localStorage.setItem('nids-access-token', 'expired-token');
    vi.resetModules();
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ setup_required: false }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          text: async () => JSON.stringify({ detail: 'Token expired' }),
        }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('clears an invalid stored token and renders the login screen', async () => {
    await act(async () => {
      await import('./main.jsx');
    });

    expect(window.localStorage.getItem('nids-access-token')).toBeNull();
    expect(document.querySelector('h1')?.textContent).toBe('Sign in');
  });
});
