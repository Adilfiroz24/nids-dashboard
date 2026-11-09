// @vitest-environment jsdom
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('application startup', () => {
  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    window.localStorage.clear();
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    vi.resetModules();
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ setup_required: true }),
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders the first-run administrator setup screen without a token', async () => {
    await act(async () => {
      await import('./main.jsx');
    });

    expect(document.querySelector('h1')?.textContent).toBe('Create administrator');
    expect(document.querySelector('form button')?.textContent).toBe('Configure administrator');
  });
});
