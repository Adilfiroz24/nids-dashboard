// @vitest-environment jsdom
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('backend connection state', () => {
  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    window.localStorage.clear();
    vi.resetModules();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('shows the backend URL and a retry action when the API is unreachable', async () => {
    await act(async () => {
      await import('./main.jsx');
    });

    expect(document.querySelector('[role="alert"]')?.textContent).toContain(
      'Backend not reachable at http://127.0.0.1:8000/api',
    );
    expect(document.querySelector('button')?.textContent).toBe('Retry connection');
  });
});
