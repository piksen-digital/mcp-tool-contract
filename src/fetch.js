const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

export async function fetchText(url, timeoutMs, maxRedirects, fetchImpl = fetch) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let currentUrl = url;
    let redirectsFollowed = 0;
    for (;;) {
      const response = await fetchImpl(currentUrl, {
        redirect: 'manual',
        signal: controller.signal,
      });

      if (REDIRECT_STATUS.has(response.status)) {
        if (redirectsFollowed >= maxRedirects) {
          throw new Error(
            `Exceeded maxRedirects (${maxRedirects}) at ${currentUrl}`
          );
        }
        const location = response.headers.get('location');
        if (!location) {
          throw new Error(
            `Redirect ${response.status} without Location header at ${currentUrl}`
          );
        }
        currentUrl = new URL(location, currentUrl).toString();
        redirectsFollowed += 1;
        continue;
      }

      if (response.status >= 400) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }
      const text = await response.text();
      return { response, text, finalUrl: currentUrl, redirectsFollowed };
    }
  } finally {
    clearTimeout(timer);
  }
}
