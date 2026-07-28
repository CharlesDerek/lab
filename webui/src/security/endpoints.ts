const allowedOrigins = new Set(["127.0.0.1", "localhost"]);

export function safeLocalHref(endpoint: string): string | null {
  try {
    const url = new URL(endpoint);
    return allowedOrigins.has(url.hostname) ? url.toString() : null;
  } catch {
    return null;
  }
}

export function safeEndpointLabel(endpoint: string): string {
  const href = safeLocalHref(endpoint);
  if (!href) {
    return endpoint;
  }

  const url = new URL(href);
  return `${url.hostname}:${url.port || "80"}`;
}
