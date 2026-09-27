import {
  PARAFE_EXTENSION_URI,
  A2A_EXTENSIONS_HEADER,
  A2A_EXTENSIONS_HEADER_V0_3,
  A2A_VERSION_HEADER,
} from './constants.js';

/**
 * HTTP headers a client sends to activate the Parafe extension.
 * A2A 1.0: `A2A-Version: 1.0` and `A2A-Extensions`. A2A 0.3: `X-A2A-Extensions`.
 *
 * With @a2a-js/sdk you don't need this: pass
 * `{ serviceParameters: ServiceParameters.create(withA2AExtensions(PARAFE_EXTENSION_URI)) }`
 * and the SDK picks the header name for the negotiated version.
 *
 * @param otherExtensions other extension URIs to activate on the same request
 */
export function activationHeaders(
  a2aVersion: '1.0' | '0.3' = '1.0',
  otherExtensions: readonly string[] = []
): Record<string, string> {
  const value = [PARAFE_EXTENSION_URI, ...otherExtensions.filter((u) => u !== PARAFE_EXTENSION_URI)].join(',');
  return a2aVersion === '0.3'
    ? { [A2A_EXTENSIONS_HEADER_V0_3]: value }
    : { [A2A_VERSION_HEADER]: '1.0', [A2A_EXTENSIONS_HEADER]: value };
}

/**
 * Server side: did this request activate the Parafe extension?
 * Accepts a plain header object (Node/Express style, any casing) or a Fetch `Headers`.
 * Checks both `A2A-Extensions` and the A2A 0.3 `X-A2A-Extensions`.
 *
 * With @a2a-js/sdk, `ctx.context.requestedExtensions` already holds the parsed list.
 */
export function isParafeActivated(
  headers: Headers | Record<string, string | string[] | undefined>
): boolean {
  const read = (name: string): string[] => {
    if (typeof (headers as Headers).get === 'function') {
      const v = (headers as Headers).get(name);
      return v === null ? [] : [v];
    }
    const lower = name.toLowerCase();
    const values: string[] = [];
    for (const [key, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
      if (key.toLowerCase() !== lower || v === undefined) continue;
      values.push(...(Array.isArray(v) ? v : [v]));
    }
    return values;
  };
  return [...read(A2A_EXTENSIONS_HEADER), ...read(A2A_EXTENSIONS_HEADER_V0_3)]
    .flatMap((v) => v.split(','))
    .some((uri) => uri.trim() === PARAFE_EXTENSION_URI);
}
