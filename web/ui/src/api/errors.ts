import { Code, ConnectError } from "@connectrpc/connect";

export { Code, ConnectError };

export function connectCode(err: unknown): Code | undefined {
  if (err instanceof ConnectError) return err.code;
  return undefined;
}

export function isCode(err: unknown, code: Code): boolean {
  return connectCode(err) === code;
}

/** Human readable message of an error, without the "[code]" prefix. */
export function errorMessage(err: unknown): string {
  if (err instanceof ConnectError) {
    const msg = err.rawMessage || Code[err.code] || "request failed";
    if (err.code === Code.Unavailable && /fetch|network/i.test(msg)) {
      return "The OpenPicket manager is not reachable.";
    }
    return msg;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

export function codeName(err: unknown): string {
  const c = connectCode(err);
  return c === undefined ? "" : Code[c];
}

/** The message of an invalid search query, or undefined. */
export function queryError(err: unknown): string | undefined {
  return isCode(err, Code.InvalidArgument) ? errorMessage(err) : undefined;
}
