// Lets the API layer tell the local sign-in gate that the server rejected a
// request because the local session is missing or expired, without the API
// module depending on React Query or the gate component.

type Listener = () => void;

const listeners = new Set<Listener>();

export function notifyLocalAuthRequired(): void {
  for (const listener of listeners) {
    listener();
  }
}

export function onLocalAuthRequired(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
