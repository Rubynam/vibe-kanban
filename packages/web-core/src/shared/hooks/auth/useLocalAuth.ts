import { useEffect } from 'react';
import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query';
import type { LocalAuthCredentials } from 'shared/types';
import { localAuthApi } from '@/shared/lib/api';
import { onLocalAuthRequired } from '@/shared/lib/auth/localAuthEvents';

export const localAuthKeys = {
  status: ['local-auth', 'status'] as const,
};

export function useLocalAuthStatus() {
  const queryClient = useQueryClient();

  // Re-check the session whenever any API call is rejected by the local
  // sign-in gate, so an expired session drops back to the sign-in screen.
  useEffect(
    () =>
      onLocalAuthRequired(() => {
        void queryClient.invalidateQueries({ queryKey: localAuthKeys.status });
      }),
    [queryClient]
  );

  return useQuery({
    queryKey: localAuthKeys.status,
    queryFn: () => localAuthApi.status(),
    staleTime: 60_000,
    retry: 1,
  });
}

async function refreshAfterAuthChange(queryClient: QueryClient) {
  await queryClient.invalidateQueries({ queryKey: localAuthKeys.status });
}

export function useLocalAuthMutations() {
  const queryClient = useQueryClient();

  const login = useMutation({
    mutationFn: (credentials: LocalAuthCredentials) =>
      localAuthApi.login(credentials),
    onSuccess: () => refreshAfterAuthChange(queryClient),
  });

  const setup = useMutation({
    mutationFn: (credentials: LocalAuthCredentials) =>
      localAuthApi.setup(credentials),
    onSuccess: () => refreshAfterAuthChange(queryClient),
  });

  const logout = useMutation({
    mutationFn: () => localAuthApi.logout(),
    onSuccess: async () => {
      // Refetch the status first so the gate swaps the app for the sign-in
      // screen, then drop every other response cached under the old session.
      await refreshAfterAuthChange(queryClient);
      queryClient.removeQueries({
        predicate: (query) => query.queryKey[0] !== localAuthKeys.status[0],
      });
    },
  });

  return { login, setup, logout };
}
