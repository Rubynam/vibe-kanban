import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocalAuthMutations } from '@/shared/hooks/auth/useLocalAuth';
import {
  LocalSignInForm,
  type LocalSignInMode,
} from '@/features/local-auth/ui/LocalSignInForm';

interface LocalSignInContainerProps {
  mode: LocalSignInMode;
  onSignedIn?: () => void;
}

/** Holds the form state and submits it to the local sign-in API. */
export function LocalSignInContainer({
  mode,
  onSignedIn,
}: LocalSignInContainerProps) {
  const { t } = useTranslation('common');
  const { login, setup } = useLocalAuthMutations();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const mutation = mode === 'setup' ? setup : login;

  const handleSubmit = () => {
    setError(null);
    if (mode === 'setup' && password !== confirmPassword) {
      setError(t('localAuth.passwordMismatch'));
      return;
    }
    mutation.mutate(
      { username: username.trim(), password },
      {
        onSuccess: () => {
          setPassword('');
          setConfirmPassword('');
          onSignedIn?.();
        },
        onError: (err) => {
          setError(
            err instanceof Error ? err.message : t('localAuth.genericError')
          );
        },
      }
    );
  };

  return (
    <LocalSignInForm
      mode={mode}
      username={username}
      password={password}
      confirmPassword={confirmPassword}
      error={error}
      isSubmitting={mutation.isPending}
      onUsernameChange={setUsername}
      onPasswordChange={setPassword}
      onConfirmPasswordChange={setConfirmPassword}
      onSubmit={handleSubmit}
    />
  );
}
