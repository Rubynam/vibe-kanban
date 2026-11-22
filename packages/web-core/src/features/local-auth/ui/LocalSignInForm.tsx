import type { FormEvent } from 'react';
import { SpinnerIcon } from '@phosphor-icons/react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/shared/lib/utils';

export type LocalSignInMode = 'login' | 'setup';

export interface LocalSignInFormProps {
  mode: LocalSignInMode;
  username: string;
  password: string;
  confirmPassword: string;
  error: string | null;
  isSubmitting: boolean;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onConfirmPasswordChange: (value: string) => void;
  onSubmit: () => void;
}

const inputClassName =
  'w-full px-base py-half bg-secondary rounded border border-border text-base text-normal placeholder:text-low focus:outline-none focus:ring-1 focus:ring-brand';

/** Stateless username/password form for local accounts. */
export function LocalSignInForm({
  mode,
  username,
  password,
  confirmPassword,
  error,
  isSubmitting,
  onUsernameChange,
  onPasswordChange,
  onConfirmPasswordChange,
  onSubmit,
}: LocalSignInFormProps) {
  const { t } = useTranslation('common');
  const isSetup = mode === 'setup';
  const canSubmit =
    !isSubmitting &&
    username.trim().length > 0 &&
    password.length > 0 &&
    (!isSetup || confirmPassword.length > 0);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (canSubmit) onSubmit();
  };

  return (
    <form className="space-y-base" onSubmit={handleSubmit} noValidate>
      <label className="block space-y-half">
        <span className="text-sm text-low">{t('localAuth.username')}</span>
        <input
          className={inputClassName}
          value={username}
          onChange={(event) => onUsernameChange(event.target.value)}
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          autoFocus
        />
      </label>
      <label className="block space-y-half">
        <span className="text-sm text-low">{t('localAuth.password')}</span>
        <input
          className={inputClassName}
          type="password"
          value={password}
          onChange={(event) => onPasswordChange(event.target.value)}
          autoComplete={isSetup ? 'new-password' : 'current-password'}
        />
      </label>
      {isSetup && (
        <label className="block space-y-half">
          <span className="text-sm text-low">
            {t('localAuth.confirmPassword')}
          </span>
          <input
            className={inputClassName}
            type="password"
            value={confirmPassword}
            onChange={(event) => onConfirmPasswordChange(event.target.value)}
            autoComplete="new-password"
          />
        </label>
      )}

      {error && (
        <div
          role="alert"
          className="rounded-sm border border-error/30 bg-error/10 p-base text-sm text-high"
        >
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={!canSubmit}
        className={cn(
          'w-full rounded-sm px-base py-half text-cta min-h-cta flex gap-half items-center justify-center',
          canSubmit
            ? 'bg-brand hover:bg-brand-hover text-on-brand'
            : 'cursor-not-allowed bg-panel text-low'
        )}
      >
        {isSubmitting && <SpinnerIcon className="size-icon-sm animate-spin" />}
        {isSetup
          ? isSubmitting
            ? t('localAuth.creatingAccount')
            : t('localAuth.createAccount')
          : isSubmitting
            ? t('localAuth.signingIn')
            : t('localAuth.signIn')}
      </button>
    </form>
  );
}
