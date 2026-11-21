import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocalAuthStatus } from '@/shared/hooks/auth/useLocalAuth';
import { LocalSignInContainer } from '@/features/local-auth/ui/LocalSignInContainer';
import '@/app/styles/new/index.css';

interface LocalLoginGateProps {
  children: ReactNode;
}

/**
 * Renders the app only once this server's local sign-in is satisfied. When
 * local sign-in is disabled (the default whenever a cloud API is configured)
 * it renders children straight away.
 */
export function LocalLoginGate({ children }: LocalLoginGateProps) {
  const { t } = useTranslation('common');
  const { data: status, isPending, isError, refetch } = useLocalAuthStatus();

  if (isPending) {
    return (
      <GateShell>
        <p className="text-sm text-low text-center">{t('localAuth.loading')}</p>
      </GateShell>
    );
  }

  if (isError) {
    return (
      <GateShell>
        <div className="space-y-base text-center">
          <p className="text-sm text-normal">{t('localAuth.statusError')}</p>
          <button
            type="button"
            className="rounded-sm border border-border bg-panel px-base py-half text-sm text-normal hover:bg-primary"
            onClick={() => void refetch()}
          >
            {t('localAuth.retry')}
          </button>
        </div>
      </GateShell>
    );
  }

  if (!status.enabled || status.user) {
    return <>{children}</>;
  }

  const mode = status.setup_required ? 'setup' : 'login';
  return (
    <GateShell>
      <header className="space-y-half text-center">
        <h1 className="text-xl text-high">
          {mode === 'setup'
            ? t('localAuth.setupTitle')
            : t('localAuth.signInTitle')}
        </h1>
        <p className="text-sm text-low">
          {mode === 'setup'
            ? t('localAuth.setupDescription')
            : t('localAuth.signInDescription')}
        </p>
      </header>
      <LocalSignInContainer key={mode} mode={mode} />
    </GateShell>
  );
}

function GateShell({ children }: { children: ReactNode }) {
  return (
    <div className="h-screen overflow-auto bg-primary font-ibm-plex-sans">
      <div className="mx-auto flex min-h-full w-full max-w-sm flex-col justify-center px-base py-double">
        <div className="rounded-sm border border-border bg-secondary p-double space-y-double">
          <div className="flex justify-center">
            <img
              src="/vibe-kanban-logo.svg"
              alt="Vibe Kanban"
              className="h-8 w-auto logo dark:hidden"
            />
            <img
              src="/vibe-kanban-logo-dark.svg"
              alt="Vibe Kanban"
              className="h-8 w-auto logo hidden dark:block"
            />
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}
