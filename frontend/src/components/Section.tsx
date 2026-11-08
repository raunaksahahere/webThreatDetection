import type { ReactNode } from 'react';

interface Props {
  id?: string;
  num?: string;
  title: string;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
  sectionRef?: (el: HTMLElement | null) => void;
}

export function Section({ id, num, title, aside, children, className = '', sectionRef }: Props) {
  return (
    <section className={`panel ${className}`} id={id} ref={sectionRef} aria-labelledby={id ? `${id}-h` : undefined}>
      <header className="panel-head">
        <h2 id={id ? `${id}-h` : undefined}>
          {num ? <span className="panel-num">{num}</span> : null}
          {title}
        </h2>
        {aside ? <div className="panel-aside">{aside}</div> : null}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function Notice({ tone = 'info', icon, title, children }: { tone?: 'info' | 'warn' | 'bad' | 'good' | 'neutral'; icon?: ReactNode; title?: string; children?: ReactNode }) {
  return (
    <div className={`notice notice-${tone}`} role={tone === 'bad' ? 'alert' : undefined}>
      {icon ? <span className="notice-icon">{icon}</span> : null}
      <div className="notice-body">
        {title ? <strong className="notice-title">{title}</strong> : null}
        {children ? <div className="notice-text">{children}</div> : null}
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}
