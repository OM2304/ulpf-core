import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';

interface Props {
  onDone: () => void;
}

export default function Preloader({ onDone }: Props) {
  const rootRef  = useRef<HTMLDivElement>(null);
  const barRef   = useRef<HTMLDivElement>(null);
  const textRef  = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const tl = gsap.timeline();

    // Progress bar fill
    tl.to(barRef.current, {
      scaleX: 1,
      duration: 1.6,
      ease: 'power1.inOut',
    });

    // Text cycle
    tl.to(textRef.current, {
      opacity: 0,
      duration: 0.2,
    }, 0.5);

    // Fade out entire preloader
    tl.to(rootRef.current, {
      opacity: 0,
      duration: 0.4,
      ease: 'power2.in',
      onComplete: onDone,
    }, '+=0.1');

    return () => { tl.kill(); };
  }, [onDone]);

  return (
    <div
      ref={rootRef}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'var(--bg)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 32,
      }}
    >
      {/* Logo mark */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{
          width: 44,
          height: 44,
          background: 'var(--accent)',
          borderRadius: 10,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 16,
          fontWeight: 800,
          color: '#000',
          fontFamily: 'var(--font-mono)',
          letterSpacing: '-0.02em',
        }}>
          UL
        </div>
        <div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 14,
            fontWeight: 700,
            letterSpacing: '0.1em',
            color: 'var(--text)',
          }}>
            ULPS
          </div>
          <div ref={textRef} style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            color: 'var(--text-3)',
            letterSpacing: '0.12em',
            marginTop: 2,
          }}>
            INITIALIZING PIPELINE…
          </div>
        </div>
      </div>

      {/* Progress bar */}
      <div style={{
        width: 200,
        height: 2,
        background: 'var(--border)',
        borderRadius: 2,
        overflow: 'hidden',
      }}>
        <div
          ref={barRef}
          style={{
            height: '100%',
            background: 'var(--accent)',
            borderRadius: 2,
            transformOrigin: 'left center',
            transform: 'scaleX(0)',
          }}
        />
      </div>

      {/* Stage labels */}
      <div style={{
        display: 'flex',
        gap: 6,
        fontFamily: 'var(--font-mono)',
        fontSize: 9,
        color: 'var(--text-4)',
        letterSpacing: '0.1em',
      }}>
        {['INGEST', '→', 'BUFFER', '→', 'PARSE', '→', 'NORMALIZE', '→', 'OUTPUT'].map((s, i) => (
          <span key={i} style={{ color: s === '→' ? 'var(--border)' : 'var(--text-4)' }}>{s}</span>
        ))}
      </div>
    </div>
  );
}
