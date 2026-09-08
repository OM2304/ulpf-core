import { useEffect, useRef, useState, useCallback } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { PIPELINE_STAGES } from '../data/logs';
import { useReducedMotion } from '../hooks/useReducedMotion';

gsap.registerPlugin(ScrollTrigger);

export default function PipelineSection() {
  const [activeStage, setActiveStage] = useState(0);
  const [progress, setProgress] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  const stickyRef = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion();

  const updateStage = useCallback((p: number) => {
    const idx = Math.min(Math.floor(p * PIPELINE_STAGES.length), PIPELINE_STAGES.length - 1);
    setActiveStage(idx);
    setProgress(p);
  }, []);

  useEffect(() => {
    if (!wrapRef.current || !stickyRef.current) return;

    const st = ScrollTrigger.create({
      trigger: wrapRef.current,
      start: 'top top',
      end: 'bottom bottom',
      pin: stickyRef.current,
      pinSpacing: false,
      onUpdate: (self) => updateStage(self.progress),
      scrub: reduced ? false : 1,
    });

    return () => { st.kill(); };
  }, [reduced, updateStage]);

  return (
    <div ref={wrapRef} id="pipeline" style={{ height: `${PIPELINE_STAGES.length * 100}vh`, position: 'relative' }}>
      <div
        ref={stickyRef}
        className="pipeline-sticky-wrap"
        style={{ height: '100vh' }}
      >
        {/* Progress bar */}
        <div className="pipeline-progress-bar">
          <div
            className="pipeline-progress-fill"
            style={{ height: `${progress * 100}%` }}
          />
        </div>

        {/* Stage navigation sidebar */}
        <div className="pipeline-stages-nav">
          <div style={{ marginBottom: 16 }}>
            <div className="t-label" style={{ padding: '0 10px', marginBottom: 12 }}>Pipeline</div>
          </div>
          {PIPELINE_STAGES.map((s, i) => (
            <div
              key={i}
              className={`pipeline-stage-nav-item ${i === activeStage ? 'active' : ''}`}
              id={`pipeline-nav-${i}`}
            >
              <span className="pipeline-stage-nav-num">{s.num}</span>
              <span className="pipeline-stage-nav-name">{s.name}</span>
              {i === activeStage && (
                <span className="dot dot-accent" style={{ marginLeft: 'auto' }} />
              )}
            </div>
          ))}
        </div>

        {/* Main stage content */}
        <div className="pipeline-content">
          {PIPELINE_STAGES.map((s, i) => (
            <div
              key={i}
              className={`pipeline-stage-display ${i === activeStage ? 'active' : ''}`}
            >
              {/* Info panel */}
              <div className="pipeline-stage-info">
                <div className="pipeline-stage-num">STAGE {s.num} / {PIPELINE_STAGES.length.toString().padStart(2, '0')}</div>
                <h2 className="pipeline-stage-title">{s.title}</h2>
                <p className="pipeline-stage-desc">{s.desc}</p>

                <div className="pipeline-stage-meta">
                  <div className="pipeline-stage-meta-row">
                    <span className="pipeline-stage-meta-key">INPUT</span>
                    <span className="pipeline-stage-meta-val">{s.input}</span>
                  </div>
                  <div className="pipeline-stage-meta-row">
                    <span className="pipeline-stage-meta-key">OUTPUT</span>
                    <span className="pipeline-stage-meta-val">{s.output}</span>
                  </div>
                  <div style={{ marginTop: 12 }}>
                    <span className="badge badge-accent">{s.detail}</span>
                  </div>
                </div>
              </div>

              {/* Transform visualization */}
              <div className="pipeline-stage-viz">
                <div className="pipeline-transform-box">
                  <div className="pipeline-transform-header">
                    <span className="dot dot-success" />
                    <span className="t-label" style={{ color: 'var(--text-2)' }}>INPUT</span>
                    <span style={{ marginLeft: 'auto', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-3)' }}>
                      stage_{s.num}
                    </span>
                  </div>
                  <div className="pipeline-transform-body">
                    <pre className="code-block" style={{ maxHeight: 140, overflowY: 'auto', fontSize: 10.5 }}>
                      {s.inputSample}
                    </pre>
                  </div>

                  <div className="pipeline-transform-arrow" style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
                    <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)', padding: '8px 16px' }}>
                      <span className="dot dot-accent pulse" />
                      {s.name.toUpperCase()} IN PROGRESS
                    </span>
                  </div>

                  <div className="pipeline-transform-header" style={{ borderTop: 'none', borderBottom: 'none' }}>
                    <span className="dot dot-accent" />
                    <span className="t-label" style={{ color: 'var(--accent)' }}>OUTPUT</span>
                  </div>
                  <div className="pipeline-transform-body">
                    <pre className="code-block" style={{ maxHeight: 140, overflowY: 'auto', fontSize: 10.5, borderLeftColor: 'var(--accent)', borderLeft: '2px solid var(--accent)' }}>
                      {s.outputSample}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
