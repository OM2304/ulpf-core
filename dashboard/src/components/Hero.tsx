import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { useReducedMotion } from '../hooks/useReducedMotion';

const SOURCES = [
  {
    label: 'Palo Alto Firewall',
    lines: [
      { text: 'CEF:0|PAN|PAN-OS|10.1|TRAFFIC|drop|7|', type: 'op' },
      { text: 'src=192.168.1.24 dst=10.0.0.5', type: 'highlight' },
      { text: 'proto=TCP act=drop', type: 'normal' },
    ],
  },
  {
    label: 'Linux SSH / Auth',
    lines: [
      { text: 'Sep 08 10:42:18 auth-server', type: 'normal' },
      { text: 'sshd[12345]: Failed password', type: 'highlight' },
      { text: 'from 185.220.101.47 port 44321', type: 'normal' },
    ],
  },
  {
    label: 'App JSON Log',
    lines: [
      { text: '{"level":"error","service":', type: 'op' },
      { text: ' "api-gateway","status":401,', type: 'highlight' },
      { text: ' "client_ip":"172.16.0.88"}', type: 'op' },
    ],
  },
  {
    label: 'AWS CloudTrail',
    lines: [
      { text: '"eventName":"AttachUserPolicy"', type: 'highlight' },
      { text: '"sourceIPAddress":"203.0.113.12"', type: 'normal' },
      { text: '"userName":"devops"', type: 'normal' },
    ],
  },
  {
    label: 'Windows Event Log',
    lines: [
      { text: '<EventID>4625</EventID>', type: 'op' },
      { text: '<TargetUserName>admin', type: 'highlight' },
      { text: '<IpAddress>192.168.100.15', type: 'normal' },
    ],
  },
];

const NORMALIZED_LINES = [
  { key: 'class_uid',   val: '4001',           type: 'num' },
  { key: 'class_name',  val: '"Network Activity"', type: 'str' },
  { key: 'time',        val: '"2026-09-08T10:42:18Z"', type: 'str' },
  { key: 'severity',    val: '"High"',          type: 'str' },
  { key: 'src_endpoint',val: '{"ip":"192.168.1.24"}', type: 'op' },
  { key: 'disposition', val: '"Blocked"',       type: 'str' },
  { key: 'parser_id',   val: '"builtin_cef_v1"',type: 'str' },
];

export default function Hero() {
  const sectionRef = useRef<HTMLElement>(null);
  const sourcesRef = useRef<HTMLDivElement>(null);
  const processorRef = useRef<HTMLDivElement>(null);
  const outputRef = useRef<HTMLDivElement>(null);
  const linesRef = useRef<SVGSVGElement>(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    if (reduced) {
      // Skip animations, show everything immediately
      gsap.set([sourcesRef.current?.children, processorRef.current, outputRef.current], { opacity: 1, x: 0 });
      return;
    }

    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ delay: 0.3 });

      // Animate source boxes in stagger
      tl.from('.hero-source-box', {
        opacity: 0,
        x: -30,
        stagger: 0.12,
        duration: 0.5,
        ease: 'power2.out',
      });

      // Draw SVG lines
      if (linesRef.current) {
        const paths = linesRef.current.querySelectorAll('path');
        paths.forEach((p) => {
          const len = (p as SVGPathElement).getTotalLength?.() ?? 200;
          gsap.set(p, { strokeDasharray: len, strokeDashoffset: len });
        });
        tl.to(linesRef.current.querySelectorAll('path'), {
          strokeDashoffset: 0,
          duration: 0.7,
          stagger: 0.1,
          ease: 'power2.inOut',
        }, '-=0.2');
      }

      // Processor appears
      tl.to(processorRef.current, {
        opacity: 1,
        scale: 1,
        duration: 0.4,
        ease: 'back.out(1.4)',
      }, '-=0.3');

      // Output appears
      tl.to(outputRef.current, {
        opacity: 1,
        x: 0,
        duration: 0.5,
        ease: 'power2.out',
      }, '-=0.1');

    }, sectionRef);

    return () => ctx.revert();
  }, [reduced]);

  return (
    <section ref={sectionRef} className="hero" id="overview">
      {/* Label */}
      <div className="hero-label reveal">
        <span className="t-label t-label-accent">Universal Log Pre-Processing System</span>
      </div>

      {/* Title */}
      <h1 className="hero-title reveal">
        Raw logs.<br />
        Different sources.<br />
        <em>One structure.</em>
      </h1>

      {/* Subtitle */}
      <p className="hero-sub reveal">
        ULPS ingests heterogeneous log formats from any source and transforms them
        into consistent, queryable OCSF Class 4001 events — ready for SIEM and analytics.
      </p>

      {/* CTA */}
      <div className="hero-cta reveal">
        <a href="/console" className="btn btn-primary" id="hero-console-btn">
          Open Console →
        </a>
        <a href="#pipeline" className="btn btn-ghost" id="hero-learn-btn">
          How it works ↓
        </a>
      </div>

      {/* Main Visualization */}
      <div className="hero-viz">
        <div style={{ display: 'flex', alignItems: 'center', gap: 0, width: '100%' }}>

          {/* Sources */}
          <div ref={sourcesRef} className="hero-sources" style={{ flex: '0 0 260px' }}>
            {SOURCES.map((src, i) => (
              <div key={i} className="hero-source-box" id={`hero-source-${i}`}>
                <div className="source-label">{src.label}</div>
                {src.lines.map((line, j) => (
                  <div key={j} className={
                    line.type === 'highlight' ? 'source-highlight' :
                    line.type === 'op' ? 'source-line' : 'source-line'
                  } style={{ color: line.type === 'highlight' ? 'var(--accent)' : line.type === 'op' ? 'var(--text-3)' : 'var(--text-2)' }}>
                    {line.text}
                  </div>
                ))}
              </div>
            ))}
          </div>

          {/* SVG connecting lines */}
          <svg
            ref={linesRef}
            style={{ flex: '1', minWidth: 80, height: 260, overflow: 'visible' }}
            viewBox="0 0 120 260"
            preserveAspectRatio="none"
          >
            {[20, 68, 116, 164, 212].map((y, i) => (
              <path
                key={i}
                d={`M 0 ${y} C 60 ${y}, 60 130, 120 130`}
                stroke={i === 2 ? 'var(--accent)' : 'var(--border)'}
                strokeWidth={i === 2 ? 1.5 : 1}
                fill="none"
                opacity={i === 2 ? 1 : 0.6}
                style={{ strokeDasharray: 200, strokeDashoffset: 200 }}
              />
            ))}
            {/* Flow dots */}
            {[20, 68, 116, 164, 212].map((y, i) => (
              <circle
                key={`dot-${i}`}
                r="3"
                fill={i === 2 ? 'var(--accent)' : 'var(--text-3)'}
                opacity={0.7}
              >
                <animateMotion
                  dur={`${1.2 + i * 0.15}s`}
                  repeatCount="indefinite"
                  path={`M 0 ${y} C 60 ${y}, 60 130, 120 130`}
                  begin={`${i * 0.3}s`}
                />
              </circle>
            ))}
          </svg>

          {/* Processor */}
          <div
            ref={processorRef}
            className="hero-processor"
            style={{ opacity: 0, transform: 'scale(0.8)' }}
          >
            <div className="hero-processor-label">ULPS Engine</div>
            <div className="hero-processor-ring" />
            <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-3)' }}>
              PARSING<br />NORMALIZING
            </div>
          </div>

          {/* SVG out */}
          <svg
            style={{ flex: '0 0 60px', height: 260, overflow: 'visible' }}
            viewBox="0 0 60 260"
            preserveAspectRatio="none"
          >
            <path
              d="M 0 130 L 60 130"
              stroke="var(--success)"
              strokeWidth="1.5"
              fill="none"
            />
            <circle r="3" fill="var(--success)">
              <animateMotion dur="1s" repeatCount="indefinite" path="M 0 130 L 60 130" />
            </circle>
          </svg>

          {/* Normalized Output */}
          <div
            ref={outputRef}
            className="hero-output"
            style={{ opacity: 0, transform: 'translateX(20px)' }}
          >
            <div className="hero-output-label">OCSF CLASS 4001</div>
            {NORMALIZED_LINES.map((line, i) => (
              <div key={i}>
                <span className="code-key">"{line.key}"</span>
                <span className="code-op">: </span>
                <span className={`code-${line.type}`}>{line.val}</span>
                {i < NORMALIZED_LINES.length - 1 && <span className="code-op">,</span>}
              </div>
            ))}
          </div>
        </div>

        {/* Stats strip */}
        <div style={{
          display: 'flex', gap: 32, justifyContent: 'center',
          marginTop: 40, paddingTop: 32, borderTop: '1px solid var(--border)',
        }}>
          {[
            { val: '5+', label: 'Log Source Types' },
            { val: '3+', label: 'Built-in Parsers' },
            { val: '∞',  label: 'AI-Synthesized Parsers' },
            { val: '4001', label: 'OCSF Class' },
          ].map(({ val, label }) => (
            <div key={label} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text)', letterSpacing: '-0.02em' }}>
                {val}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4, fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }}>
                {label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
