import { useEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { fetchEvents, OCSFEvent } from '../api/ulpf';

gsap.registerPlugin(ScrollTrigger);

const DESTINATIONS = [
  { icon: '🛡', name: 'SIEM Platform',       desc: 'Splunk / Elastic / QRadar',   color: 'var(--accent)'      },
  { icon: '📊', name: 'Analytics Engine',    desc: 'Grafana / Kibana data source', color: 'var(--success)'    },
  { icon: '🗄', name: 'Long-term Storage',   desc: 'S3 / GCS archival pipeline',  color: 'var(--processing)' },
  { icon: '🔔', name: 'Alerting System',     desc: 'PagerDuty / OpsGenie',        color: 'var(--warning)'    },
];

export default function OutputFlow() {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [latestEvent, setLatestEvent] = useState<OCSFEvent | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetchEvents({ limit: 1 });
        if (res.events.length > 0) {
          setLatestEvent(res.events[0]);
        }
      } catch (e) {
        console.error(e);
      }
    };
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.from('.output-dest', {
        opacity: 0,
        x: 30,
        stagger: 0.12,
        duration: 0.5,
        ease: 'power2.out',
        scrollTrigger: {
          trigger: sectionRef.current,
          start: 'top 75%',
        },
      });
    }, sectionRef);
    return () => ctx.revert();
  }, []);

  const ocsfJsonStr = latestEvent?.ocsf_json ? (() => {
    try {
      const obj = JSON.parse(latestEvent.ocsf_json);
      return JSON.stringify(obj, null, 2);
    } catch {
      return latestEvent.ocsf_json;
    }
  })() : null;

  return (
    <div ref={sectionRef} id="output">
      <div style={{ marginBottom: 40 }}>
        <div className="t-label" style={{ marginBottom: 8 }}>Downstream</div>
        <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 8 }}>
          Structured Output
        </h2>
        <p style={{ color: 'var(--text-2)', fontSize: 14, maxWidth: 540 }}>
          Every committed OCSF event is immediately queryable via REST API and can be routed
          to any downstream SIEM, analytics, or alerting system.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: 40, alignItems: 'center' }}>
        {/* OCSF output event */}
        <div className="card">
          <div className="console-card-header">
            <span className={`dot ${latestEvent ? 'dot-success' : 'dot-warning'}`} />
            <span className="console-card-title">
              {latestEvent ? 'OCSF Class 4001 — Committed Event' : 'Awaiting First Event...'}
            </span>
          </div>
          <div className="card-pad">
            {latestEvent ? (
              <pre className="code-block" style={{ borderLeft: '2px solid var(--success)', maxHeight: 250, overflowY: 'auto', fontSize: 10.5 }}>
                {ocsfJsonStr}
              </pre>
            ) : (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                No committed events yet.<br/>
                Inject logs to see the final OCSF JSON output here.
              </div>
            )}
            <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
              {latestEvent ? (
                <>
                  <span className="badge badge-success">COMMITTED</span>
                  <span className="badge badge-accent">Class 4001</span>
                  <span className="badge badge-muted">NormalizedStorage</span>
                </>
              ) : (
                <span className="badge badge-warning">WAITING</span>
              )}
            </div>
          </div>
        </div>

        {/* Arrow */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
          <svg width="60" height="1" viewBox="0 0 60 1" style={{ overflow: 'visible' }}>
            <line x1="0" y1="0" x2="50" y2="0" stroke="var(--border)" strokeWidth="1" strokeDasharray="4 3" />
            <polygon points="50,0 44,-4 44,4" fill="var(--text-3)" transform="translate(0,0.5)" />
          </svg>
          <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-3)', letterSpacing: '0.08em' }}>
            DISPATCH
          </span>
        </div>

        {/* Destination systems */}
        <div className="output-destinations">
          {DESTINATIONS.map((dest, i) => (
            <div className="output-dest card" key={i} id={`output-dest-${i}`}>
              <div
                className="output-dest-icon"
                style={{ background: `${dest.color}18`, border: `1px solid ${dest.color}30` }}
              >
                {dest.icon}
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 2 }}>
                  {dest.name}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                  {dest.desc}
                </div>
              </div>
              <span
                className="dot dot-success"
                style={{ marginLeft: 'auto', flexShrink: 0 }}
              />
            </div>
          ))}
        </div>
      </div>

      {/* REST API reference */}
      <div className="card" style={{ marginTop: 24 }}>
        <div className="console-card-header">
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-3)' }}>REST API</span>
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
            http://localhost:8000
          </span>
        </div>
        <div className="card-pad">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { method: 'GET',  path: '/api/v1/events',       desc: 'Paginated OCSF table' },
              { method: 'GET',  path: '/api/v1/metrics',      desc: 'Pipeline telemetry' },
              { method: 'POST', path: '/api/v1/ingest',       desc: 'Batch log ingestion' },
              { method: 'GET',  path: '/api/v1/parsers',      desc: 'Active parser registry' },
            ].map(({ method, path, desc }) => (
              <div
                key={path}
                style={{
                  background: 'var(--bg)', borderRadius: 'var(--radius)',
                  padding: '10px 12px', border: '1px solid var(--border)',
                }}
              >
                <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                  <span className={`badge ${method === 'GET' ? 'badge-accent' : 'badge-success'}`}
                    style={{ fontSize: 9 }}>
                    {method}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)', marginBottom: 4 }}>
                  {path}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
