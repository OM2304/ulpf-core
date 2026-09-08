import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { useLenis } from '../hooks/useLenis';
import Hero from '../components/Hero';
import PipelineSection from '../components/PipelineSection';
import LogExplorer from '../components/LogExplorer';
import SystemStatus from '../components/SystemStatus';
import OutputFlow from '../components/OutputFlow';
import Footer from '../components/Footer';


gsap.registerPlugin(ScrollTrigger);

export default function Landing() {
  useLenis();

  const mainRef = useRef<HTMLDivElement>(null);

  // Reveal animations for section headers
  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.utils.toArray<HTMLElement>('.reveal').forEach(el => {
        gsap.from(el, {
          opacity: 0,
          y: 24,
          duration: 0.6,
          ease: 'power2.out',
          scrollTrigger: {
            trigger: el,
            start: 'top 88%',
          },
        });
      });
    }, mainRef);
    return () => ctx.revert();
  }, []);

  return (
    <div ref={mainRef}>
      {/* Hero */}
      <Hero />

      {/* Divider with label */}
      <div className="container">
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '0 0 60px' }}>
          <div className="hr" style={{ flex: 1 }} />
          <span className="t-label">Processing Pipeline</span>
          <div className="hr" style={{ flex: 1 }} />
        </div>
      </div>

      {/* Pipeline Section — full width, scroll-pinned */}
      <PipelineSection />

      {/* Main content sections */}
      <div className="container">
        {/* Log Explorer */}
        <section className="section">
          <LogExplorer />
        </section>

        <hr className="hr" />

        {/* System Status + Metrics */}
        <section className="section" id="status">
          <SystemStatus />
        </section>

        <hr className="hr" />

        {/* Output Flow */}
        <section className="section">
          <OutputFlow />
        </section>
      </div>

      <Footer />
    </div>
  );
}
