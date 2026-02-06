'use client';

/**
 * Stvor Landing Page
 * 
 * Investor-grade, credibility-first landing page for a deep-tech cybersecurity startup.
 * Design philosophy: Calm, confident, technically honest.
 * Visual style: Dark theme, minimalist, academic + modern (Signal / Linear / Stripe Docs vibe)
 * Color scheme: Hacker green (#00ff00 family)
 */

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';

// ============================================================================
// LATTICE VISUALIZATION COMPONENT
// Abstract cryptographic visualization - no lock icons, no hacker clichés
// ============================================================================

function LatticeVisualization() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>();
  const mouseRef = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = canvas.width = canvas.offsetWidth * 2;
    let height = canvas.height = canvas.offsetHeight * 2;
    ctx.scale(2, 2);

    // Lattice points
    interface Point {
      x: number;
      y: number;
      baseX: number;
      baseY: number;
      vx: number;
      vy: number;
    }

    const points: Point[] = [];
    const gridSize = 60;
    const cols = Math.ceil(width / 2 / gridSize) + 2;
    const rows = Math.ceil(height / 2 / gridSize) + 2;

    // Initialize lattice grid
    for (let i = 0; i < cols; i++) {
      for (let j = 0; j < rows; j++) {
        const x = i * gridSize - gridSize;
        const y = j * gridSize - gridSize;
        points.push({
          x,
          y,
          baseX: x,
          baseY: y,
          vx: 0,
          vy: 0,
        });
      }
    }

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseRef.current = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      };
    };

    canvas.addEventListener('mousemove', handleMouseMove);

    let time = 0;

    const animate = () => {
      time += 0.008;
      ctx.fillStyle = 'rgba(8, 8, 12, 1)';
      ctx.fillRect(0, 0, width / 2, height / 2);

      // Update points with subtle wave motion
      for (const point of points) {
        const wave = Math.sin(point.baseX * 0.01 + time) * Math.cos(point.baseY * 0.01 + time * 0.7);
        point.x = point.baseX + wave * 8;
        point.y = point.baseY + Math.cos(point.baseX * 0.008 + time * 0.5) * 6;

        // Mouse interaction - subtle repulsion
        const dx = mouseRef.current.x - point.x;
        const dy = mouseRef.current.y - point.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const force = (120 - dist) / 120;
          point.x -= dx * force * 0.15;
          point.y -= dy * force * 0.15;
        }
      }

      // Draw connections - green color
      ctx.strokeStyle = 'rgba(34, 197, 94, 0.08)';
      ctx.lineWidth = 1;

      for (let i = 0; i < points.length; i++) {
        for (let j = i + 1; j < points.length; j++) {
          const dx = points[i].x - points[j].x;
          const dy = points[i].y - points[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < gridSize * 1.5) {
            const alpha = (1 - dist / (gridSize * 1.5)) * 0.12;
            ctx.strokeStyle = `rgba(34, 197, 94, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(points[i].x, points[i].y);
            ctx.lineTo(points[j].x, points[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw points - green color
      for (const point of points) {
        const distFromMouse = Math.sqrt(
          Math.pow(mouseRef.current.x - point.x, 2) +
          Math.pow(mouseRef.current.y - point.y, 2)
        );
        const highlight = distFromMouse < 100 ? 0.6 : 0.25;
        
        ctx.fillStyle = `rgba(74, 222, 128, ${highlight})`;
        ctx.beginPath();
        ctx.arc(point.x, point.y, 2, 0, Math.PI * 2);
        ctx.fill();
      }

      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      width = canvas.width = canvas.offsetWidth * 2;
      height = canvas.height = canvas.offsetHeight * 2;
      ctx.scale(2, 2);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      canvas.removeEventListener('mousemove', handleMouseMove);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full opacity-60"
      style={{ background: 'transparent' }}
    />
  );
}

// ============================================================================
// SECTION COMPONENTS
// ============================================================================

function NavBar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 30);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
      scrolled ? 'bg-[#08080c]/95 backdrop-blur-md border-b border-white/5' : 'bg-transparent'
    }`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 sm:py-4 flex items-center justify-between">
        <Link href="/main" className="text-lg sm:text-xl font-semibold tracking-tight text-white">
          Stvor
        </Link>
        
        {/* Desktop menu */}
        <div className="hidden lg:flex items-center gap-6 text-sm text-zinc-400">
          <a href="#products" className="hover:text-white transition-colors">Products</a>
          <a href="#security" className="hover:text-white transition-colors">Security</a>
          <a href="#invest" className="hover:text-emerald-400 transition-colors">Investors</a>
          <a href="https://github.com/sapogeth/stvor" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">GitHub</a>
        </div>
        
        {/* Desktop CTA */}
        <Link 
          href="/chat"
          className="hidden sm:inline-flex px-4 py-2 text-sm font-medium text-white bg-white/10 rounded-lg hover:bg-white/15 transition-colors"
        >
          Open Messenger
        </Link>
        
        {/* Mobile menu button */}
        <button 
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="lg:hidden p-2 text-zinc-400 hover:text-white"
          aria-label="Toggle menu"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            {mobileMenuOpen ? (
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            ) : (
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            )}
          </svg>
        </button>
      </div>
      
      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden bg-[#08080c]/98 backdrop-blur-md border-b border-white/5 px-4 py-4 space-y-4">
          <a href="#products" className="block text-sm text-zinc-400 hover:text-white transition-colors" onClick={() => setMobileMenuOpen(false)}>Products</a>
          <a href="#security" className="block text-sm text-zinc-400 hover:text-white transition-colors" onClick={() => setMobileMenuOpen(false)}>Security</a>
          <a href="#invest" className="block text-sm text-emerald-400 hover:text-emerald-300 transition-colors" onClick={() => setMobileMenuOpen(false)}>Investors</a>
          <a href="https://github.com/sapogeth/stvor" target="_blank" rel="noopener noreferrer" className="block text-sm text-zinc-400 hover:text-white transition-colors" onClick={() => setMobileMenuOpen(false)}>GitHub</a>
          <Link 
            href="/chat"
            className="inline-flex sm:hidden px-4 py-2 text-sm font-medium text-white bg-white/10 rounded-lg hover:bg-white/15 transition-colors w-full justify-center"
            onClick={() => setMobileMenuOpen(false)}
          >
            Open Messenger
          </Link>
        </div>
      )}
    </nav>
  );
}

function HeroSection() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden pt-20 sm:pt-24">
      <LatticeVisualization />
      
      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 text-center">
        <div className="mb-4 sm:mb-6">
          <span className="inline-block px-3 py-1 text-xs font-medium text-emerald-400 bg-emerald-500/10 rounded-full border border-emerald-500/20">
            Research-Grade Cryptography
          </span>
        </div>
        
        <h1 className="text-2xl sm:text-4xl md:text-5xl lg:text-6xl font-semibold tracking-tight text-white mb-4 sm:mb-6 leading-[1.15]">
          Post-Quantum Secure<br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-green-400">
            Messaging Infrastructure
          </span>
        </h1>
        
        <p className="text-sm sm:text-base md:text-lg text-zinc-400 max-w-2xl mx-auto mb-6 leading-relaxed">
          Research-grade E2EE protocol with mandated re-encapsulation.<br className="hidden sm:block" />
          Built for long-term confidentiality, not marketing demos.
        </p>
        
        {/* Funding signal in hero */}
        <p className="text-xs sm:text-sm text-emerald-400/80 mb-8 sm:mb-10">
          Currently raising a small pre-seed to continue post-quantum cryptographic R&D.
        </p>
        
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4 mb-6 sm:mb-8">
          <Link
            href="/chat"
            className="px-5 sm:px-6 py-2.5 sm:py-3 text-sm font-medium text-white bg-emerald-600 rounded-lg hover:bg-emerald-500 transition-colors w-full sm:w-auto min-w-[160px]"
          >
            View Messenger Demo
          </Link>
          <a
            href="#funding"
            className="px-5 sm:px-6 py-2.5 sm:py-3 text-sm font-medium text-white bg-white/10 rounded-lg hover:bg-white/15 transition-colors w-full sm:w-auto min-w-[160px]"
          >
            Funding Information
          </a>
        </div>
        
        <a
          href="https://sdk.stvor.xyz"
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs sm:text-sm text-zinc-500 hover:text-zinc-300 transition-colors inline-flex items-center gap-1"
        >
          Explore SDK Documentation →
        </a>
      </div>
      
      <div className="absolute bottom-6 sm:bottom-8 left-1/2 -translate-x-1/2 animate-bounce">
        <svg className="w-5 h-5 sm:w-6 sm:h-6 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
        </svg>
      </div>
    </section>
  );
}

function WhyNowSection() {
  return (
    <section className="py-16 sm:py-20 md:py-24 px-4 sm:px-6 bg-[#08080c] border-b border-white/5">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-10 sm:mb-12">
          <h2 className="text-xl sm:text-2xl md:text-3xl font-semibold text-white mb-3 sm:mb-4">
            Why Now
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base max-w-xl mx-auto">
            The window for post-quantum migration is open — and narrowing
          </p>
        </div>
        
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5 lg:gap-6">
          <div className="p-5 sm:p-6 rounded-xl bg-emerald-500/5 border border-emerald-500/10">
            <div className="text-emerald-400 font-mono text-xs sm:text-sm mb-2">2024</div>
            <h3 className="text-white font-medium mb-2 text-sm sm:text-base">NIST PQ Standards Finalized</h3>
            <p className="text-zinc-500 text-xs sm:text-sm">
              ML-KEM and ML-DSA are now official. The cryptographic foundation exists.
            </p>
          </div>
          
          <div className="p-5 sm:p-6 rounded-xl bg-emerald-500/5 border border-emerald-500/10">
            <div className="text-emerald-400 font-mono text-xs sm:text-sm mb-2">Now</div>
            <h3 className="text-white font-medium mb-2 text-sm sm:text-base">Messengers Are Not Re-architecting</h3>
            <p className="text-zinc-500 text-xs sm:text-sm">
              Major platforms are patching, not rebuilding. Session-level PQ remains rare.
            </p>
          </div>
          
          <div className="p-5 sm:p-6 rounded-xl bg-emerald-500/5 border border-emerald-500/10 sm:col-span-2 lg:col-span-1">
            <div className="text-emerald-400 font-mono text-xs sm:text-sm mb-2">Active</div>
            <h3 className="text-white font-medium mb-2 text-sm sm:text-base">Harvest-Now-Decrypt-Later</h3>
            <p className="text-zinc-500 text-xs sm:text-sm">
              State actors are collecting encrypted traffic today. The threat is not theoretical.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function WhatIsStvor() {
  return (
    <section className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#0a0a0f]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-10 sm:mb-14 md:mb-20">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            What is Stvor
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base max-w-xl mx-auto">
            A research-driven approach to post-quantum secure communications
          </p>
        </div>
        
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5 lg:gap-8">
          {/* Block 1 */}
          <div className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5">
            <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center mb-4 sm:mb-6">
              <svg className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
              </svg>
            </div>
            <h3 className="text-base sm:text-lg font-medium text-white mb-2 sm:mb-3">What it is</h3>
            <p className="text-zinc-400 text-xs sm:text-sm leading-relaxed mb-3 sm:mb-4">
              Stvor is a research-driven, post-quantum secure messaging stack:
            </p>
            <ul className="space-y-1.5 sm:space-y-2 text-xs sm:text-sm text-zinc-500">
              <li className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-emerald-500 shrink-0"></span>
                <span>E2EE Messenger</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-emerald-500 shrink-0"></span>
                <span>Developer SDK</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-emerald-500 shrink-0"></span>
                <span>Security Analysis Engine (Kenesary)</span>
              </li>
            </ul>
          </div>
          
          {/* Block 2 */}
          <div className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5">
            <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-green-500/10 flex items-center justify-center mb-4 sm:mb-6">
              <svg className="w-4 h-4 sm:w-5 sm:h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" />
              </svg>
            </div>
            <h3 className="text-base sm:text-lg font-medium text-white mb-2 sm:mb-3">Why it exists</h3>
            <p className="text-zinc-400 text-xs sm:text-sm leading-relaxed">
              Most messengers secure the handshake.
            </p>
            <p className="text-white text-xs sm:text-sm font-medium mt-2 sm:mt-4">
              Stvor secures the entire session lifecycle.
            </p>
            <p className="text-zinc-500 text-xs sm:text-sm mt-2 sm:mt-4 leading-relaxed">
              We address the harvest-now-decrypt-later threat by implementing continuous post-quantum protection throughout the communication session.
            </p>
          </div>
          
          {/* Block 3 */}
          <div className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5 sm:col-span-2 lg:col-span-1">
            <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-teal-500/10 flex items-center justify-center mb-4 sm:mb-6">
              <svg className="w-4 h-4 sm:w-5 sm:h-5 text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <h3 className="text-base sm:text-lg font-medium text-white mb-3 sm:mb-4">What makes it different</h3>
            <ul className="space-y-2.5 sm:space-y-3 text-xs sm:text-sm">
              <li className="flex items-start gap-2.5 sm:gap-3">
                <span className="w-1.5 h-1.5 rounded-full bg-teal-500 mt-1.5 sm:mt-2 shrink-0"></span>
                <span className="text-zinc-400">
                  <span className="text-white font-medium">Mandated re-encapsulation</span> — periodic key refresh using post-quantum primitives
                </span>
              </li>
              <li className="flex items-start gap-2.5 sm:gap-3">
                <span className="w-1.5 h-1.5 rounded-full bg-teal-500 mt-1.5 sm:mt-2 shrink-0"></span>
                <span className="text-zinc-400">
                  <span className="text-white font-medium">Hybrid PQ cryptography</span> — classical + post-quantum for defense in depth
                </span>
              </li>
              <li className="flex items-start gap-2.5 sm:gap-3">
                <span className="w-1.5 h-1.5 rounded-full bg-teal-500 mt-1.5 sm:mt-2 shrink-0"></span>
                <span className="text-zinc-400">
                  <span className="text-white font-medium">Honest threat model disclosure</span> — we document risks, not hide them
                </span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}

function CoreProducts() {
  const products = [
    {
      title: 'Stvor Messenger',
      description: 'Browser-native end-to-end encrypted messaging with post-quantum secure sessions and zero-knowledge relay architecture.',
      features: ['Browser-native E2EE', 'Post-quantum secure sessions', 'Zero-knowledge relay'],
      link: '/chat',
      linkText: 'Open Messenger',
      gradient: 'from-emerald-500 to-green-500',
    },
    {
      title: 'Stvor SDK',
      description: 'Drop-in E2EE for developers. Implements X3DH + Double Ratchet with post-quantum extensions in a type-safe TypeScript API.',
      features: ['Drop-in E2EE for developers', 'X3DH + Double Ratchet + PQ', 'Type-safe TypeScript API'],
      link: 'https://sdk.stvor.xyz',
      linkText: 'View Documentation',
      gradient: 'from-green-500 to-teal-500',
      external: true,
    },
    {
      title: 'Kenesary Security Engine',
      description: 'Multi-perspective security analysis with explicit assumptions and confidence levels. Read-only static analysis for protocol verification.',
      features: ['Multi-perspective security analysis', 'Explicit assumptions & confidence levels', 'Read-only static analysis'],
      link: 'https://kenesary.stvor.xyz',
      linkText: 'Explore Engine',
      gradient: 'from-teal-500 to-cyan-500',
      external: true,
    },
  ];

  return (
    <section id="products" className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#08080c]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-10 sm:mb-14 md:mb-20">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            Core Products
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base max-w-xl mx-auto">
            Three integrated components for secure communications infrastructure
          </p>
        </div>
        
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5 lg:gap-6">
          {products.map((product, index) => (
            <div
              key={index}
              className="group relative p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5 hover:border-white/10 transition-all duration-300"
            >
              <div className={`absolute inset-0 rounded-xl sm:rounded-2xl bg-gradient-to-br ${product.gradient} opacity-0 group-hover:opacity-[0.03] transition-opacity duration-300`} />
              
              <div className="relative">
                <h3 className="text-base sm:text-lg lg:text-xl font-medium text-white mb-2 sm:mb-3">{product.title}</h3>
                <p className="text-zinc-400 text-xs sm:text-sm leading-relaxed mb-5 sm:mb-6">
                  {product.description}
                </p>
                
                <ul className="space-y-1.5 sm:space-y-2 mb-6 sm:mb-8">
                  {product.features.map((feature, i) => (
                    <li key={i} className="flex items-center gap-2 text-xs sm:text-sm text-zinc-500">
                      <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
                
                {product.external ? (
                  <a
                    href={product.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 sm:gap-2 text-xs sm:text-sm font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
                  >
                    {product.linkText}
                    <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                ) : (
                  <Link
                    href={product.link}
                    className="inline-flex items-center gap-1.5 sm:gap-2 text-xs sm:text-sm font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
                  >
                    {product.linkText}
                    <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
                    </svg>
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function SecurityResearch() {
  return (
    <section id="security" className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#0a0a0f]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-10 sm:mb-14 md:mb-20">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            Security & Research Depth
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base max-w-xl mx-auto">
            Academic rigor meets practical implementation
          </p>
        </div>
        
        <div className="grid sm:grid-cols-2 gap-4 sm:gap-5 lg:gap-8 mb-8 sm:mb-10 md:mb-12">
          <div className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5">
            <h3 className="text-base sm:text-lg font-medium text-white mb-5 sm:mb-6">Threat Model</h3>
            <div className="space-y-4">
              <div className="flex items-start gap-3 sm:gap-4">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                  <span className="text-red-400 text-xs font-mono">DY</span>
                </div>
                <div>
                  <p className="text-white text-sm font-medium">Dolev-Yao Adversary</p>
                  <p className="text-zinc-500 text-xs sm:text-sm">Full network control, message interception, injection, and replay capabilities</p>
                </div>
              </div>
              <div className="flex items-start gap-3 sm:gap-4">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-orange-500/10 flex items-center justify-center shrink-0">
                  <span className="text-orange-400 text-xs font-mono">Q</span>
                </div>
                <div>
                  <p className="text-white text-sm font-medium">Quantum Adversary</p>
                  <p className="text-zinc-500 text-xs sm:text-sm">Cryptographically relevant quantum computer with harvest-now-decrypt-later capability</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5">
            <h3 className="text-base sm:text-lg font-medium text-white mb-5 sm:mb-6">Formal Verification</h3>
            <div className="space-y-4">
              <div className="flex items-start gap-3 sm:gap-4">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0">
                  <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <p className="text-white text-sm font-medium">LaTeX Whitepaper</p>
                  <p className="text-zinc-500 text-xs sm:text-sm">Formal specification with complete protocol description and security proofs</p>
                </div>
              </div>
              <div className="flex items-start gap-3 sm:gap-4">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-blue-500/10 flex items-center justify-center shrink-0">
                  <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                  </svg>
                </div>
                <div>
                  <p className="text-white text-sm font-medium">Game-Based Proof Sketch</p>
                  <p className="text-zinc-500 text-xs sm:text-sm">Security reduction to standard cryptographic assumptions</p>
                </div>
              </div>
              <div className="flex items-start gap-3 sm:gap-4">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-yellow-500/10 flex items-center justify-center shrink-0">
                  <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div>
                  <p className="text-white text-sm font-medium">ProVerif Analysis</p>
                  <p className="text-zinc-500 text-xs sm:text-sm">Partial verification — honest status, work in progress</p>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div className="p-4 sm:p-5 md:p-6 rounded-xl bg-emerald-500/5 border border-emerald-500/10 text-center">
          <p className="text-emerald-300 text-xs sm:text-sm font-medium">
            "Residual risks are documented, not hidden."
          </p>
        </div>
      </div>
    </section>
  );
}

function CryptographyStack() {
  const stack = [
    {
      component: 'Key Exchange',
      classical: 'X25519',
      postQuantum: 'ML-KEM-768',
      standard: 'NIST FIPS 203',
    },
    {
      component: 'Signatures',
      classical: 'Ed25519',
      postQuantum: 'ML-DSA-65',
      standard: 'NIST FIPS 204',
    },
    {
      component: 'AEAD',
      classical: 'ChaCha20-Poly1305',
      postQuantum: '—',
      standard: 'RFC 8439',
    },
    {
      component: 'Ratchet',
      classical: 'Double Ratchet',
      postQuantum: 'Re-encapsulation cadence',
      standard: 'Signal Protocol + PQ ext.',
    },
  ];

  return (
    <section id="cryptography" className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#08080c]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-10 sm:mb-14 md:mb-20">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            Cryptography Stack
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base max-w-xl mx-auto">
            Hybrid classical + post-quantum primitives for defense in depth
          </p>
        </div>
        
        <div className="overflow-x-auto -mx-4 sm:mx-0 sm:overflow-visible">
          <div className="min-w-full sm:min-w-0">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left py-3 px-4 text-xs sm:text-sm font-medium text-zinc-400">Component</th>
                  <th className="text-left py-3 px-4 text-xs sm:text-sm font-medium text-zinc-400">Classical</th>
                  <th className="text-left py-3 px-4 text-xs sm:text-sm font-medium text-zinc-400">Post-Quantum</th>
                  <th className="text-left py-3 px-4 text-xs sm:text-sm font-medium text-zinc-400">Standard</th>
                </tr>
              </thead>
              <tbody>
                {stack.map((row, index) => (
                  <tr key={index} className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                    <td className="py-3 px-4 text-xs sm:text-sm text-white font-medium">{row.component}</td>
                    <td className="py-3 px-4 text-xs sm:text-sm text-zinc-400 font-mono">{row.classical}</td>
                    <td className="py-3 px-4 text-xs sm:text-sm text-emerald-400 font-mono">{row.postQuantum}</td>
                    <td className="py-3 px-4 text-xs sm:text-sm text-zinc-500">{row.standard}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  );
}

function PerformanceTradeoffs() {
  const metrics = [
    { label: 'Handshake latency', value: '~45ms', note: 'ARM (Apple M1)' },
    { label: 'Message overhead', value: '+11%', note: 'vs. classical-only' },
    { label: 'Re-encapsulation', value: '24h / 2²⁰', note: 'time or message count' },
  ];

  return (
    <section className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#0a0a0f]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-10 sm:mb-14 md:mb-20">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            Performance & Trade-offs
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base max-w-xl mx-auto">
            Measured numbers, no excuses
          </p>
        </div>
        
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5 lg:gap-6 mb-8 sm:mb-10 md:mb-12">
          {metrics.map((metric, index) => (
            <div key={index} className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5 text-center">
              <p className="text-2xl sm:text-3xl md:text-4xl font-semibold text-white mb-2 font-mono">
                {metric.value}
              </p>
              <p className="text-xs sm:text-sm text-zinc-400 mb-1">{metric.label}</p>
              <p className="text-xs text-zinc-600">{metric.note}</p>
            </div>
          ))}
        </div>
        
        <div className="p-4 sm:p-5 md:p-6 rounded-xl bg-white/[0.02] border border-white/5 text-center">
          <p className="text-zinc-400 text-xs sm:text-sm">
            Stvor prioritizes <span className="text-white font-medium">long-term confidentiality</span> over minimal bandwidth.
          </p>
        </div>
      </div>
    </section>
  );
}

function HonestLimitations() {
  const limitations = [
    {
      title: 'Metadata leakage',
      description: 'Timing, message sizes, and communication patterns are visible to the relay. Documented in threat model.',
    },
    {
      title: 'No multi-device sync',
      description: 'Single-device architecture by design. Multi-device introduces key management complexity.',
    },
    {
      title: 'Browser security assumptions',
      description: 'Relies on browser sandbox, WebCrypto, and secure context. Not suitable for high-assurance environments.',
    },
    {
      title: 'Audit pending',
      description: 'No third-party security audit completed. Protocol is research-grade, not production-hardened.',
    },
  ];

  return (
    <section className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#08080c]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-10 sm:mb-14 md:mb-20">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            Honest Limitations
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base max-w-xl mx-auto">
            We believe transparency is a security feature
          </p>
        </div>
        
        <div className="grid sm:grid-cols-2 gap-4 sm:gap-5 lg:gap-6">
          {limitations.map((limitation, index) => (
            <div key={index} className="p-4 sm:p-5 md:p-6 rounded-xl bg-white/[0.02] border border-white/5">
              <div className="flex items-start gap-3 sm:gap-4">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-amber-500/10 flex items-center justify-center shrink-0">
                  <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-white text-sm font-medium mb-1">{limitation.title}</h3>
                  <p className="text-zinc-500 text-xs sm:text-sm">{limitation.description}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function FundingSection() {
  return (
    <section id="funding" className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#0a0a0f]">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-10 sm:mb-14 md:mb-16">
          <span className="inline-block px-3 py-1 text-xs font-medium text-emerald-400 bg-emerald-500/10 rounded-full border border-emerald-500/20 mb-4 sm:mb-6">
            Pre-Seed
          </span>
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            Funding Status
          </h2>
          <p className="text-zinc-400 text-sm sm:text-base max-w-2xl mx-auto leading-relaxed mb-3 sm:mb-4">
            Stvor is currently raising a small pre-seed round ($100k–$250k) to continue cryptographic R&D, formal verification, and independent security auditing.
          </p>
          <p className="text-zinc-600 text-xs sm:text-sm">
            Actively exploring cyber / deep-tech accelerators and research-aligned investors.
          </p>
        </div>
        
        <div className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-emerald-500/5 border border-emerald-500/10 mb-8 sm:mb-10 md:mb-12">
          <h3 className="text-white font-medium mb-4 sm:mb-5 text-sm sm:text-base">This funding extends the project runway by 6 months and enables:</h3>
          <ul className="space-y-3 sm:space-y-4">
            <li className="flex items-start gap-3 sm:gap-4">
              <div className="w-5 h-5 sm:w-6 sm:h-6 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0 mt-0.5">
                <span className="text-emerald-400 text-xs font-mono">1</span>
              </div>
              <div>
                <p className="text-white text-sm font-medium">Complete ProVerif model for multi-epoch ratcheting</p>
                <p className="text-zinc-500 text-xs sm:text-sm">Formal verification of the re-encapsulation protocol</p>
              </div>
            </li>
            <li className="flex items-start gap-3 sm:gap-4">
              <div className="w-5 h-5 sm:w-6 sm:h-6 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0 mt-0.5">
                <span className="text-emerald-400 text-xs font-mono">2</span>
              </div>
              <div>
                <p className="text-white text-sm font-medium">Increase test coverage to &gt;70%</p>
                <p className="text-zinc-500 text-xs sm:text-sm">Comprehensive unit and integration testing across the stack</p>
              </div>
            </li>
            <li className="flex items-start gap-3 sm:gap-4">
              <div className="w-5 h-5 sm:w-6 sm:h-6 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0 mt-0.5">
                <span className="text-emerald-400 text-xs font-mono">3</span>
              </div>
              <div>
                <p className="text-white text-sm font-medium">External cryptographic audit (scope defined)</p>
                <p className="text-zinc-500 text-xs sm:text-sm">Third-party review of cryptographic implementation & protocol invariants</p>
              </div>
            </li>
          </ul>
        </div>
        
        <div className="text-center">
          <p className="text-zinc-500 text-xs sm:text-sm mb-5 sm:mb-6">
            For investors interested in post-quantum security infrastructure
          </p>
          <a
            href="mailto:izahii@protonmail.com?subject=Stvor Pre-Seed Investment Inquiry"
            className="inline-flex items-center gap-2 px-6 py-3 sm:px-8 sm:py-4 text-sm font-medium text-white bg-emerald-600 rounded-lg hover:bg-emerald-500 transition-colors"
          >
            Discuss Pre-Seed / Research Funding
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
            </svg>
          </a>
        </div>
      </div>
    </section>
  );
}

function FounderSection() {
  return (
    <section className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-[#08080c]">
      <div className="max-w-3xl mx-auto">
        <div className="text-center mb-10 sm:mb-12">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-3 sm:mb-4">
            Founder
          </h2>
          <p className="text-zinc-500 text-sm sm:text-base">
            Why this person, why this project
          </p>
        </div>
        
        <div className="p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-white/[0.02] border border-white/5">
          <div className="space-y-4 sm:space-y-5">
            <div className="flex items-start gap-3 sm:gap-4">
              <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0">
                <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
              </div>
              <div>
                <p className="text-white text-sm font-medium">Cryptography-focused engineer</p>
                <p className="text-zinc-500 text-xs sm:text-sm">Deep expertise in applied cryptography and secure protocol design</p>
              </div>
            </div>
            
            <div className="flex items-start gap-3 sm:gap-4">
              <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0">
                <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                </svg>
              </div>
              <a
                href="https://eprint.iacr.org/2025/1713"
                target="_blank"
                rel="noopener noreferrer"
                className="block hover:bg-white/5 rounded-lg -m-2 p-2 -ml-2 transition-colors"
              >
                <p className="text-white text-sm font-medium">IACR ePrint publication</p>
                <p className="text-zinc-500 text-xs sm:text-sm">Post-quantum handshake protocol research</p>
              </a>
            </div>
            
            <div className="flex items-start gap-3 sm:gap-4">
              <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0">
                <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                </svg>
              </div>
              <div>
                <p className="text-white text-sm font-medium">Built full E2EE stack solo (47k+ LOC)</p>
                <p className="text-zinc-500 text-xs sm:text-sm">Messenger, SDK, relay, and security analysis engine</p>
              </div>
            </div>
            
            <div className="flex items-start gap-3 sm:gap-4">
              <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0">
                <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <div>
                <p className="text-white text-sm font-medium">Research-first, security-honest philosophy</p>
                <p className="text-zinc-500 text-xs sm:text-sm">Prioritizes correctness and transparency over speed-to-market</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function CallToAction() {
  return (
    <section className="py-16 sm:py-20 md:py-28 px-4 sm:px-6 bg-gradient-to-b from-[#0a0a0f] to-[#08080c]">
      <div className="max-w-4xl mx-auto text-center">
        <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-white mb-4 sm:mb-6 md:mb-12">
          Get Started
        </h2>
        <p className="text-zinc-500 text-sm sm:text-base mb-8 sm:mb-10 md:mb-12 max-w-xl mx-auto">
          Choose your path into the Stvor ecosystem
        </p>
        
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5 lg:gap-6">
          <Link
            href="/chat"
            className="group p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/15 hover:border-emerald-500/30 transition-all"
          >
            <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-emerald-500/20 flex items-center justify-center mx-auto mb-3 sm:mb-4 group-hover:scale-110 transition-transform">
              <svg className="w-5 h-5 sm:w-6 sm:h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
            </div>
            <h3 className="text-white font-medium mb-2 text-sm sm:text-base">Try the Messenger</h3>
            <p className="text-zinc-500 text-xs sm:text-sm">Experience post-quantum E2EE in your browser</p>
          </Link>
          
          <a
            href="https://sdk.stvor.xyz"
            target="_blank"
            rel="noopener noreferrer"
            className="group p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-green-500/10 border border-green-500/20 hover:bg-green-500/15 hover:border-green-500/30 transition-all"
          >
            <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-green-500/20 flex items-center justify-center mx-auto mb-3 sm:mb-4 group-hover:scale-110 transition-transform">
              <svg className="w-5 h-5 sm:w-6 sm:h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
            </div>
            <h3 className="text-white font-medium mb-2 text-sm sm:text-base">Integrate the SDK</h3>
            <p className="text-zinc-500 text-xs sm:text-sm">Add E2EE to your application</p>
          </a>
          
          <a
            href="mailto:izahii@protonmail.com?subject=Stvor Pre-Seed Investment Inquiry"
            className="group p-5 sm:p-6 lg:p-8 rounded-xl sm:rounded-2xl bg-teal-500/10 border border-teal-500/20 hover:bg-teal-500/15 hover:border-teal-500/30 transition-all sm:col-span-2 lg:col-span-1"
          >
            <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-teal-500/20 flex items-center justify-center mx-auto mb-3 sm:mb-4 group-hover:scale-110 transition-transform">
              <svg className="w-5 h-5 sm:w-6 sm:h-6 text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-white font-medium mb-2 text-sm sm:text-base">Discuss Funding</h3>
            <p className="text-zinc-500 text-xs sm:text-sm">For investors in PQ security infrastructure</p>
          </a>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="py-10 sm:py-12 md:py-16 px-4 sm:px-6 bg-[#08080c] border-t border-white/5">
      <div className="max-w-6xl mx-auto">
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8 sm:gap-6 lg:gap-12 mb-10 sm:mb-12">
          <div>
            <h3 className="text-white font-semibold mb-3 sm:mb-4">Stvor</h3>
            <p className="text-zinc-500 text-xs sm:text-sm leading-relaxed">
              Post-quantum secure messaging infrastructure for the long term.
            </p>
          </div>
          
          <div>
            <h4 className="text-zinc-400 text-xs sm:text-sm font-medium mb-3 sm:mb-4">Products</h4>
            <ul className="space-y-2">
              <li><Link href="/chat" className="text-zinc-500 text-xs sm:text-sm hover:text-white transition-colors">Messenger</Link></li>
              <li><a href="https://sdk.stvor.xyz" target="_blank" rel="noopener noreferrer" className="text-zinc-500 text-xs sm:text-sm hover:text-white transition-colors">SDK</a></li>
              <li><a href="https://kenesary.stvor.xyz" target="_blank" rel="noopener noreferrer" className="text-zinc-500 text-xs sm:text-sm hover:text-white transition-colors">Kenesary</a></li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-zinc-400 text-xs sm:text-sm font-medium mb-3 sm:mb-4">Resources</h4>
            <ul className="space-y-2">
              <li><a href="/whitepaper.pdf" className="text-zinc-500 text-xs sm:text-sm hover:text-white transition-colors">Whitepaper</a></li>
              <li><Link href="/security" className="text-zinc-500 text-xs sm:text-sm hover:text-white transition-colors">Security Docs</Link></li>
              <li><a href="https://github.com/sapogeth/stvor" target="_blank" rel="noopener noreferrer" className="text-zinc-500 text-xs sm:text-sm hover:text-white transition-colors">GitHub</a></li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-zinc-400 text-xs sm:text-sm font-medium mb-3 sm:mb-4">Contact</h4>
            <ul className="space-y-2">
              <li><a href="mailto:izahii@protonmail.com" className="text-zinc-500 text-xs sm:text-sm hover:text-white transition-colors">izahii@protonmail.com</a></li>
            </ul>
          </div>
        </div>
        
        <div className="pt-6 sm:pt-8 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between gap-3 sm:gap-4">
          <p className="text-zinc-600 text-xs">
            Stvor — stvor.xyz
          </p>
          <p className="text-zinc-600 text-xs">
            Research-grade cryptography. Honest documentation.
          </p>
        </div>
      </div>
    </footer>
  );
}

// ============================================================================
// MAIN PAGE COMPONENT
// ============================================================================

export default function MainPage() {
  return (
    <main className="min-h-screen bg-[#08080c] text-white antialiased selection:bg-emerald-500/30">
      <NavBar />
      <HeroSection />
      <WhyNowSection />
      <WhatIsStvor />
      <CoreProducts />
      <SecurityResearch />
      <CryptographyStack />
      <PerformanceTradeoffs />
      <HonestLimitations />
      
      {/* Investor Section - accessible via /main#invest */}
      <section id="invest">
        <FundingSection />
        <FounderSection />
      </section>
      
      <CallToAction />
      <Footer />
    </main>
  );
}
