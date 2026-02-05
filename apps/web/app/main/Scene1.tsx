'use client';

import { useEffect, useRef } from 'react';

/**
 * Stream: A persistent vertical column of binary digits
 * 
 * Lives like a waterfall - continuous flow of 0s and 1s
 * falling from top to bottom
 */
interface Stream {
  x: number;
  y: number;
  speed: number;
  symbols: string[];
  symbolIndex: number;
  length: number;
  opacity: number;
}

/**
 * Scene 1: "Digital Waterfall"
 *
 * A continuous waterfall of falling binary digits (0 and 1).
 * 
 * Like water cascading down, except it's data flowing.
 * Philosophy:
 * - Dense, continuous streams
 * - Always-on waterfalls across the screen
 * - Bright enough to see clearly
 * - Smooth, calm motion
 * - Infrastructure-scale data flow
 * 
 * Aesthetic:
 * - Dark green (#0fX range) on pure black
 * - No glow, no blur, no neon
 * - Clean monospace digits
 * - Readable but not harsh
 */
export function Scene1() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamsRef = useRef<Stream[]>([]);
  const animationFrameRef = useRef<number>();
  const prefersReducedMotionRef = useRef(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Check reduced motion preference
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    prefersReducedMotionRef.current = mediaQuery.matches;

    const handleMotionPreference = (e: MediaQueryListEvent) => {
      prefersReducedMotionRef.current = e.matches;
    };
    mediaQuery.addListener(handleMotionPreference);

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      initializeStreams();
    };

    /**
     * Generate persistent symbols for a stream
     */
    const generateSymbols = (count: number): string[] => {
      const symbols: string[] = [];
      for (let i = 0; i < count; i++) {
        symbols.push(Math.random() > 0.5 ? '0' : '1');
      }
      return symbols;
    };

    /**
     * Create stream that falls like water
     */
    const createStream = (x: number): Stream => {
      const speed = 1.0 + Math.random() * 0.8; // 1.0-1.8 px/frame (flowing)
      const length = 25 + Math.floor(Math.random() * 20); // 25-45 symbols (full column)
      
      return {
        x,
        y: -length * 11, // Start above canvas
        speed,
        symbols: generateSymbols(length * 3),
        symbolIndex: 0,
        length,
        opacity: 1,
      };
    };

    const initializeStreams = () => {
      streamsRef.current = [];
      
      // Create waterfall across entire width
      const columnSpacing = 12; // Very close - fill entire screen
      
      let x = 8;
      while (x < canvas.width) {
        streamsRef.current.push(createStream(x));
        x += columnSpacing;
      }
    };

    /**
     * Get brightness for position
     * Gradually fade at bottom like mist
     */
    const getBrightnessForPosition = (y: number): number => {
      const fadeStart = canvas.height * 0.9;
      const fadeEnd = canvas.height + 30;

      if (y > fadeStart) {
        const fadeRatio = Math.min(1, (y - fadeStart) / (fadeEnd - fadeStart));
        return Math.floor(80 * (1 - fadeRatio));
      }

      return 70 + Math.floor(Math.random() * 30); // 70-100 (visible, readable)
    };

    /**
     * Draw a flying eagle (BERKUT) made of 0s and 1s
     * Emerges from the waterfall on the left side
     */
    const drawBerkut = (time: number) => {
      // Eagle pattern - wings spread wide like a real eagle in flight
      const eaglePattern = [
        '11111           11111',
        '11111           11111',
        '11111           11111',
        '111111         111111',
        '111111         111111',
        '1111111       1111111',
        '11111111     11111111',
        '111111111   111111111',
        '1111111111 1111111111',
        '11111111111111111111',
        '111111111111111111111',
        '1111111111111111111111',
        '11111111111111111111',
        '1111111111 1111111111',
        '111111111   111111111',
        '11111111     11111111',
        '1111111       1111111',
        '111111         111111',
        '111111         111111',
        '11111           11111',
      ];

      const timeS = time / 1000;
      
      // Flying trajectory - sweeps across screen horizontally
      const cycleTime = (timeS * 0.4) % 1; // Full cycle every 2.5 seconds
      const x = cycleTime * (canvas.width + 400) - 200; // Left to right
      const baseY = canvas.height * 0.25;
      const wingFlap = Math.sin(timeS * 4) * 25; // Wing flapping
      const y = baseY + Math.sin(timeS * 1) * 40 + wingFlap;
      
      const scale = 1.2;

      ctx.font = 'bold 9px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      for (let row = 0; row < eaglePattern.length; row++) {
        const line = eaglePattern[row];
        for (let col = 0; col < line.length; col++) {
          const char = line[col];
          
          if (char === '1') {
            const px = x + (col - 10) * 8 * scale; // Center the eagle
            const py = y + row * 8 * scale;

            // Only draw if on screen
            if (px > -250 && px < canvas.width + 250 && py > -150 && py < canvas.height + 150) {
              // Dynamic brightness from wing flaps
              const flap = Math.abs(Math.sin(timeS * 4)) * 25;
              const brightness = 75 + Math.floor(flap) + Math.floor(Math.random() * 25);
              
              ctx.fillStyle = `rgb(0, ${brightness}, 0)`;
              ctx.globalAlpha = 0.93;
              ctx.fillText(char, px, py);
            }
          }
        }
      }
    };

    const animate = () => {
      if (prefersReducedMotionRef.current) {
        drawStaticFrame();
        return;
      }

      // Clear canvas
      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Update and draw all streams
      for (let i = 0; i < streamsRef.current.length; i++) {
        const stream = streamsRef.current[i];

        // Move stream down
        stream.y += stream.speed;

        // When stream exits bottom, respawn at top
        if (stream.y > canvas.height + 100) {
          stream.y = -stream.length * 11;
          stream.symbolIndex = Math.floor(Math.random() * stream.symbols.length / 2);
        }

        // Draw symbols in this stream
        ctx.font = 'bold 11px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        for (let j = 0; j < stream.length; j++) {
          const symbolY = stream.y + j * 11;

          // Skip if off-screen
          if (symbolY < -30 || symbolY > canvas.height + 30) {
            continue;
          }

          // Get symbol from persistent array
          const symbolIdx = (stream.symbolIndex + j) % stream.symbols.length;
          const symbol = stream.symbols[symbolIdx];

          // Calculate brightness
          const brightness = getBrightnessForPosition(symbolY);

          // Draw symbol (bright and visible like waterfall)
          ctx.fillStyle = `rgb(0, ${brightness}, 0)`;
          ctx.globalAlpha = brightness / 100;
          ctx.fillText(symbol, stream.x, symbolY);
        }

        ctx.globalAlpha = 1;
      }

      // Draw flying Berkut (Eagle)
      drawBerkut(Date.now());

      animationFrameRef.current = requestAnimationFrame(animate);
    };

    const drawStaticFrame = () => {
      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Draw calm waterfall snapshot
      for (const stream of streamsRef.current) {
        const startY = canvas.height / 3;

        ctx.font = 'bold 11px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        for (let j = 0; j < stream.length; j++) {
          const symbolY = startY + j * 11;
          const symbolIdx = j % stream.symbols.length;
          const symbol = stream.symbols[symbolIdx];
          const brightness = 70;

          ctx.fillStyle = `rgb(0, ${brightness}, 0)`;
          ctx.globalAlpha = brightness / 100;
          ctx.fillText(symbol, stream.x, symbolY);
        }
      }

      ctx.globalAlpha = 1;
    };

    // Initialize
    resizeCanvas();
    animationFrameRef.current = requestAnimationFrame(animate);

    // Handle resize
    const handleResize = () => {
      resizeCanvas();
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      mediaQuery.removeListener(handleMotionPreference);
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        display: 'block',
        zIndex: 1,
      }}
    />
  );
}
