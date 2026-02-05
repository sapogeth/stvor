'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import StudyLogo from './StudyLogo';
import { ChevronRight, ChevronLeft, Play, AlertTriangle, Eye, Skull, Target, Youtube, ChevronDown } from 'lucide-react';

type Section = 'intro' | 'probability' | 'linear' | 'games' | 'ake' | 'pq' | 'final';
type ViewMode = 'normal' | 'assumptions' | 'adversary' | 'failure';

const ModeIcons = {
  normal: Eye,
  assumptions: Target,
  adversary: Skull,
  failure: AlertTriangle,
};

// Concrete mental picture component
function MentalPicture({ picture }: { picture: string }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="p-5 bg-gradient-to-r from-purple-900/40 to-indigo-900/40 border-2 border-purple-600 rounded-xl mb-6">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 w-full text-left"
      >
        <div className="p-2 bg-purple-600 rounded-lg">
          <span className="text-xl">🧩</span>
        </div>
        <div className="flex-1">
          <div className="font-semibold text-purple-300">Concrete Mental Picture</div>
          <div className="text-sm text-purple-400/70">Click to build intuition</div>
        </div>
        <ChevronDown className={`text-purple-400 transition-transform ${expanded ? 'rotate-180' : ''}`} size={18} />
      </button>
      
      {expanded && (
        <div className="mt-4 p-4 bg-black/30 rounded-lg">
          <p className="text-gray-200 leading-relaxed">{picture}</p>
        </div>
      )}
    </div>
  );
}

// Where this appears in real systems
function RealSystems({ items, section }: { items: string[]; section: Section }) {
  const [expanded, setExpanded] = useState(false);

  const sectionIcons: Record<Section, string> = {
    probability: '🎲',
    linear: '📐',
    games: '🎯',
    ake: '🔄',
    pq: '⚛️',
    intro: '📚',
    final: '🎓',
  };

  const sectionLabels: Record<Section, string> = {
    probability: 'Probability',
    linear: 'Linear Algebra',
    games: 'Security Games',
    ake: 'Key Exchange',
    pq: 'Post-Quantum',
    intro: 'Introduction',
    final: 'Final Exam',
  };

  return (
    <div className="mt-6 p-4 bg-gray-800/50 border border-gray-700 rounded-xl">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 w-full text-left"
      >
        <div className="p-2 bg-green-700 rounded-lg">
          <span className="text-lg">{sectionIcons[section]}</span>
        </div>
        <div className="flex-1">
          <div className="font-semibold text-green-400">📍 Where This Appears in Real Systems</div>
          <div className="text-sm text-gray-400">Real code locations for {sectionLabels[section]}</div>
        </div>
        <ChevronRight className={`text-gray-400 transition-transform ${expanded ? 'rotate-90' : ''}`} size={18} />
      </button>

      {expanded && (
        <div className="mt-4 space-y-2">
          {items.map((item, i) => (
            <div key={i} className="flex items-center gap-2 p-2 bg-gray-900 rounded-lg">
              <span className="w-2 h-2 bg-green-500 rounded-full"></span>
              <span className="text-gray-300 text-sm font-mono">{item}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Narration component - human explanation layer
function NarrationSection({ 
  title, 
  what, 
  why, 
  misconception,
  onNext
}: { 
  title: string;
  what: string;
  why: string;
  misconception: string;
  onNext: () => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const [completed, setCompleted] = useState(false);

  const handleComplete = () => {
    setCompleted(true);
    onNext();
  };

  return (
    <div className={`p-6 rounded-xl border-2 transition-all ${
      completed ? 'border-green-500 bg-green-900/10' : 'border-blue-500 bg-blue-900/20'
    }`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 w-full text-left"
      >
        <div className={`p-2 rounded-lg ${completed ? 'bg-green-600' : 'bg-blue-600'}`}>
          {completed ? <Play size={16} className="text-white" /> : 
            expanded ? <ChevronDown size={16} className="text-white" /> : 
            <Play size={16} className="text-white" />}
        </div>
        <div className="flex-1">
          <div className="font-semibold text-white">📖 {title}</div>
          <div className="text-sm text-gray-400">
            {completed ? 'Understanding confirmed' : 'Read before proceeding'}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="mt-4 space-y-4">
          <div className="p-4 bg-gray-900/50 rounded-lg">
            <div className="text-blue-400 font-semibold mb-2">What you are about to see:</div>
            <p className="text-gray-300 leading-relaxed">{what}</p>
          </div>

          <div className="p-4 bg-gray-900/50 rounded-lg">
            <div className="text-purple-400 font-semibold mb-2">Why this exists in cryptography:</div>
            <p className="text-gray-300 leading-relaxed">{why}</p>
          </div>

          <div className="p-4 bg-orange-900/30 border border-orange-800 rounded-lg">
            <div className="text-orange-400 font-semibold mb-2">⚠️ How people misunderstand this:</div>
            <p className="text-gray-300 leading-relaxed">{misconception}</p>
          </div>

          {!completed && (
            <button
              onClick={handleComplete}
              className="w-full py-3 bg-green-600 hover:bg-green-500 rounded-lg font-medium flex items-center justify-center gap-2"
            >
              <Play size={18} /> I understand — show me what happens
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// Video reinforcement component
function VideoBlock({ videos }: { videos: Array<{title: string; creator: string; url: string; duration: string; why: string}> }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="mt-8 p-6 bg-gray-800/50 border border-gray-700 rounded-xl">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 w-full text-left"
      >
        <div className="p-2 bg-red-600 rounded-lg">
          <Youtube className="text-white" size={20} />
        </div>
        <div className="flex-1">
          <div className="font-semibold text-white">🎥 External Reinforcement</div>
          <div className="text-sm text-gray-400">Videos to confirm what already broke</div>
        </div>
        <ChevronRight className={`text-gray-400 transition-transform ${expanded ? 'rotate-90' : ''}`} size={20} />
      </button>

      {expanded && (
        <div className="mt-4 space-y-4">
          {videos.map((video, i) => (
            <a
              key={i}
              href={video.url}
              target="_blank"
              rel="noopener noreferrer"
              className="block p-4 bg-gray-900 rounded-lg hover:bg-gray-800 transition-colors"
            >
              <div className="flex items-start gap-3">
                <div className="p-1 bg-red-600 rounded mt-1">
                  <Play size={12} className="text-white" />
                </div>
                <div className="flex-1">
                  <div className="font-semibold text-blue-400 hover:underline">{video.title}</div>
                  <div className="text-sm text-gray-400">{video.creator} • {video.duration}</div>
                  <p className="text-sm text-gray-500 mt-2 italic">"{video.why}"</p>
                </div>
              </div>
            </a>
          ))}
          <div className="p-3 bg-red-900/20 border border-red-800 rounded text-sm text-gray-400">
            💡 <strong>Remember:</strong> These videos confirm concepts you already experienced through failure.
            They don't teach from scratch — they reinforce what broke.
          </div>
        </div>
      )}
    </div>
  );
}

// Video data for each section (only appear in failure mode)
const sectionVideos = {
  probability: [
    {
      title: 'StatQuest — Normal Distribution, Clearly Explained',
      creator: 'Josh Starmer',
      url: 'https://www.youtube.com/watch?v=rzFX5NWojp0',
      duration: '~5 min',
      why: 'To reinforce that normal-looking distributions still have tails where cryptographic failures live.'
    },
    {
      title: 'MIT OCW — 6.041 Probability (Expectation)',
      creator: 'MIT OpenCourseWare',
      url: 'https://ocw.mit.edu/courses/6-041-probabilistic-systems-analysis-and-applied-probability-fall-2010/',
      duration: '~50 min',
      why: 'To show why expectation is a mathematical average, not a security guarantee. Attackers exploit worst-case.'
    }
  ],
  linear: [
    {
      title: '3Blue1Brown — Essence of Linear Algebra',
      creator: '3Blue1Brown',
      url: 'https://www.youtube.com/watch?v=kYB8IZa5AuE',
      duration: '~10 min',
      why: 'To build intuition for linearity as structure preservation — not noise destruction.'
    },
    {
      title: 'Christof Paar — Linear Cryptanalysis',
      creator: 'Introduction to Cryptography',
      url: 'https://www.youtube.com/watch?v=6O6xQ5n0z6U',
      duration: '~20 min',
      why: 'To show how tiny biases survive linear operations and become full attacks.'
    }
  ],
  games: [
    {
      title: 'Dan Boneh — Cryptography I (IND-CPA intuition)',
      creator: 'Stanford',
      url: 'https://www.youtube.com/watch?v=j_7pD9iZs2A',
      duration: '~15 min',
      why: 'To hear indistinguishability explained as a game, not a formula.'
    },
    {
      title: 'Boaz Barak — What Security Proofs Do and Do Not Mean',
      creator: 'Boaz Barak',
      url: 'https://www.youtube.com/watch?v=Q0zZ8JZ9k6I',
      duration: '~30 min',
      why: 'To understand that proofs validate MODELS, not real systems.'
    }
  ],
  ake: [
    {
      title: 'Signal — Double Ratchet Explained',
      creator: 'Signal',
      url: 'https://www.youtube.com/watch?v=9sO2qdTci-s',
      duration: '~10 min',
      why: 'To see how real systems recover from compromise instead of pretending it never happens.'
    },
    {
      title: 'Hugo Krawczyk — Key Exchange and Secure Channels',
      creator: 'Hugo Krawczyk',
      url: 'https://www.youtube.com/watch?v=0pK9r7pJ3yE',
      duration: '~30 min',
      why: 'To understand why authentication and freshness are separate problems.'
    }
  ],
  pq: [
    {
      title: 'NIST — Post-Quantum Cryptography Overview',
      creator: 'NIST',
      url: 'https://www.youtube.com/watch?v=F3pJ8T1TnUw',
      duration: '~15 min',
      why: 'To understand the real threat model: harvest-now, decrypt-later.'
    },
    {
      title: 'Hybrid KEMs — Why Hedge?',
      creator: 'Research Seminar',
      url: 'https://www.youtube.com/watch?v=Yt9Wb3vNf7I',
      duration: '~20 min',
      why: 'To explain why hybrid constructions hedge assumptions instead of replacing them.'
    }
  ]
};

// Final exam questions
const finalQuestions = [
  {
    q: "Why is expected value irrelevant for security?",
    required: true,
    placeholder: "Explain why averages do not matter for security...",
  },
  {
    q: "What exact assumption keeps XOR safe?",
    required: true,
    placeholder: "What must be true for XOR to provide secrecy?",
  },
  {
    q: "Where does IND-CPA fail for messaging?",
    required: true,
    placeholder: "What does IND-CPA NOT protect against?",
  },
  {
    q: "Why does hybrid help but not guarantee safety?",
    required: true,
    placeholder: "What risk does hybrid shift, not eliminate?",
  },
  {
    q: "What does the adversary WAIT for?",
    required: true,
    placeholder: "What is the patient adversary?",
  },
];

function FinalExam() {
  const [answers, setAnswers] = useState<Record<number, string>>({});
  const [submitted, setSubmitted] = useState(false);

  const unanswered = finalQuestions.filter((_, i) => !answers[i]?.trim());

  return (
    <div className="space-y-6">
      <div className="p-6 bg-gray-800 rounded-xl">
        <h2 className="text-2xl font-bold mb-4 text-red-400">🎓 Final Examination</h2>
        <p className="text-gray-300 mb-4">
          Answer ALL questions. If you cannot answer, review the sections.
          The adversary does not accept partial understanding.
        </p>
        <div className="p-4 bg-red-900/20 border border-red-800 rounded-lg">
          <p className="text-sm text-gray-300">
            💡 <strong>Reminder:</strong> You are NOT watching these videos to learn.
            You are watching them to CONFIRM what already broke in your head.
          </p>
        </div>
      </div>

      {finalQuestions.map((q, i) => (
        <div key={i} className={`p-6 rounded-xl border-2 ${
          submitted && !answers[i]?.trim() 
            ? 'border-red-500 bg-red-900/20' 
            : 'border-gray-700 bg-gray-800'
        }`}>
          <div className="flex items-start gap-3 mb-3">
            <span className="bg-red-600 text-white text-xs font-bold px-2 py-1 rounded">Q{i + 1}</span>
            <span className="font-semibold text-white">{q.q}</span>
          </div>
          <textarea
            value={answers[i] || ''}
            onChange={(e) => setAnswers({ ...answers, [i]: e.target.value })}
            placeholder={q.placeholder}
            disabled={submitted}
            className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
            rows={3}
          />
        </div>
      ))}

      {!submitted ? (
        <button
          onClick={() => setSubmitted(true)}
          disabled={unanswered.length > 0}
          className="w-full py-4 bg-red-600 hover:bg-red-500 rounded-lg font-bold disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          <Skull size={20} /> Submit Answers
        </button>
      ) : (
        <div className="p-6 bg-gray-800 rounded-xl">
          {unanswered.length > 0 ? (
            <div className="text-center">
              <div className="text-red-400 font-bold text-xl mb-2">❌ INCOMPLETE</div>
              <p className="text-gray-400">You must answer ALL questions before proceeding.</p>
              <div className="mt-4 text-sm text-gray-500">
                Review sections: {unanswered.map((_, i) => `${i + 1}`).join(', ')}
              </div>
            </div>
          ) : (
            <div className="text-center">
              <div className="text-green-400 font-bold text-xl mb-2">✅ EXAMINATION COMPLETE</div>
              <p className="text-gray-300">
                You have demonstrated understanding of cryptographic reasoning.
                Remember: Security is about knowing where systems BREAK.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// 0.1 Probability Section with Narration
function ProbabilitySection({ mode }: { mode: ViewMode }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [distribution, setDistribution] = useState<'uniform' | 'biased' | 'normal'>('uniform');
  const [tailEvent, setTailEvent] = useState(false);
  const [narrationComplete, setNarrationComplete] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const width = canvas.width;
    const height = canvas.height;

    let particles: Array<{x: number; y: number; vx: number; vy: number}> = [];
    
    for (let i = 0; i < 100; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 2,
        vy: (Math.random() - 0.5) * 2,
      });
    }

    const animate = () => {
      ctx.fillStyle = '#0a0a0a';
      ctx.fillRect(0, 0, width, height);

      ctx.strokeStyle = mode === 'failure' ? '#ef4444' : '#4b5563';
      ctx.lineWidth = 2;
      ctx.beginPath();
      for (let x = 0; x < width; x++) {
        const t = x / width;
        let y: number;
        if (distribution === 'uniform') {
          y = height * 0.5;
        } else if (distribution === 'biased') {
          y = height * (0.85 - 0.7 * Math.pow(t - 0.65, 2));
        } else {
          y = height * (0.9 - 0.85 * Math.pow((t - 0.5) * 3, 2));
        }
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      if (mode === 'adversary' || mode === 'failure') {
        const tailX = width * 0.95;
        ctx.fillStyle = 'rgba(239, 68, 68, 0.3)';
        ctx.fillRect(tailX, 0, width - tailX, height);
        ctx.fillStyle = '#ef4444';
        ctx.font = 'bold 14px monospace';
        ctx.fillText('TAIL', tailX + 5, height / 2);
      }

      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;

        if (distribution === 'biased') {
          if (p.x > width * 0.65) p.vx -= 0.015;
          else p.vx += 0.008;
        } else if (distribution === 'normal') {
          const center = width / 2;
          p.vx -= (p.x - center) * 0.0008;
        }

        if (mode === 'failure' && p.x > width * 0.95) {
          setTailEvent(true);
        }

        ctx.beginPath();
        ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
        ctx.fillStyle = mode === 'failure' && p.x > width * 0.95 
          ? '#ef4444' 
          : mode === 'adversary' && p.x > width * 0.9
          ? '#f97316'
          : distribution === 'biased' ? '#f59e0b' : distribution === 'normal' ? '#3b82f6' : '#10b981';
        ctx.fill();
      });

      requestAnimationFrame(animate);
    };

    animate();
  }, [distribution, mode]);

  return (
    <div className="space-y-6">
      <MentalPicture picture="Представь: Ты запускаешь STVOR-чат 1 раз — всё ок. 10 раз — всё ок. 1 000 000 раз — один ключ оказывается слабым. Криптография — это наука не про обычно, а про тот один раз, который тебя убьёт. И ТОЛЬКО ПОТОМ — точки, кривые, хвосты." />

      <NarrationSection
        title="Probability Distributions"
        what="You are about to see many executions of the same system. Each dot is one run. We are not judging one run. We are judging behavior over time. The curve shows where the dots tend to land — that is the distribution."
        why="Cryptography does not fail loudly. It fails quietly, in rare cases. To see those cases, we must look at distributions, not single values. The security of your system lives in the tails of these curves."
        misconception="Most people look at averages and feel safe. Attackers do not. They wait for rare events. Expected value tells you what happens on average — the attacker exploits what happens on the worst days."
        onNext={() => setNarrationComplete(true)}
      />

      <RealSystems 
        section="probability"
        items={[
          'apps/web/app/api/chat/resolve-peer/route.ts — nonce generation',
          'apps/relay/src/web-jwt-auth.ts — session token randomness',
          'packages/crypto/src/x25519.ts — ephemeral key generation',
          'apps/web/app/security/page.tsx — crypto padding',
        ]}
      />

      {narrationComplete && (
        <>
          <div className="flex gap-4 mb-4">
            {(['uniform', 'biased', 'normal'] as const).map((d) => (
              <button
                key={d}
                onClick={() => setDistribution(d)}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  distribution === d ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300'
                }`}
              >
                {d.charAt(0).toUpperCase() + d.slice(1)}
              </button>
            ))}
          </div>

          {mode === 'assumptions' && (
            <div className="p-4 bg-red-900/30 border border-red-600 rounded-lg mb-4">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <AlertTriangle size={18} /> ASSUMPTION
              </div>
              <p className="text-gray-300 text-sm">
                <strong>Samples are i.i.d. uniform.</strong> This assumption is CRITICAL.
                If violated, security breaks. The adversary exploits any deviation.
              </p>
            </div>
          )}

          {mode === 'adversary' && (
            <div className="p-4 bg-orange-900/30 border border-orange-600 rounded-lg mb-4">
              <div className="flex items-center gap-2 text-orange-400 font-bold mb-2">
                <Skull size={18} /> ADVERSARY STRATEGY
              </div>
              <p className="text-gray-300 text-sm">
                Attackers do NOT play averages. They zoom into the <strong>TAIL</strong>.
                With enough samples, rare events become certain. This is why
                2⁻¹²⁸ probability is not impossible — it is expensive.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <div className="p-4 bg-red-900/50 border-2 border-red-500 rounded-lg mb-4 animate-pulse">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <Skull size={18} /> FAILURE MODE
              </div>
              <p className="text-gray-300 text-sm">
                <strong>Expected value was fine. Security is broken.</strong><br/>
                One rare event → key reuse → full compromise.<br/>
                The distribution looked safe. The tail killed you.
              </p>
              {tailEvent && (
                <div className="mt-2 text-red-400 font-bold">⚠️ TAIL EVENT OCCURRED ⚠️</div>
              )}
            </div>
          )}

          <canvas ref={canvasRef} width={700} height={300} className="w-full bg-gray-900 rounded-lg" />

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="p-3 bg-gray-800 rounded-lg">
              <div className="text-green-400 font-semibold">What You See</div>
              <div className="text-gray-400">Particles forming a distribution. Looks random.</div>
            </div>
            <div className="p-3 bg-gray-800 rounded-lg">
              <div className="text-red-400 font-semibold">What The Attacker Sees</div>
              <div className="text-gray-400">The TAIL. The deviation. The weakness.</div>
            </div>
          </div>

          {mode === 'failure' && (
            <div className="p-4 bg-gray-800 rounded-lg mt-4">
              <div className="text-red-400 font-semibold mb-2">Failure Summary</div>
              <p className="text-gray-300">
                The system did not fail randomly. It failed because we trusted the average.
                One rare event was enough. When security depends on this never happens,
                the adversary makes it happen.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <VideoBlock videos={sectionVideos.probability} />
          )}
        </>
      )}
    </div>
  );
}

// 0.2 Linear Section with Narration
function LinearSection({ mode }: { mode: ViewMode }) {
  const [bits, setBits] = useState<number[]>(Array(8).fill(0).map(() => Math.round(Math.random())));
  const [bits2, setBits2] = useState<number[]>(Array(8).fill(0).map(() => Math.round(Math.random())));
  const [xorResult, setXorResult] = useState<number[]>([]);
  const [biasMode, setBiasMode] = useState(false);
  const [narrationComplete, setNarrationComplete] = useState(false);

  const runXOR = useCallback(() => {
    setXorResult(bits.map((b, i) => b ^ bits2[i]));
  }, [bits, bits2]);

  const biasedBits = biasMode ? [...bits.slice(0, 7), 1] : bits;

  return (
    <div className="space-y-6">
      <MentalPicture picture="Представь: Ты XOR-ишь сообщение с ключом. Думаешь, хаос! Но нет. Если в ключе хоть один бит предсказуем — он ПРОЯВИТСЯ в выходе. Линейность — это не враг хаоса. Это микроскоп, который показывает предсказуемость." />

      <NarrationSection
        title="XOR and Linearity"
        what="XOR is the simplest operation in cryptography. You put in two bits, you get one bit out. It feels like flipping a coin. But here is the thing: XOR preserves structure. If one input has a pattern, the output shows it too."
        why="XOR is the foundation of stream ciphers and the Double Ratchet. When used correctly with random keys, it creates perfect secrecy. When used incorrectly — when keys have any bias — that bias leaks directly into the ciphertext."
        misconception="People think XOR combines patterns differently than you expect. If you XOR a message with random noise, you get random noise. If you XOR a message with predictable noise, you get predictable noise. The attacker is patient — they wait for the predictable parts."
        onNext={() => setNarrationComplete(true)}
      />

      <RealSystems 
        section="linear"
        items={[
          'packages/crypto/src/xor.ts — primitive XOR operations',
          'apps/relay/src/storage/memory-adapter.ts — stream cipher masking',
          'apps/web/app/security/page.tsx — key blinding',
          'packages/crypto/src/double-ratchet.ts — message encryption',
        ]}
      />

      {narrationComplete && (
        <>
          {mode === 'assumptions' && (
            <div className="p-4 bg-red-900/30 border border-red-600 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <AlertTriangle size={18} /> CRITICAL ASSUMPTION
              </div>
              <p className="text-gray-300 text-sm">
                <strong>Inputs are uniformly random.</strong><br/>
                If ANY input bit has bias, XOR preserves and propagates that bias.
                Linearity does NOT destroy bias — it EXPOSES it.
              </p>
            </div>
          )}

          {mode === 'adversary' && (
            <div className="p-4 bg-orange-900/30 border border-orange-600 rounded-lg">
              <div className="flex items-center gap-2 text-orange-400 font-bold mb-2">
                <Skull size={18} /> ADVERSARY EXPLOITS BIAS
              </div>
              <p className="text-gray-300 text-sm">
                With 1-bit bias across 2⁶⁴ messages, the attacker recovers the key.
                Linear relations allow information leakage. Each biased bit = one less bit of security.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <div className="p-4 bg-red-900/50 border-2 border-red-500 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <Skull size={18} /> FAILURE: LINEARITY BETRAYED YOU
              </div>
              <p className="text-gray-300 text-sm">
                XOR looks safe. But linear algebra is the attacker is friend.
                <br/><strong>Linear relations = information leakage.</strong>
                <br/>The system did not break by accident — linearity guaranteed the leak.
              </p>
            </div>
          )}

          <div className="flex justify-center items-center gap-6 flex-wrap">
            <div className="text-center">
              <div className="text-sm text-gray-400 mb-2">Input A</div>
              <div className="flex gap-1">
                {biasedBits.map((b, i) => (
                  <div
                    key={i}
                    className={`w-10 h-10 flex items-center justify-center rounded font-mono text-lg font-bold ${
                      b ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400'
                    }`}
                  >
                    {b}
                  </div>
                ))}
              </div>
              {biasMode && <div className="text-red-400 text-xs mt-1">⚠️ BIASED</div>}
            </div>

            <div className="text-2xl font-bold text-purple-400">⊕</div>

            <div className="text-center">
              <div className="text-sm text-gray-400 mb-2">Input B</div>
              <div className="flex gap-1">
                {bits2.map((b, i) => (
                  <div
                    key={i}
                    className={`w-10 h-10 flex items-center justify-center rounded font-mono text-lg font-bold ${
                      b ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'
                    }`}
                  >
                    {b}
                  </div>
                ))}
              </div>
            </div>

            <div className="text-2xl font-bold text-green-400">→</div>

            <div className="text-center">
              <div className="text-sm text-gray-400 mb-2">Output</div>
              <div className="flex gap-1">
                {xorResult.map((b, i) => (
                  <div
                    key={i}
                    className={`w-10 h-10 flex items-center justify-center rounded font-mono text-lg font-bold ${
                      b ? 'bg-green-600 text-white' : 'bg-gray-800 text-gray-600'
                    }`}
                  >
                    {b}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="flex gap-4 justify-center">
            <button
              onClick={() => {
                setBits(Array(8).fill(0).map(() => Math.round(Math.random())));
                setBits2(Array(8).fill(0).map(() => Math.round(Math.random())));
                setXorResult([]);
              }}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg"
            >
              Randomize
            </button>
            <button
              onClick={runXOR}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg flex items-center gap-2"
            >
              <Play size={16} /> Compute
            </button>
            {mode !== 'normal' && (
              <button
                onClick={() => setBiasMode(!biasMode)}
                className={`px-4 py-2 rounded-lg ${biasMode ? 'bg-red-600' : 'bg-gray-700'}`}
              >
                {biasMode ? 'Remove Bias' : 'Inject Bias'}
              </button>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="p-4 bg-gray-800 rounded-lg">
              <div className="text-purple-400 font-semibold mb-2">XOR Properties</div>
              <ul className="text-gray-400 space-y-1">
                <li>• Linear over GF(2)</li>
                <li>• a ⊕ a = 0 (cancels self)</li>
                <li>• Preserves structure</li>
              </ul>
            </div>
            <div className="p-4 bg-gray-800 rounded-lg">
              <div className="text-red-400 font-semibold mb-2">The Danger</div>
              <ul className="text-gray-400 space-y-1">
                <li>• Bias is NOT destroyed</li>
                <li>• Linear relations leak info</li>
                <li>• Uniform ≠ Secure (alone)</li>
              </ul>
            </div>
          </div>

          {mode === 'failure' && (
            <div className="p-4 bg-gray-800 rounded-lg mt-4">
              <div className="text-red-400 font-semibold mb-2">Failure Summary</div>
              <p className="text-gray-300">
                The system looked random but was not. The bias we ignored — the one unlikely 
                bit that was always 1 — propagated through every XOR operation until the 
                attacker could see the pattern. Linearity did not hide the flaw. It preserved it.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <VideoBlock videos={sectionVideos.linear} />
          )}
        </>
      )}
    </div>
  );
}

// 1. Games Section with Narration
function GamesSection({ mode }: { mode: ViewMode }) {
  const [challenge, setChallenge] = useState<'m0' | 'm1' | null>(null);
  const [games, setGames] = useState(0);
  const [wins, setWins] = useState(0);
  const [narrationComplete, setNarrationComplete] = useState(false);

  const playGame = () => {
    const secret = Math.random() > 0.5 ? 'm0' : 'm1';
    setChallenge(secret);
    const guess = Math.random() > 0.5 ? 'm0' : 'm1';
    const win = guess === secret;
    setGames(g => g + 1);
    if (win) setWins(w => w + 1);
  };

  return (
    <div className="space-y-6">
      <MentalPicture picture="Представь: Ты играешь в игру с незнакомцем. Он прячет шарик под один из двух стаканчиков. Ты должен угадать, где шарик. Если ты угадываешь лучше, чем 50% — что-то не так. IND-CPA — это формализация этой игры. Доказательство говорит: угадывать лучше нельзя. Но доказательство — это не система. Это МОДЕЛЬ системы." />

      <NarrationSection
        title="Security Games"
        what="A security game is a formal way of asking: Can an attacker tell two things apart? In this game, you see an encryption of one of two messages. You guess which one. If you can do better than random guessing, security is broken."
        why="Games give us a language for talking about security. Instead of saying the system is safe, we can say in this specific game, the attacker has advantage ε. We can then prove that ε is small. But — and this is critical — we only proved something about the game."
        misconception="People see a security proof and think this system is proven secure. But we proved the game is hard. We did NOT prove the system is secure. The game is a model. The system is reality. They differ. That is where security fails."
        onNext={() => setNarrationComplete(true)}
      />

      <RealSystems 
        section="games"
        items={[
          'packages/crypto/src/defense-in-depth.ts — proof of IND-CPA',
          'apps/relay/src/auth.ts — session security game',
          'apps/web/app/api/auth/relay-token/route.ts — token indistinguishability',
          'apps/relay/src/web-jwt-auth.ts — adversary capability model',
        ]}
      />

      {narrationComplete && (
        <>
          {mode === 'assumptions' && (
            <div className="p-4 bg-red-900/30 border border-red-600 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <AlertTriangle size={18} /> CRITICAL ASSUMPTION
              </div>
              <p className="text-gray-300 text-sm">
                <strong>Indistinguishability holds.</strong><br/>
                If this assumption is false, ε → 0.5, and the adversary wins.
                Security proofs bound ε — they do not make it zero.
              </p>
            </div>
          )}

          {mode === 'adversary' && (
            <div className="p-4 bg-orange-900/30 border border-orange-600 rounded-lg">
              <div className="flex items-center gap-2 text-orange-400 font-bold mb-2">
                <Skull size={18} /> ADVERSARY ADAPTS
              </div>
              <p className="text-gray-300 text-sm">
                The adversary chooses messages ADAPTIVELY based on previous responses.
                Non-adaptive security is weaker. Real adversaries are adaptive.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <div className="p-4 bg-red-900/50 border-2 border-red-500 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <Skull size={18} /> FAILURE: ε COLLAPSED
              </div>
              <p className="text-gray-300 text-sm">
                <strong>IND-CPA ≠ Secure Messaging.</strong><br/>
                The proof guarantees indistinguishability of encryptions.
                It does NOT guarantee: replay protection, forward secrecy, or authentication.
                You proved a MODEL — not a SYSTEM.
              </p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-8">
            <div className="p-6 bg-gray-800 rounded-xl">
              <div className="text-center mb-4">
                <div className="text-lg font-semibold text-blue-400">Real World</div>
                <div className="text-sm text-gray-400">Enc(m{challenge?.slice(1) || '?'})</div>
              </div>
              <div className="flex justify-center items-center gap-4">
                <div className="w-16 h-16 bg-blue-900 rounded-lg flex items-center justify-center text-2xl">🔐</div>
                <div className="text-xl">→</div>
                <div className="w-16 h-16 bg-gray-700 rounded-lg flex items-center justify-center text-xl">📦</div>
              </div>
            </div>

            <div className="p-6 bg-gray-800 rounded-xl">
              <div className="text-center mb-4">
                <div className="text-lg font-semibold text-purple-400">Ideal World</div>
                <div className="text-sm text-gray-400">Indistinguishable</div>
              </div>
              <div className="flex justify-center items-center gap-4">
                <div className="w-16 h-16 bg-purple-900 rounded-lg flex items-center justify-center text-2xl">🎲</div>
                <div className="text-xl">→</div>
                <div className="w-16 h-16 bg-gray-700 rounded-lg flex items-center justify-center text-xl">📦</div>
              </div>
            </div>
          </div>

          <div className="flex justify-center gap-4">
            <button
              onClick={() => setChallenge(Math.random() > 0.5 ? 'm0' : 'm1')}
              className="px-4 py-2 bg-amber-600 hover:bg-amber-500 rounded-lg"
            >
              Get Challenge
            </button>
            <button
              onClick={playGame}
              className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded-lg flex items-center gap-2"
            >
              <Play size={16} /> Guess
            </button>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-gray-800 rounded-lg text-center">
              <div className="text-2xl font-bold text-blue-400">{games}</div>
              <div className="text-sm text-gray-400">Games</div>
            </div>
            <div className="p-4 bg-gray-800 rounded-lg text-center">
              <div className="text-2xl font-bold text-green-400">{wins}</div>
              <div className="text-sm text-gray-400">Wins</div>
            </div>
            <div className={`p-4 bg-gray-800 rounded-lg text-center ${
              games > 10 && Math.abs(wins / games - 0.5) > 0.2 && mode === 'failure' ? 'border-2 border-red-500' : ''
            }`}>
              <div className={`text-2xl font-bold ${
                games > 10 && Math.abs(wins / games - 0.5) > 0.2 ? 'text-red-400' : 'text-green-400'
              }`}>
                {games > 0 ? ((wins / games) - 0.5).toFixed(3) : '0.000'}
              </div>
              <div className="text-sm text-gray-400">Advantage (ε)</div>
            </div>
          </div>

          {mode !== 'normal' && (
            <div className="p-4 bg-blue-900/30 border border-blue-800 rounded-lg">
              <div className="text-blue-400 font-semibold mb-2">Game Hopping</div>
              <div className="text-gray-300 text-sm">
                G₀ (Real) → G₁ (Modified) → G₂ (Ideal)<br/>
                Each hop REQUIRES an assumption. If any assumption fails, the proof is void.
              </div>
            </div>
          )}

          {mode === 'failure' && (
            <div className="p-4 bg-gray-800 rounded-lg mt-4">
              <div className="text-red-400 font-semibold mb-2">Failure Summary</div>
              <p className="text-gray-300">
                We proved the game was hard. But the game is not the system. 
                Real messaging needs replay protection, forward secrecy, authentication — 
                things IND-CPA never promised to provide. The proof was correct. 
                The translation to reality was incomplete.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <VideoBlock videos={sectionVideos.games} />
          )}
        </>
      )}
    </div>
  );
}

// 3. AKE Section with Narration
function AKESection({ mode }: { mode: ViewMode }) {
  const [phase, setPhase] = useState<'init' | 'send' | 'receive' | 'established' | 'compromise' | 'recover'>('init');
  const [aliceKey, setAliceKey] = useState<string>('?');
  const [bobKey, setBobKey] = useState<string>('?');
  const [messages, setMessages] = useState<Array<{from: string; content: string}>>([]);
  const [narrationComplete, setNarrationComplete] = useState(false);

  const runProtocol = async () => {
    setPhase('init');
    setAliceKey('?');
    setBobKey('?');
    setMessages([]);

    await new Promise(r => setTimeout(r, 600));
    setPhase('send');
    setMessages([{ from: 'Alice', content: 'eka, pka' }]);
    setAliceKey('*');

    await new Promise(r => setTimeout(r, 800));
    setPhase('receive');
    setMessages(prev => [...prev, { from: 'Bob', content: 'ekb, pkb' }]);
    setBobKey('*');

    await new Promise(r => setTimeout(r, 800));
    setPhase('established');
    setAliceKey('K_AB');
    setBobKey('K_AB');

    await new Promise(r => setTimeout(r, 800));
    setPhase('compromise');
    setAliceKey('⊥');
    setBobKey('⊥');
    setMessages(prev => [...prev, { from: '⚠️', content: 'State compromised!' }]);

    await new Promise(r => setTimeout(r, 800));
    setPhase('recover');
    setMessages(prev => [...prev, { from: 'System', content: 'Ratchet forward...' }]);
    setAliceKey('K_AB¹');
    setBobKey('K_AB¹');
  };

  return (
    <div className="space-y-6">
      <MentalPicture picture="Представь: Ты хочешь поговорить с незнакомцем. Вы оба выкрикиваете числа в пустоту. Потом каждый умножает чужое число на своё. У обоих получается одинаковый результат. Подслушивающий слышит оба числа, но не может получить результат. Это key exchange. Но! handshake ≠ messaging. Одно не даёт тебе защиты от повтора, от пересылки, от отказа." />

      <NarrationSection
        title="Authenticated Key Exchange"
        what="Key exchange is how two strangers become friends securely. Alice and Bob exchange special keys, do some math, and end up with the same secret. If done right, even if Eve watched everything, she cannot learn the secret."
        why="Without authenticated key exchange, you cannot have secure communication. You need a shared secret to encrypt messages. But how do you get that secret when someone might be listening? The answer is clever math that lets two parties compute a secret while an observer learns nothing."
        misconception="People think secure key exchange means secure messaging. It does not. AKE gives you a shared secret. It does not give you replay protection, forward secrecy, or message authenticity. Those are separate problems that require separate solutions."
        onNext={() => setNarrationComplete(true)}
      />

      <RealSystems 
        section="ake"
        items={[
          'apps/relay/src/auth.ts — X25519 key exchange',
          'apps/relay/src/index.ts — handshake protocol',
          'packages/crypto/src/x25519.ts — elliptic curve DH',
          'packages/crypto/src/double-ratchet.ts — ratcheting forward secrecy',
        ]}
      />

      {narrationComplete && (
        <>
          {mode === 'assumptions' && (
            <div className="p-4 bg-red-900/30 border border-red-600 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <AlertTriangle size={18} /> CRITICAL ASSUMPTIONS
              </div>
              <p className="text-gray-300 text-sm">
                1. <strong>Long-term keys uncompromised</strong> — if stolen, all past sessions die.<br/>
                2. <strong>Session state secret</strong> — memory disclosure breaks FS.<br/>
                3. <strong>Random oracles ideal</strong> — hash function assumptions.
              </p>
            </div>
          )}

          {mode === 'adversary' && (
            <div className="p-4 bg-orange-900/30 border border-orange-600 rounded-lg">
              <div className="flex items-center gap-2 text-orange-400 font-bold mb-2">
                <Skull size={18} /> KCI ATTACK
              </div>
              <p className="text-gray-300 text-sm">
                Key Compromise Impersonation: If long-term key is compromised,
                attacker can impersonate ANYONE to the victim.
                This is why forward secrecy matters.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <div className="p-4 bg-red-900/50 border-2 border-red-500 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <Skull size={18} /> FAILURE: SECURE AKE ≠ SECURE MESSAGING
              </div>
              <p className="text-gray-300 text-sm">
                AKE provides authenticated key exchange.<br/>
                It does NOT provide:<br/>
                • Forward secrecy after compromise (unless ratcheting)<br/>
                • Message authenticity (separate MAC needed)<br/>
                • Replay protection (sequence numbers needed)<br/>
                You solved ONE problem. Messaging has MANY.
              </p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-8">
            <div className="p-6 bg-gray-800 rounded-xl text-center">
              <div className="text-blue-400 font-semibold mb-4">Alice</div>
              <div className={`w-20 h-20 mx-auto rounded-xl flex items-center justify-center text-2xl transition-all ${
                aliceKey === '?' ? 'bg-gray-700' :
                aliceKey === '⊥' ? 'bg-red-900 animate-pulse' :
                aliceKey === '*' ? 'bg-blue-900' :
                'bg-green-900'
              }`}>
                {aliceKey === '?' ? '❓' : aliceKey === '⊥' ? '☠️' : aliceKey === '*' ? '🔑' : '🔐'}
              </div>
              <div className="mt-2 font-mono text-sm">{aliceKey}</div>
            </div>

            <div className="p-6 bg-gray-800 rounded-xl text-center">
              <div className="text-purple-400 font-semibold mb-4">Bob</div>
              <div className={`w-20 h-20 mx-auto rounded-xl flex items-center justify-center text-2xl transition-all ${
                bobKey === '?' ? 'bg-gray-700' :
                bobKey === '⊥' ? 'bg-red-900 animate-pulse' :
                bobKey === '*' ? 'bg-purple-900' :
                'bg-green-900'
              }`}>
                {bobKey === '?' ? '❓' : bobKey === '⊥' ? '☠️' : bobKey === '*' ? '🔑' : '🔐'}
              </div>
              <div className="mt-2 font-mono text-sm">{bobKey}</div>
            </div>
          </div>

          <div className="p-4 bg-gray-800 rounded-xl">
            <div className="text-sm text-gray-400 mb-2">Message Flow</div>
            <div className="space-y-2">
              {messages.map((msg, i) => (
                <div
                  key={i}
                  className={`flex items-center gap-2 ${
                    msg.from === 'Alice' ? 'justify-end' : 
                    msg.from === 'Bob' ? 'justify-start' : 'justify-center'
                  }`}
                >
                  {msg.from === 'Alice' && <span className="text-blue-400 text-sm">Alice:</span>}
                  <span className="bg-gray-700 px-3 py-1 rounded-lg text-sm">{msg.content}</span>
                  {msg.from === 'Bob' && <span className="text-purple-400 text-sm">:Bob</span>}
                </div>
              ))}
            </div>
          </div>

          <div className="flex justify-center gap-4">
            <button
              onClick={runProtocol}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-500 rounded-lg font-medium flex items-center gap-2"
            >
              <Play size={18} /> Run Protocol
            </button>
          </div>

          <div className={`p-4 rounded-lg border-2 text-center ${
            phase === 'compromise' ? 'border-red-500 bg-red-900/30' :
            phase === 'established' ? 'border-green-500 bg-green-900/30' :
            'border-gray-700 bg-gray-800'
          }`}>
            <div className="text-lg font-semibold uppercase">{phase}</div>
            <div className="text-sm opacity-70">
              {phase === 'init' && 'Initial state - no shared secret'}
              {phase === 'send' && 'Alice sends ephemeral + prekey'}
              {phase === 'receive' && 'Bob receives, computes shared secret'}
              {phase === 'established' && 'Both parties have matching session keys'}
              {phase === 'compromise' && 'Session state leaked - OLD messages at risk'}
              {phase === 'recover' && 'Ratchet forward - new keys derived'}
            </div>
          </div>

          {mode === 'failure' && (
            <div className="p-4 bg-gray-800 rounded-lg mt-4">
              <div className="text-red-400 font-semibold mb-2">Failure Summary</div>
              <p className="text-gray-300">
                We authenticated the key exchange. We did not authenticate the messages.
                The attacker can replay old messages, cannot decrypt new ones, but can 
                confuse the participants. Secure AKE gave us a shared secret. 
                It did not give us a secure conversation.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <VideoBlock videos={sectionVideos.ake} />
          )}
        </>
      )}
    </div>
  );
}

// 5. PQ Section with Narration
function PQSection({ mode }: { mode: ViewMode }) {
  const [attackPhase, setAttackPhase] = useState<'now' | 'harvest' | 'quantum'>('now');
  const [narrationComplete, setNarrationComplete] = useState(false);

  return (
    <div className="space-y-6">
      <MentalPicture picture="Представь: Сегодня ты шифруешь сообщение RSA. Злоумышленник копирует его. Пока RSA работает — он не может прочитать. Но представь: через 10 лет появится квантовый компьютер. Он берёт сохранённое сообщение и мгновенно читает. harvest-now-decrypt-later. Вот почему нужно менять криптографию СЕЙЧАС — до квантовых компьютеров." />

      <NarrationSection
        title="Post-Quantum Cryptography"
        what="Today encryption (RSA, ECC) relies on problems that quantum computers can solve easily. Post-quantum cryptography uses different math that quantum computers struggle with. But here is the catch: we are betting on problems being hard, and we have only been testing them for a few years."
        why="Adversaries are recording encrypted traffic TODAY. They cannot read it yet. But when quantum computers arrive, they will decrypt everything they stored. This is harvest now, decrypt later. We need new encryption before quantum computers arrive, or everything becomes readable."
        misconception="People think post-quantum crypto replaces regular crypto. It does not. We use HYBRID encryption — both old and new. If post-quantum breaks, old crypto protects you. If old crypto breaks (unexpected!), post-quantum protects you. We hedge our bets because we do not fully trust either."
        onNext={() => setNarrationComplete(true)}
      />

      <RealSystems 
        section="pq"
        items={[
          'packages/crypto/src/ml-kem.ts — ML-KEM-768 key encapsulation',
          'packages/crypto/src/hybrid.ts — X25519 + ML-KEM composition',
          'apps/relay/src/index.ts — PQ-ready handshake',
          'apps/web/app/api/relay/prekeys/route.ts — prekey storage',
        ]}
      />

      {narrationComplete && (
        <>
          {mode === 'assumptions' && (
            <div className="p-4 bg-red-900/30 border border-red-600 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <AlertTriangle size={18} /> CRITICAL ASSUMPTION
              </div>
              <p className="text-gray-300 text-sm">
                <strong>Lattice problems are hard for quantum computers.</strong><br/>
                This is NOT proven. It is a conjecture. ML-KEM and ML-DSA
                security rests on this unproven assumption.
              </p>
            </div>
          )}

          {mode === 'adversary' && (
            <div className="p-4 bg-orange-900/30 border border-orange-600 rounded-lg">
              <div className="flex items-center gap-2 text-orange-400 font-bold mb-2">
                <Skull size={18} /> HARVEST NOW, DECRYPT LATER
              </div>
              <p className="text-gray-300 text-sm">
                Adversaries record encrypted traffic TODAY.
                They wait for quantum computers to become practical.
                Then they decrypt all historical communications.
                This is why migration matters NOW.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <div className="p-4 bg-red-900/50 border-2 border-red-500 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-bold mb-2">
                <Skull size={18} /> FAILURE: BOTH PARADIGMS BROKEN
              </div>
              <p className="text-gray-300 text-sm">
                <strong>Hybrid does not eliminate risk — it SHIFTS it.</strong><br/><br/>
                If ML-KEM breaks AND X25519 breaks → System dead.<br/>
                If ML-KEM breaks, X25519 holds → Still secure.<br/>
                If X25519 breaks, ML-KEM holds → Still secure.<br/>
                Hybrid reduces risk profile, not to zero.
              </p>
            </div>
          )}

          <div className="grid grid-cols-3 gap-4">
            <div
              className={`p-6 rounded-xl cursor-pointer transition-all ${
                attackPhase === 'now' ? 'bg-blue-900/50 border-2 border-blue-500' : 'bg-gray-800 hover:bg-gray-700'
              }`}
              onClick={() => setAttackPhase('now')}
            >
              <div className="text-4xl mb-4">🔐</div>
              <div className="text-blue-400 font-semibold">Now</div>
              <div className="text-gray-400 text-sm mt-2">
                Classical computers only.
              </div>
            </div>

            <div
              className={`p-6 rounded-xl cursor-pointer transition-all ${
                attackPhase === 'harvest' ? 'bg-amber-900/50 border-2 border-amber-500' : 'bg-gray-800 hover:bg-gray-700'
              }`}
              onClick={() => setAttackPhase('harvest')}
            >
              <div className="text-4xl mb-4">📡</div>
              <div className="text-amber-400 font-semibold">Harvest Now</div>
              <div className="text-gray-400 text-sm mt-2">
                Recording encrypted traffic...
              </div>
            </div>

            <div
              className={`p-6 rounded-xl cursor-pointer transition-all ${
                attackPhase === 'quantum' ? 'bg-red-900/50 border-2 border-red-500' : 'bg-gray-800 hover:bg-gray-700'
              }`}
              onClick={() => setAttackPhase('quantum')}
            >
              <div className="text-4xl mb-4">💻</div>
              <div className="text-red-400 font-semibold">Quantum Attack</div>
              <div className="text-gray-400 text-sm mt-2">
                RSA/ECC broken. Historical data decrypts.
              </div>
            </div>
          </div>

          <div className="p-6 bg-green-900/30 border border-green-800 rounded-xl">
            <div className="text-green-400 font-semibold text-lg mb-4">🛡️ Hybrid Protection</div>
            <div className="flex items-center justify-center gap-4 flex-wrap">
              <div className="px-4 py-2 bg-blue-900 rounded-lg">
                <div className="text-blue-400 font-semibold">X25519</div>
                <div className="text-xs text-gray-400">Classical</div>
              </div>
              <div className="text-2xl">+</div>
              <div className="px-4 py-2 bg-purple-900 rounded-lg">
                <div className="text-purple-400 font-semibold">ML-KEM-768</div>
                <div className="text-xs text-gray-400">Post-Quantum</div>
              </div>
              <div className="text-2xl">→</div>
              <div className="px-4 py-2 bg-green-900 rounded-lg">
                <div className="text-green-400 font-semibold">Hybrid Key</div>
                <div className="text-xs text-gray-400">Defense in depth</div>
              </div>
            </div>
          </div>

          <div className="p-4 bg-yellow-900/30 border border-yellow-800 rounded-lg">
            <div className="text-yellow-400 font-semibold mb-2">Why hybrid?</div>
            <div className="text-gray-300 text-sm">
              If lattices are broken but elliptic curves survive → X25519 protects.<br/>
              If elliptic curves are broken (unexpected!) → ML-KEM protects.<br/>
              We bet on TWO assumptions, not one. This is defense in depth.
            </div>
          </div>

          {mode === 'failure' && (
            <div className="p-4 bg-gray-800 rounded-lg mt-4">
              <div className="text-red-400 font-semibold mb-2">Failure Summary</div>
              <p className="text-gray-300">
                Hybrid encryption does not mean double security. It means double hedging.
                If one assumption fails, the other still holds. But if both fail — 
                and both could fail for different reasons — the system is dead.
                Hybrid shifts risk, it does not eliminate it.
              </p>
            </div>
          )}

          {mode === 'failure' && (
            <VideoBlock videos={sectionVideos.pq} />
          )}
        </>
      )}
    </div>
  );
}

// Main page
export default function StudyPage() {
  const [activeSection, setActiveSection] = useState<Section>('intro');
  const [viewMode, setViewMode] = useState<ViewMode>('normal');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const sections: { id: Section; title: string; icon: string }[] = [
    { id: 'intro', title: 'Introduction', icon: '📚' },
    { id: 'probability', title: '0.1 Probability', icon: '🎲' },
    { id: 'linear', title: '0.2 Linear Algebra', icon: '📐' },
    { id: 'games', title: '1. Security Games', icon: '🎯' },
    { id: 'ake', title: '3. Key Exchange', icon: '🔄' },
    { id: 'pq', title: '5. Post-Quantum', icon: '⚛️' },
    { id: 'final', title: 'Final Exam', icon: '🎓' },
  ];

  const ModeButton = ({ mode }: { mode: ViewMode }) => {
    const Icon = ModeIcons[mode];
    const isActive = viewMode === mode;
    
    const colors = {
      normal: 'bg-blue-600',
      assumptions: 'bg-red-600',
      adversary: 'bg-orange-600',
      failure: 'bg-red-700',
    };

    return (
      <button
        onClick={() => setViewMode(mode)}
        className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
          isActive 
            ? `${colors[mode]} text-white` 
            : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
        }`}
      >
        <Icon size={16} />
        {mode.charAt(0).toUpperCase() + mode.slice(1)}
      </button>
    );
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white flex">
      {/* Sidebar */}
      {sidebarOpen && (
        <aside className="w-72 bg-gray-900 border-r border-gray-800 flex flex-col">
          <div className="p-4 border-b border-gray-800">
            <div className="flex items-center gap-3">
              {/* <div className="w-12 h-12 flex items-center justify-center"><StudyLogo /></div> */}
              <div>
                <h1 className="text-lg font-bold text-blue-400">Cryptography</h1>
                <p className="text-xs text-gray-500">Reasoning Through Failure</p>
              </div>
            </div>
          </div>
          <nav className="flex-1 overflow-y-auto p-2">
            {sections.map((section) => (
              <button
                key={section.id}
                onClick={() => {
                  setActiveSection(section.id);
                  setViewMode('normal');
                }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all mb-1 ${
                  activeSection === section.id
                    ? 'bg-blue-900/50 text-blue-400'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                }`}
              >
                <span>{section.icon}</span>
                <span>{section.title}</span>
              </button>
            ))}
          </nav>
        </aside>
      )}

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Header with View Mode Toggle */}
        <header className="h-16 border-b border-gray-800 flex items-center px-4 bg-gray-900/50 gap-4">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 hover:bg-gray-800 rounded-lg"
          >
            {sidebarOpen ? '◀' : '▶'}
          </button>
          <h1 className="text-lg font-semibold flex-1">
            {sections.find(s => s.id === activeSection)?.title}
          </h1>
          
          {activeSection !== 'intro' && activeSection !== 'final' && (
            <div className="flex items-center gap-2 bg-gray-800 rounded-lg p-1">
              <ModeButton mode="normal" />
              <ModeButton mode="assumptions" />
              <ModeButton mode="adversary" />
              <ModeButton mode="failure" />
            </div>
          )}
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-8">
          <div className="max-w-4xl mx-auto space-y-8">
            {activeSection === 'intro' && (
              <div className="space-y-6">
                {/* <div className="flex items-center justify-center mb-6">
                  <div className="w-48 h-48 flex items-center justify-center"><StudyLogo /></div>
                </div> */}
                <div className="p-8 bg-gradient-to-br from-blue-900/30 to-purple-900/30 rounded-2xl border border-blue-800/50">
                  <h2 className="text-3xl font-bold mb-4 text-blue-400">
                    You Will Not Pass By Watching
                  </h2>
                  <p className="text-gray-300 text-lg leading-relaxed">
                    This is not entertainment. This is a <strong>reasoning engine</strong>.
                    Every section forces you to understand where systems <strong>BREAK</strong>.
                  </p>
                  <p className="text-gray-400 mt-4">
                    Use the <strong>view mode toggle</strong> above to see:
                  </p>
                  <ul className="text-gray-400 mt-2 space-y-1">
                    <li>🔵 <strong>Normal:</strong> What the system looks like</li>
                    <li>🔴 <strong>Assumptions:</strong> What MUST be true for security</li>
                    <li>🟠 <strong>Adversary:</strong> How the attacker exploits weaknesses</li>
                    <li>🔴 <strong>Failure:</strong> What happens when assumptions collapse</li>
                  </ul>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-6 bg-gray-800 rounded-xl border-l-4 border-red-500">
                    <div className="text-4xl mb-4">⚠️</div>
                    <h3 className="text-xl font-semibold mb-2 text-red-400">Assumptions Matter</h3>
                    <p className="text-gray-400 text-sm">
                      Every security proof relies on assumptions. If any assumption is false,
                      the proof is void. Know the assumptions. Question them.
                    </p>
                  </div>
                  <div className="p-6 bg-gray-800 rounded-xl border-l-4 border-orange-500">
                    <div className="text-4xl mb-4">💀</div>
                    <h3 className="text-xl font-semibold mb-2 text-orange-400">Adversaries Are Patient</h3>
                    <p className="text-gray-400 text-sm">
                      Attackers do not play averages. They wait for rare events.
                      Expected value is meaningless when the attacker controls the distribution.
                    </p>
                  </div>
                  <div className="p-6 bg-gray-800 rounded-xl border-l-4 border-red-600">
                    <div className="text-4xl mb-4">💔</div>
                    <h3 className="text-xl font-semibold mb-2 text-red-400">Failure Is The Point</h3>
                    <p className="text-gray-400 text-sm">
                      Security is not about what works. It is about what BREAKS.
                      Understanding failure modes is the only way to reason about security.
                    </p>
                  </div>
                  <div className="p-6 bg-gray-800 rounded-xl border-l-4 border-blue-500">
                    <div className="text-4xl mb-4">🎓</div>
                    <h3 className="text-xl font-semibold mb-2 text-blue-400">Final Examination</h3>
                    <p className="text-gray-400 text-sm">
                      You must answer 5 questions demonstrating understanding.
                      No hand-waving. Be specific about assumptions and failures.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {activeSection === 'probability' && (
              <ProbabilitySection mode={viewMode} />
            )}

            {activeSection === 'linear' && (
              <LinearSection mode={viewMode} />
            )}

            {activeSection === 'games' && (
              <GamesSection mode={viewMode} />
            )}

            {activeSection === 'ake' && (
              <AKESection mode={viewMode} />
            )}

            {activeSection === 'pq' && (
              <PQSection mode={viewMode} />
            )}

            {activeSection === 'final' && (
              <FinalExam />
            )}

            {activeSection !== 'intro' && activeSection !== 'final' && (
              <div className="flex justify-between pt-8 border-t border-gray-800">
                <button
                  onClick={() => {
                    const idx = sections.findIndex(s => s.id === activeSection);
                    if (idx > 0) setActiveSection(sections[idx - 1].id);
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg"
                >
                  <ChevronLeft size={18} /> Previous
                </button>
                <button
                  onClick={() => {
                    const idx = sections.findIndex(s => s.id === activeSection);
                    if (idx < sections.length - 1) setActiveSection(sections[idx + 1].id);
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg"
                >
                  Next <ChevronRight size={18} />
                </button>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
