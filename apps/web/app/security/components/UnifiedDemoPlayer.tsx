'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Play, Pause, SkipBack, SkipForward, RotateCcw, X } from 'lucide-react';

type DemoPhase =
  | 'handshake_intro'
  | 'handshake_detail'
  | 'ratchet_intro'
  | 'ratchet_detail'
  | 'keystore_intro'
  | 'keystore_detail'
  | 'signatures_intro'
  | 'signatures_detail'
  | 'relay_intro'
  | 'relay_detail'
  | 'groupchat_intro'
  | 'groupchat_detail';

interface AnimationFrame {
  phase: DemoPhase;
  title: string;
  shortTitle: string;
  description: string;
  fullDescription: string;
  progress: number;
}

const DEMO_FRAMES: AnimationFrame[] = [
  // HANDSHAKE
  {
    phase: 'handshake_intro',
    shortTitle: 'Гибридный Handshake',
    title: '🤝 Гибридный Handshake',
    description: 'X25519 + ML-KEM-768 — лучшее из классического и пост-квантового',
    fullDescription:
      'Когда вы начинаете чат, система создает два замка на одной двери. Один — классический (X25519), второй — пост-квантовый (ML-KEM). Взломать оба одновременно невозможно.',
    progress: 8,
  },
  {
    phase: 'handshake_detail',
    shortTitle: 'Handshake в действии',
    title: '🤝 Как Работает Handshake',
    description: 'X25519 (быстрый) + ML-KEM-768 (безопасен от КВК)',
    fullDescription:
      'Алиса генерирует X25519 ключи и ML-KEM ключи. Боб делает то же самое независимо. Оба обмениваются публичными ключами через Relay. Боб encapsulate → Алиса decapsulate → оба знают один shared secret, защищенный гибридным шифрованием.',
    progress: 16,
  },

  // RATCHET
  {
    phase: 'ratchet_intro',
    shortTitle: 'Пост-квантовый Ratchet',
    title: '🔄 Pост-квантовый Ratchet',
    description: 'Каждое сообщение — новые ключи. Forward secrecy на стероидах',
    fullDescription:
      'Каждое сообщение — это новое звено в цепи. Даже если кто-то украдет одно звено, остальная цепь остается целой. Каждое сообщение обновляет Chain Key, и старые ключи стираются навсегда.',
    progress: 24,
  },
  {
    phase: 'ratchet_detail',
    shortTitle: 'Ratchet в действии',
    title: '🔄 Как Работает Ratchet',
    description: 'Chain Key[N] → Message Key[N] → Chain Key[N+1]',
    fullDescription:
      'Для каждого сообщения вывводится новый Message Key из Chain Key. Сообщение шифруется с этим ключом. После отправки Chain Key обновляется: ChainKey[N+1] = HMAC(ChainKey[N], 0x01). Message Key удаляется. Боб делает то же самое независимо, и оба остаются синхронизированы.',
    progress: 32,
  },

  // KEYSTORE
  {
    phase: 'keystore_intro',
    shortTitle: 'Secure Keystore',
    title: '🔐 Secure Keystore',
    description: 'Твои ключи зашифрованы локально. Даже мы их не видим',
    fullDescription:
      'Все твои криптографические ключи зашифрованы на твоем устройстве PBKDF2 + AES-GCM. Даже если Ilyazh серверы взломают, они не смогут расшифровать твои ключи. Твой пароль → PBKDF2 (600k раундов) → Master Key → AES-GCM шифрует все ключи.',
    progress: 40,
  },
  {
    phase: 'keystore_detail',
    shortTitle: 'Keystore в действии',
    title: '🔐 Как Хранятся Ключи',
    description: 'PBKDF2 + AES-GCM + IndexedDB',
    fullDescription:
      '1) Ты создаешь пароль → 2) Генерируется 256-битная соль → 3) PBKDF2 запускает 600,000 раундов хеширования (медленно для компьютера, ОЧЕНЬ медленно для взломщика) → 4) Получается Master Key → 5) Master Key шифрует все твои ключи через AES-GCM → 6) Зашифрованные ключи хранятся в IndexedDB браузера.',
    progress: 48,
  },

  // SIGNATURES
  {
    phase: 'signatures_intro',
    shortTitle: 'Двойные Подписи',
    title: '✍️ Двойные Подписи',
    description: 'Каждое сообщение подписано дважды — невозможно подделать',
    fullDescription:
      'Каждое сообщение подписано классической (Ed25519) и пост-квантовой (ML-DSA) подписью. Это гарантирует аутентичность и невозможность отрицания. Даже если одна подпись скомпрометирована, вторая защищает.',
    progress: 56,
  },
  {
    phase: 'signatures_detail',
    shortTitle: 'Подписи в действии',
    title: '✍️ Как Работают Подписи',
    description: 'Ed25519 (быстро) + ML-DSA (безопасно от КВК)',
    fullDescription:
      '1) Сообщение берется как есть → 2) Подписывается Ed25519 (быстро, за миллисекунды) → 3) Подписывается ML-DSA (безопасно от квантовых компьютеров) → 4) Обе подписи отправляются вместе с сообщением → 5) Получатель проверяет обе подписи: если хотя бы одна не совпадает, сообщение отклоняется.',
    progress: 64,
  },

  // RELAY
  {
    phase: 'relay_intro',
    shortTitle: 'Relay Server',
    title: '🚀 Relay Server',
    description: 'Сервер маршрутизирует, но не видит содержимое',
    fullDescription:
      'Relay — это слепой курьер. Он доставляет зашифрованные письма, но не может открыть их и прочитать, что внутри. Даже если Relay взломают, они получат только зашифрованные данные.',
    progress: 72,
  },
  {
    phase: 'relay_detail',
    shortTitle: 'Relay в действии',
    title: '🚀 Как Работает Relay',
    description: 'Маршрутизация без видимости',
    fullDescription:
      'Алиса отправляет зашифрованное сообщение на Relay → Relay не видит содержимое (он просто хранит его и маршрутизирует) → Боб запрашивает свои сообщения у Relay → Relay отправляет зашифрованное сообщение Бобу → Боб расшифровывает локально. Relay никогда не видит plaintext!',
    progress: 80,
  },

  // GROUP CHAT
  {
    phase: 'groupchat_intro',
    shortTitle: 'Групповые Чаты',
    title: '👥 Групповые Чаты',
    description: 'Детерминистические ключи — масштабируемость без компромиссов',
    fullDescription:
      'В групповых чатах все участники имеют доступ к одним и тем же ключам, вычисленным детерминистически. Это обеспечивает масштабируемость без потери безопасности.',
    progress: 88,
  },
  {
    phase: 'groupchat_detail',
    shortTitle: 'Групповой чат в действии',
    title: '👥 Как Работают Групповые Чаты',
    description: 'Все участники → один детерминистический ключ',
    fullDescription:
      '1) Создатель группы генерирует Group Key детерминистически на основе ID группы → 2) Все участники могут вычислить этот же ключ, используя тот же алгоритм → 3) Все сообщения в группе шифруются этим ключом → 4) Если кто-то присоединяется позже, он может вычислить ключ независимо → 5) Масштабируется до тысяч участников без усложнения криптографии.',
    progress: 96,
  },
];

interface UnifiedDemoPlayerProps {
  onClose?: () => void;
}

export function UnifiedDemoPlayer({ onClose }: UnifiedDemoPlayerProps) {
  const [currentFrameIndex, setCurrentFrameIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);

  const currentFrame = DEMO_FRAMES[currentFrameIndex];

  useEffect(() => {
    if (!isPlaying) return;

    const delay = (4000 / speed) * 1000;
    const timer = setTimeout(() => {
      if (currentFrameIndex < DEMO_FRAMES.length - 1) {
        setCurrentFrameIndex((prev) => prev + 1);
      } else {
        setIsPlaying(false);
      }
    }, delay);

    return () => clearTimeout(timer);
  }, [currentFrameIndex, isPlaying, speed]);

  const handlePlayPause = () => {
    setIsPlaying(!isPlaying);
  };

  const handlePrevFrame = () => {
    if (currentFrameIndex > 0) {
      setCurrentFrameIndex(currentFrameIndex - 1);
      setIsPlaying(false);
    }
  };

  const handleNextFrame = () => {
    if (currentFrameIndex < DEMO_FRAMES.length - 1) {
      setCurrentFrameIndex(currentFrameIndex + 1);
    }
  };

  const handleReset = () => {
    setCurrentFrameIndex(0);
    setIsPlaying(true);
  };

  const handleSeek = (index: number) => {
    setCurrentFrameIndex(index);
    setIsPlaying(false);
  };

  return (
    <div className="fixed inset-0 bg-black z-50 flex flex-col overflow-hidden">
      {/* Close button */}
      <button
        onClick={onClose}
        className="absolute top-4 right-4 p-2 bg-white/10 hover:bg-white/20 rounded-lg text-white z-10 transition-colors"
      >
        <X className="w-6 h-6" />
      </button>

      {/* Main Content */}
      <div className="flex-1 flex flex-col items-center justify-center p-4 sm:p-6 overflow-y-auto">
        <div className="w-full max-w-6xl space-y-4">
          {/* Visualization */}
          <div className="bg-gray-900 rounded-lg p-4 sm:p-6 flex items-center justify-center border border-gray-700 min-h-48 sm:min-h-64">
            <DemoVisualization frame={currentFrame} frameIndex={currentFrameIndex} />
          </div>

          {/* Text Content */}
          <div className="space-y-2 sm:space-y-3 bg-gray-900 rounded-lg p-4 sm:p-6 border border-gray-700">
            <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white">{currentFrame.title}</h1>
            <p className="text-sm sm:text-base text-gray-300">{currentFrame.description}</p>
            <p className="text-xs sm:text-sm text-gray-400 leading-relaxed">{currentFrame.fullDescription}</p>
          </div>
        </div>
      </div>

      {/* Controls Bar */}
      <div className="bg-gray-900 border-t border-gray-700 px-4 sm:px-6 py-3 sm:py-4 space-y-2 sm:space-y-3 flex-shrink-0 overflow-y-auto max-h-60">
        {/* Progress Bar */}
        <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
          <div
            className="bg-gradient-to-r from-blue-500 via-green-500 to-purple-500 h-full transition-all duration-300"
            style={{ width: `${currentFrame.progress}%` }}
          />
        </div>

        {/* Frame Counter */}
        <div className="flex items-center justify-between text-gray-400 text-xs sm:text-sm">
          <span>Слайд {currentFrameIndex + 1} / {DEMO_FRAMES.length}</span>
          <span className="hidden sm:inline">{currentFrame.shortTitle}</span>
        </div>

        {/* Timeline Scrubber */}
        <div className="w-full bg-gray-800 rounded-lg p-2 overflow-x-auto">
          <div className="flex gap-1 sm:gap-2 min-w-max">
            {DEMO_FRAMES.map((frame, idx) => (
              <button
                key={idx}
                onClick={() => handleSeek(idx)}
                className={`flex-shrink-0 px-2 py-1 rounded text-xs font-medium transition-all ${
                  idx === currentFrameIndex
                    ? 'bg-blue-600 text-white scale-110'
                    : idx < currentFrameIndex
                      ? 'bg-green-600/50 text-gray-100'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
                title={frame.shortTitle}
              >
                {frame.shortTitle.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center justify-center gap-2 sm:gap-4 flex-wrap">
          {/* Left: Speed Control */}
          <div className="flex items-center gap-1 sm:gap-2">
            <span className="text-gray-300 text-xs sm:text-sm hidden sm:inline">Скорость:</span>
            <select
              value={speed}
              onChange={(e) => setSpeed(parseFloat(e.target.value))}
              className="bg-gray-800 text-white px-2 py-1 rounded text-xs border border-gray-700 hover:border-gray-600 transition-colors"
            >
              <option value={0.5}>0.5x</option>
              <option value={1}>1x</option>
              <option value={1.5}>1.5x</option>
              <option value={2}>2x</option>
            </select>
          </div>

          {/* Center: Playback Controls */}
          <div className="flex items-center gap-1">
            <Button
              onClick={handleReset}
              variant="ghost"
              size="sm"
              className="text-gray-300 hover:bg-gray-800 hover:text-white p-1 sm:p-2 h-8 w-8 sm:h-10 sm:w-10"
              title="Reset to start"
            >
              <RotateCcw className="w-4 h-4 sm:w-5 sm:h-5" />
            </Button>

            <Button
              onClick={handlePrevFrame}
              disabled={currentFrameIndex === 0}
              variant="ghost"
              size="sm"
              className="text-gray-300 hover:bg-gray-800 hover:text-white disabled:opacity-40 p-1 sm:p-2 h-8 w-8 sm:h-10 sm:w-10"
              title="Previous slide"
            >
              <SkipBack className="w-4 h-4 sm:w-5 sm:h-5" />
            </Button>

            <Button
              onClick={handlePlayPause}
              className="bg-blue-600 hover:bg-blue-700 text-white px-3 sm:px-6 py-1 sm:py-2 flex items-center gap-1 sm:gap-2 rounded text-xs sm:text-sm h-8 sm:h-10"
            >
              {isPlaying ? <Pause className="w-4 h-4 sm:w-5 sm:h-5" /> : <Play className="w-4 h-4 sm:w-5 sm:h-5" />}
              <span className="hidden sm:inline">{isPlaying ? 'Пауза' : 'Плей'}</span>
            </Button>

            <Button
              onClick={handleNextFrame}
              disabled={currentFrameIndex === DEMO_FRAMES.length - 1}
              variant="ghost"
              size="sm"
              className="text-gray-300 hover:bg-gray-800 hover:text-white disabled:opacity-40 p-1 sm:p-2 h-8 w-8 sm:h-10 sm:w-10"
              title="Next slide"
            >
              <SkipForward className="w-4 h-4 sm:w-5 sm:h-5" />
            </Button>
          </div>

          {/* Right: Info */}
          <div className="text-gray-400 text-xs sm:text-sm">{currentFrame.progress.toFixed(0)}%</div>
        </div>
      </div>
    </div>
  );
}

interface DemoVisualizationProps {
  frame: AnimationFrame;
  frameIndex: number;
}

function DemoVisualization({ frame, frameIndex }: DemoVisualizationProps) {
  const isDetailFrame = frameIndex % 2 === 1;

  return (
    <svg className="w-full h-40 sm:h-56 md:h-64 mx-auto" viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="blueGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3B82F6" />
          <stop offset="100%" stopColor="#1E40AF" />
        </linearGradient>
        <linearGradient id="greenGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#10B981" />
          <stop offset="100%" stopColor="#059669" />
        </linearGradient>
        <linearGradient id="purpleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#8B5CF6" />
          <stop offset="100%" stopColor="#6D28D9" />
        </linearGradient>
        <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
          <polygon points="0 0, 10 3, 0 6" fill="#3B82F6" />
        </marker>
      </defs>

      {/* Background */}
      <rect width="1000" height="500" fill="#111827" />

      {/* Handshake */}
      {(frame.phase === 'handshake_intro' || frame.phase === 'handshake_detail') && (
        <g>
          {/* Alice & Bob */}
          <circle cx="200" cy="250" r="50" fill="url(#blueGrad)" />
          <text x="200" y="260" fontSize="24" textAnchor="middle" fill="white">
            👩
          </text>
          <text x="200" y="330" fontSize="12" textAnchor="middle" fill="#3B82F6" fontWeight="bold">
            Alice
          </text>

          <circle cx="800" cy="250" r="50" fill="url(#greenGrad)" />
          <text x="800" y="260" fontSize="24" textAnchor="middle" fill="white">
            👨
          </text>
          <text x="800" y="330" fontSize="12" textAnchor="middle" fill="#10B981" fontWeight="bold">
            Bob
          </text>

          {/* Handshake symbols */}
          {isDetailFrame && (
            <>
              {/* X25519 */}
              <path d="M 250 230 Q 500 180 750 230" stroke="#F59E0B" strokeWidth="3" fill="none" />
              <text x="500" y="170" fontSize="12" textAnchor="middle" fill="#F59E0B" fontWeight="bold">
                X25519 (Классический)
              </text>
              <circle cx="500" cy="230" r="8" fill="#F59E0B" />

              {/* ML-KEM */}
              <path d="M 250 270 Q 500 320 750 270" stroke="#8B5CF6" strokeWidth="3" fill="none" />
              <text x="500" y="360" fontSize="12" textAnchor="middle" fill="#8B5CF6" fontWeight="bold">
                ML-KEM-768 (Пост-квантовый)
              </text>
              <circle cx="500" cy="270" r="8" fill="#8B5CF6" />
            </>
          )}

          {/* Simple version */}
          {!isDetailFrame && (
            <text x="500" y="250" fontSize="18" textAnchor="middle" fill="#A78BFA" fontWeight="bold">
              🤝 Гибридный обмен ключами
            </text>
          )}
        </g>
      )}

      {/* Ratchet */}
      {(frame.phase === 'ratchet_intro' || frame.phase === 'ratchet_detail') && (
        <g>
          {isDetailFrame ? (
            <>
              {/* Chain visualization */}
              <g>
                {[0, 1, 2, 3, 4].map((i) => (
                  <g key={i}>
                    <rect
                      x={150 + i * 150}
                      y="150"
                      width="120"
                      height="80"
                      fill={i === 2 ? '#10B981' : '#374151'}
                      stroke={i === 2 ? '#059669' : '#6B7280'}
                      strokeWidth="2"
                      rx="4"
                    />
                    <text
                      x={210 + i * 150}
                      y="195"
                      fontSize="11"
                      fontWeight="bold"
                      fill="white"
                      textAnchor="middle"
                    >
                      Key[{i}]
                    </text>
                  </g>
                ))}
              </g>

              {/* Arrows */}
              {[0, 1, 2, 3].map((i) => (
                <path
                  key={i}
                  d={`M ${270 + i * 150} 190 L ${300 + i * 150} 190`}
                  stroke="#9CA3AF"
                  strokeWidth="2"
                  markerEnd="url(#arrowhead)"
                />
              ))}

              {/* Message flow */}
              <text x="500" y="320" fontSize="12" textAnchor="middle" fill="#10B981" fontWeight="bold">
                После каждого сообщения Chain Key обновляется
              </text>
              <text x="500" y="350" fontSize="10" textAnchor="middle" fill="#D1D5DB">
                ChainKey[N+1] = HMAC(ChainKey[N], 0x01)
              </text>
            </>
          ) : (
            <text x="500" y="250" fontSize="18" textAnchor="middle" fill="#10B981" fontWeight="bold">
              🔄 Каждое сообщение = новый ключ
            </text>
          )}
        </g>
      )}

      {/* Keystore */}
      {(frame.phase === 'keystore_intro' || frame.phase === 'keystore_detail') && (
        <g>
          {isDetailFrame ? (
            <>
              {/* Flow diagram */}
              <g>
                {/* Password */}
                <rect x="50" y="100" width="140" height="80" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="4" />
                <text x="120" y="145" fontSize="11" fontWeight="bold" fill="#3730A3" textAnchor="middle">
                  Пароль
                </text>

                {/* Arrow */}
                <path d="M 190 140 L 220 140" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

                {/* PBKDF2 */}
                <circle cx="280" cy="140" r="45" fill="url(#purpleGrad)" opacity="0.7" />
                <text x="280" y="145" fontSize="10" fontWeight="bold" fill="white" textAnchor="middle">
                  PBKDF2
                </text>
                <text x="280" y="160" fontSize="8" fill="white" textAnchor="middle">
                  600k раунд
                </text>

                {/* Arrow */}
                <path d="M 325 140 L 355 140" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

                {/* Master Key */}
                <rect
                  x="355"
                  y="100"
                  width="140"
                  height="80"
                  fill="#DCFCE7"
                  stroke="#16A34A"
                  strokeWidth="2"
                  rx="4"
                />
                <text x="425" y="145" fontSize="11" fontWeight="bold" fill="#15803D" textAnchor="middle">
                  Master Key
                </text>

                {/* Arrow */}
                <path d="M 495 140 L 525 140" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

                {/* AES-GCM */}
                <circle cx="585" cy="140" r="45" fill="url(#greenGrad)" opacity="0.7" />
                <text x="585" y="145" fontSize="10" fontWeight="bold" fill="white" textAnchor="middle">
                  AES-GCM
                </text>

                {/* Arrow */}
                <path d="M 630 140 L 660 140" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

                {/* Encrypted Storage */}
                <rect
                  x="660"
                  y="100"
                  width="140"
                  height="80"
                  fill="#FEF3C7"
                  stroke="#D97706"
                  strokeWidth="2"
                  rx="4"
                />
                <text x="730" y="130" fontSize="10" fontWeight="bold" fill="#92400E" textAnchor="middle">
                  Шифр. Ключи
                </text>
                <text x="730" y="155" fontSize="8" fill="#92400E" textAnchor="middle">
                  IndexedDB
                </text>
              </g>

              {/* Security guarantee */}
              <text x="500" y="320" fontSize="11" textAnchor="middle" fill="#10B981" fontWeight="bold">
                ✓ Даже если Ilyazh взломают, ключи защищены
              </text>
            </>
          ) : (
            <text x="500" y="250" fontSize="18" textAnchor="middle" fill="#8B5CF6" fontWeight="bold">
              🔐 Локальное шифрование ключей
            </text>
          )}
        </g>
      )}

      {/* Signatures */}
      {(frame.phase === 'signatures_intro' || frame.phase === 'signatures_detail') && (
        <g>
          {isDetailFrame ? (
            <>
              {/* Message */}
              <rect x="150" y="50" width="700" height="60" fill="#374151" stroke="#3B82F6" strokeWidth="2" rx="4" />
              <text x="500" y="85" fontSize="11" fontWeight="bold" fill="white" textAnchor="middle">
                Сообщение: "Привет, Bob!"
              </text>

              {/* Signatures */}
              <rect x="150" y="150" width="300" height="100" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="4" />
              <text x="300" y="190" fontSize="11" fontWeight="bold" fill="#92400E" textAnchor="middle">
                ✓ Ed25519
              </text>
              <text x="300" y="215" fontSize="8" fill="#92400E" textAnchor="middle" fontFamily="monospace">
                Sig: 0x4a2f8b3d...
              </text>

              <rect x="550" y="150" width="300" height="100" fill="#E9D5FF" stroke="#7C3AED" strokeWidth="2" rx="4" />
              <text x="700" y="190" fontSize="11" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
                ✓ ML-DSA
              </text>
              <text x="700" y="215" fontSize="8" fill="#5B21B6" textAnchor="middle" fontFamily="monospace">
                Sig: 0x8d1e5c9a...
              </text>

              {/* Result */}
              <rect x="150" y="300" width="700" height="80" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
              <text x="500" y="345" fontSize="11" fontWeight="bold" fill="#15803D" textAnchor="middle">
                ✅ Обе подписи верны = Сообщение аутентично и не подделано
              </text>
            </>
          ) : (
            <text x="500" y="250" fontSize="18" textAnchor="middle" fill="#F59E0B" fontWeight="bold">
              ✍️ Двойная аутентификация
            </text>
          )}
        </g>
      )}

      {/* Relay */}
      {(frame.phase === 'relay_intro' || frame.phase === 'relay_detail') && (
        <g>
          {/* Alice */}
          <circle cx="150" cy="250" r="40" fill="url(#blueGrad)" />
          <text x="150" y="260" fontSize="18" textAnchor="middle" fill="white">
            👩
          </text>

          {/* Relay */}
          <rect x="350" y="180" width="300" height="140" fill="#6B7280" stroke="#9CA3AF" strokeWidth="2" rx="8" />
          <text x="500" y="230" fontSize="22" textAnchor="middle" fill="white">
            👁️
          </text>
          <text x="500" y="290" fontSize="11" textAnchor="middle" fill="#E5E7EB" fontWeight="bold">
            СЛЕПОЙ СЕРВЕР
          </text>

          {/* Bob */}
          <circle cx="850" cy="250" r="40" fill="url(#greenGrad)" />
          <text x="850" y="260" fontSize="18" textAnchor="middle" fill="white">
            👨
          </text>

          {/* Flying encrypted messages */}
          <g opacity="0.8">
            <path d="M 190 240 Q 500 150 810 240" stroke="#10B981" strokeWidth="3" fill="none" strokeDasharray="10,10" />
            <circle cx="500" cy="190" r="12" fill="#10B981" />
            <text x="500" y="196" fontSize="9" textAnchor="middle" fill="white" fontWeight="bold">
              🔐
            </text>
          </g>

          {!isDetailFrame && (
            <text x="500" y="380" fontSize="14" textAnchor="middle" fill="#A78BFA" fontWeight="bold">
              Доставляет, но не может читать
            </text>
          )}
        </g>
      )}

      {/* Group Chat */}
      {(frame.phase === 'groupchat_intro' || frame.phase === 'groupchat_detail') && (
        <g>
          {isDetailFrame ? (
            <>
              {/* Three users in circle */}
              {[
                { x: 500, y: 80, name: '👩 Alice' },
                { x: 250, y: 320, name: '👨 Bob' },
                { x: 750, y: 320, name: '👨 Charlie' },
              ].map((user, idx) => (
                <g key={idx}>
                  <circle cx={user.x} cy={user.y} r="40" fill="url(#blueGrad)" />
                  <text x={user.x} y={user.y + 10} fontSize="16" textAnchor="middle" fill="white">
                    {user.name.split(' ')[0]}
                  </text>
                  <text x={user.x} y={user.y + 70} fontSize="9" textAnchor="middle" fill="#3B82F6">
                    {user.name}
                  </text>
                </g>
              ))}

              {/* Connections */}
              <line x1="500" y1="120" x2="250" y2="280" stroke="#10B981" strokeWidth="3" />
              <line x1="500" y1="120" x2="750" y2="280" stroke="#10B981" strokeWidth="3" />
              <line x1="250" y1="280" x2="750" y2="280" stroke="#10B981" strokeWidth="3" />

              {/* Center: shared key */}
              <circle cx="500" cy="200" r="60" fill="#8B5CF6" opacity="0.3" />
              <text x="500" y="210" fontSize="22" textAnchor="middle" fill="#A78BFA">
                🔐
              </text>
              <text x="500" y="270" fontSize="11" textAnchor="middle" fill="#A78BFA" fontWeight="bold">
                Детерминистический Ключ
              </text>
            </>
          ) : (
            <text x="500" y="250" fontSize="18" textAnchor="middle" fill="#A78BFA" fontWeight="bold">
              👥 Групповое шифрование
            </text>
          )}
        </g>
      )}
    </svg>
  );
}
