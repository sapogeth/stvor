'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Play, Pause, SkipBack, SkipForward, Volume2, RotateCcw } from 'lucide-react';

type DemoPhase =
  | 'intro'
  | 'alice_bob_meet'
  | 'handshake_init'
  | 'handshake_keygen'
  | 'handshake_exchange'
  | 'handshake_complete'
  | 'message_1_input'
  | 'message_1_signing'
  | 'message_1_encrypt'
  | 'message_1_relay'
  | 'message_1_decrypt'
  | 'message_1_verify'
  | 'message_1_complete'
  | 'message_2_demo'
  | 'ratchet_update'
  | 'epoch_countdown'
  | 'epoch_rekey'
  | 'group_chat_intro'
  | 'group_chat_demo'
  | 'relay_blindness'
  | 'outro';

interface AnimationFrame {
  phase: DemoPhase;
  description: string;
  mainTitle: string;
  subtitle: string;
  progress: number; // 0-100
}

const DEMO_FRAMES: AnimationFrame[] = [
  // Introduction
  {
    phase: 'intro',
    description: 'Welcome to Ilyazh Security Center',
    mainTitle: '🔒 Центр Безопасности Ilyazh',
    subtitle: 'Полная визуализация криптографии в действии',
    progress: 0,
  },
  {
    phase: 'alice_bob_meet',
    description: 'Alice и Bob хотят общаться безопасно',
    mainTitle: '👋 Alice встречает Bob',
    subtitle: 'Два пользователя, один защищенный канал',
    progress: 5,
  },
  {
    phase: 'handshake_init',
    description: 'Начинается гибридный handshake',
    mainTitle: '🤝 Гибридный Handshake',
    subtitle: 'X25519 (классический) + ML-KEM-768 (пост-квантовый)',
    progress: 10,
  },
  {
    phase: 'handshake_keygen',
    description: 'Alice и Bob генерируют ключи независимо',
    mainTitle: '🔐 Генерация Ключей',
    subtitle: 'Каждый создает свои X25519 и ML-KEM пары',
    progress: 15,
  },
  {
    phase: 'handshake_exchange',
    description: 'Публичные ключи обмениваются через Relay',
    mainTitle: '📤 Обмен Публичными Ключами',
    subtitle: 'Relay доставляет, но не может прочитать',
    progress: 25,
  },
  {
    phase: 'handshake_complete',
    description: 'Оба знают один и тот же гибридный shared secret',
    mainTitle: '✅ Handshake Завершен',
    subtitle: 'Канал защищен гибридным ключом',
    progress: 35,
  },
  {
    phase: 'message_1_input',
    description: 'Alice вводит первое сообщение',
    mainTitle: '📝 Сообщение #1: "Привет, Bob!"',
    subtitle: 'Plaintext: Привет, Bob!',
    progress: 40,
  },
  {
    phase: 'message_1_signing',
    description: 'Сообщение подписывается дважды',
    mainTitle: '✍️ Двойные Подписи',
    subtitle: 'Ed25519 (классическая) + ML-DSA (пост-квантовая)',
    progress: 45,
  },
  {
    phase: 'message_1_encrypt',
    description: 'AES-GCM шифрование + AAD binding',
    mainTitle: '🔒 Шифрование',
    subtitle: 'Ciphertext: 0x4f3a2b1c...',
    progress: 50,
  },
  {
    phase: 'message_1_relay',
    description: 'Зашифрованное сообщение летит на Relay Server',
    mainTitle: '🚀 Relay Server (Слепой)',
    subtitle: 'Сервер не может прочитать содержимое',
    progress: 60,
  },
  {
    phase: 'message_1_decrypt',
    description: 'Bob получает и расшифровывает',
    mainTitle: '🔓 Расшифровка',
    subtitle: 'Plaintext восстановлен: Привет, Bob!',
    progress: 70,
  },
  {
    phase: 'message_1_verify',
    description: 'Обе подписи проверены — сообщение аутентично',
    mainTitle: '✔️ Верификация Подписей',
    subtitle: 'Ed25519 ✓ + ML-DSA ✓ = Гарантированная аутентичность',
    progress: 75,
  },
  {
    phase: 'message_1_complete',
    description: 'Сообщение успешно доставлено',
    mainTitle: '✅ Сообщение Доставлено',
    subtitle: 'Chain Key автоматически обновлен (Ratchet)',
    progress: 80,
  },
  {
    phase: 'message_2_demo',
    description: 'Второе сообщение использует новый Chain Key',
    mainTitle: '🔄 Double Ratchet в Действии',
    subtitle: 'Каждое сообщение = новый ключ. Forward Secrecy ✓',
    progress: 85,
  },
  {
    phase: 'ratchet_update',
    description: 'Chain Key постоянно обновляется',
    mainTitle: '⚙️ Ratchet Механизм',
    subtitle: 'ChainKey[N+1] = HMAC(ChainKey[N], 0x01)',
    progress: 88,
  },
  {
    phase: 'epoch_countdown',
    description: 'После 1,048,576 сообщений или 24 часов',
    mainTitle: '⏰ Мандатное Переключение Эпох',
    subtitle: '1 месяц переписки = новый Epoch',
    progress: 90,
  },
  {
    phase: 'epoch_rekey',
    description: 'Новые PQ ключи создаются автоматически',
    mainTitle: '✨ Epoch 0 → Epoch 1',
    subtitle: 'Даже КВК не может прочитать старые сообщения',
    progress: 93,
  },
  {
    phase: 'group_chat_intro',
    description: 'Групповые чаты используют детерминистические ключи',
    mainTitle: '👥 Групповые Чаты',
    subtitle: 'Все участники → одни и те же ключи (детерминистически)',
    progress: 95,
  },
  {
    phase: 'group_chat_demo',
    description: 'Alice, Bob, Charlie - все синхронизированы',
    mainTitle: '🔐 Групповая Синхронизация',
    subtitle: 'Масштабируемость без компромиссов безопасности',
    progress: 97,
  },
  {
    phase: 'relay_blindness',
    description: 'Relay - полностью слепой маршрутизатор',
    mainTitle: '👁️ Relay Server: Слепой Курьер',
    subtitle: 'Доставляет письма, не может открыть их',
    progress: 98,
  },
  {
    phase: 'outro',
    description: 'Безопасность гарантирована на всех уровнях',
    mainTitle: '🎉 Безопасность Завершена',
    subtitle: 'Ты теперь знаешь, как работает криптография в Ilyazh',
    progress: 100,
  },
];

interface UnifiedDemoPlayerProps {
  onClose?: () => void;
}

export function UnifiedDemoPlayer({ onClose }: UnifiedDemoPlayerProps) {
  const [currentFrameIndex, setCurrentFrameIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);
  const [speed, setSpeed] = useState(1); // 1x, 1.5x, 2x

  const currentFrame = DEMO_FRAMES[currentFrameIndex];

  // Auto-play logic
  useEffect(() => {
    if (!isPlaying) return;

    const delay = (3000 / speed) * 1000; // 3 seconds per frame at 1x speed
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
    <div className="fixed inset-0 bg-black/90 flex flex-col z-50 overflow-hidden">
      {/* Main Content */}
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="max-w-4xl w-full">
          <DemoVisualization frame={currentFrame} frameIndex={currentFrameIndex} />

          <div className="mt-8 text-center space-y-4">
            <h1 className="text-5xl font-bold text-white">{currentFrame.mainTitle}</h1>
            <p className="text-2xl text-gray-300">{currentFrame.subtitle}</p>
            <p className="text-lg text-gray-400">{currentFrame.description}</p>
          </div>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="px-8 pb-6">
        <div className="w-full bg-gray-700 rounded-full h-2 overflow-hidden mb-4">
          <div
            className="bg-gradient-to-r from-blue-500 via-green-500 to-purple-500 h-full transition-all duration-500"
            style={{ width: `${currentFrame.progress}%` }}
          />
        </div>

        {/* Frame Counter */}
        <div className="text-center text-gray-300 mb-4 text-sm">
          Frame {currentFrameIndex + 1} / {DEMO_FRAMES.length}
        </div>

        {/* Timeline / Scrubber */}
        <div className="w-full bg-gray-800 rounded-lg p-2 mb-6 overflow-x-auto">
          <div className="flex gap-1">
            {DEMO_FRAMES.map((frame, idx) => (
              <button
                key={idx}
                onClick={() => handleSeek(idx)}
                className={`flex-shrink-0 w-6 h-6 rounded transition-all ${
                  idx === currentFrameIndex
                    ? 'bg-blue-500 scale-125 ring-2 ring-blue-300'
                    : idx < currentFrameIndex
                      ? 'bg-green-500 opacity-60'
                      : 'bg-gray-600 opacity-40'
                } hover:opacity-100`}
                title={frame.mainTitle}
              />
            ))}
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between gap-4">
          {/* Left: Speed Control */}
          <div className="flex items-center gap-2">
            <span className="text-gray-300 text-sm">Скорость:</span>
            <select
              value={speed}
              onChange={(e) => setSpeed(parseFloat(e.target.value))}
              className="bg-gray-700 text-white px-3 py-1 rounded text-sm"
            >
              <option value={0.5}>0.5x</option>
              <option value={1}>1x</option>
              <option value={1.5}>1.5x</option>
              <option value={2}>2x</option>
            </select>
          </div>

          {/* Center: Playback Controls */}
          <div className="flex items-center gap-4">
            <Button
              onClick={handleReset}
              variant="ghost"
              className="text-white hover:bg-gray-700"
              title="Reset to start"
            >
              <RotateCcw className="w-5 h-5" />
            </Button>

            <Button
              onClick={handlePrevFrame}
              disabled={currentFrameIndex === 0}
              variant="ghost"
              className="text-white hover:bg-gray-700 disabled:opacity-50"
              title="Previous frame"
            >
              <SkipBack className="w-5 h-5" />
            </Button>

            <Button
              onClick={handlePlayPause}
              variant="default"
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 flex items-center gap-2"
            >
              {isPlaying ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
              <span>{isPlaying ? 'Пауза' : 'Плей'}</span>
            </Button>

            <Button
              onClick={handleNextFrame}
              disabled={currentFrameIndex === DEMO_FRAMES.length - 1}
              variant="ghost"
              className="text-white hover:bg-gray-700 disabled:opacity-50"
              title="Next frame"
            >
              <SkipForward className="w-5 h-5" />
            </Button>

            <Button
              onClick={onClose}
              variant="ghost"
              className="text-white hover:bg-gray-700"
              title="Close demo"
            >
              ✕
            </Button>
          </div>

          {/* Right: Sound (placeholder) */}
          <div className="flex items-center gap-2">
            <Volume2 className="w-5 h-5 text-gray-400" />
            <span className="text-gray-400 text-sm">Демонстрация</span>
          </div>
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
  return (
    <svg className="w-full h-96 mx-auto" viewBox="0 0 1000 600">
      <defs>
        <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
          <polygon points="0 0, 10 3, 0 6" fill="#3B82F6" />
        </marker>
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
      </defs>

      {/* Background */}
      <rect width="1000" height="600" fill="#1F2937" />

      {/* Main visualization based on current frame */}
      {frame.phase === 'intro' && (
        <g>
          <circle cx="500" cy="300" r="150" fill="url(#blueGrad)" opacity="0.3" />
          <text
            x="500"
            y="320"
            fontSize="64"
            fontWeight="bold"
            fill="#3B82F6"
            textAnchor="middle"
          >
            🔒
          </text>
        </g>
      )}

      {frame.phase === 'alice_bob_meet' && (
        <g>
          {/* Alice */}
          <circle cx="200" cy="300" r="40" fill="url(#blueGrad)" />
          <text x="200" y="310" fontSize="24" textAnchor="middle" fill="white">
            👩
          </text>
          <text x="200" y="370" fontSize="16" textAnchor="middle" fill="#3B82F6" fontWeight="bold">
            Alice
          </text>

          {/* Bob */}
          <circle cx="800" cy="300" r="40" fill="url(#greenGrad)" />
          <text x="800" y="310" fontSize="24" textAnchor="middle" fill="white">
            👨
          </text>
          <text x="800" y="370" fontSize="16" textAnchor="middle" fill="#10B981" fontWeight="bold">
            Bob
          </text>

          {/* Heart between them */}
          <text
            x="500"
            y="310"
            fontSize="40"
            textAnchor="middle"
            fill="#EF4444"
            opacity={frameIndex % 2 === 0 ? 1 : 0.5}
          >
            ❤️
          </text>
        </g>
      )}

      {frame.phase === 'handshake_init' && (
        <g>
          {/* Alice & Bob */}
          <circle cx="200" cy="300" r="40" fill="url(#blueGrad)" />
          <text x="200" y="310" fontSize="24" textAnchor="middle" fill="white">
            👩
          </text>
          <circle cx="800" cy="300" r="40" fill="url(#greenGrad)" />
          <text x="800" y="310" fontSize="24" textAnchor="middle" fill="white">
            👨
          </text>

          {/* Handshake symbols */}
          <g opacity={frameIndex % 2 === 0 ? 1 : 0.5}>
            <path d="M 250 280 Q 500 200 750 280" stroke="#F59E0B" strokeWidth="3" fill="none" />
            <text x="500" y="180" fontSize="20" textAnchor="middle">
              🤝 X25519
            </text>
          </g>

          <g opacity={frameIndex % 2 === 0 ? 0.5 : 1}>
            <path d="M 250 320 Q 500 400 750 320" stroke="#8B5CF6" strokeWidth="3" fill="none" />
            <text x="500" y="450" fontSize="20" textAnchor="middle">
              🔐 ML-KEM-768
            </text>
          </g>
        </g>
      )}

      {frame.phase === 'message_1_input' && (
        <g>
          {/* Alice */}
          <circle cx="150" cy="200" r="35" fill="url(#blueGrad)" />
          <text x="150" y="210" fontSize="20" textAnchor="middle" fill="white">
            👩
          </text>

          {/* Message box */}
          <rect
            x="100"
            y="280"
            width="400"
            height="100"
            fill="#374151"
            stroke="#3B82F6"
            strokeWidth="2"
            rx="8"
          />
          <text x="300" y="320" fontSize="24" textAnchor="middle" fill="white" fontWeight="bold">
            "Привет, Bob!"
          </text>
          <text x="300" y="360" fontSize="14" textAnchor="middle" fill="#9CA3AF">
            Plaintext → Signing → Encryption
          </text>
        </g>
      )}

      {frame.phase === 'message_1_signing' && (
        <g>
          {/* Two signatures */}
          <rect
            x="150"
            y="150"
            width="200"
            height="80"
            fill="#FEF3C7"
            stroke="#D97706"
            strokeWidth="2"
            rx="8"
          />
          <text x="250" y="190" fontSize="14" textAnchor="middle" fill="#92400E" fontWeight="bold">
            Ed25519
          </text>
          <text x="250" y="220" fontSize="12" textAnchor="middle" fill="#B45309">
            Sig: 0x4a2f...
          </text>

          <rect
            x="550"
            y="150"
            width="200"
            height="80"
            fill="#E9D5FF"
            stroke="#7C3AED"
            strokeWidth="2"
            rx="8"
          />
          <text x="650" y="190" fontSize="14" textAnchor="middle" fill="#5B21B6" fontWeight="bold">
            ML-DSA
          </text>
          <text x="650" y="220" fontSize="12" textAnchor="middle" fill="#7C3AED">
            Sig: 0x8d1e...
          </text>

          {/* Message */}
          <rect
            x="250"
            y="300"
            width="500"
            height="60"
            fill="#374151"
            stroke="#3B82F6"
            strokeWidth="2"
            rx="8"
          />
          <text x="500" y="335" fontSize="16" textAnchor="middle" fill="white" fontWeight="bold">
            Сообщение подписано дважды ✓
          </text>
        </g>
      )}

      {frame.phase === 'message_1_encrypt' && (
        <g>
          {/* Encryption process */}
          <rect x="200" y="100" width="150" height="80" fill="#374151" stroke="#3B82F6" strokeWidth="2" rx="8" />
          <text x="275" y="130" fontSize="12" textAnchor="middle" fill="#3B82F6" fontWeight="bold">
            Plaintext
          </text>
          <text x="275" y="160" fontSize="10" textAnchor="middle" fill="#9CA3AF" fontFamily="monospace">
            "Привет, Bob!"
          </text>

          {/* Arrow */}
          <path d="M 350 140 L 420 140" stroke="#3B82F6" strokeWidth="2" markerEnd="url(#arrowhead)" />

          {/* Encryption box */}
          <circle cx="500" cy="140" r="60" fill="url(#purpleGrad)" opacity="0.5" />
          <text x="500" y="150" fontSize="32" textAnchor="middle">
            🔐
          </text>

          {/* Arrow */}
          <path d="M 560 140 L 630 140" stroke="#3B82F6" strokeWidth="2" markerEnd="url(#arrowhead)" />

          {/* Ciphertext */}
          <rect x="630" y="100" width="150" height="80" fill="#374151" stroke="#10B981" strokeWidth="2" rx="8" />
          <text x="705" y="130" fontSize="12" textAnchor="middle" fill="#10B981" fontWeight="bold">
            Ciphertext
          </text>
          <text x="705" y="160" fontSize="10" textAnchor="middle" fill="#9CA3AF" fontFamily="monospace">
            0x4f3a2b1c...
          </text>

          {/* AAD */}
          <rect x="250" y="250" width="500" height="60" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="8" />
          <text x="500" y="275" fontSize="12" textAnchor="middle" fill="#3730A3" fontWeight="bold">
            AAD: Session ID + Counter + Epoch
          </text>
          <text x="500" y="300" fontSize="10" textAnchor="middle" fill="#4F46E5" fontFamily="monospace">
            Нonce: R64 || C32
          </text>
        </g>
      )}

      {frame.phase === 'message_1_relay' && (
        <g>
          {/* Alice */}
          <circle cx="100" cy="300" r="35" fill="url(#blueGrad)" />
          <text x="100" y="310" fontSize="20" textAnchor="middle" fill="white">
            👩
          </text>

          {/* Relay with blindfold */}
          <rect
            x="400"
            y="250"
            width="200"
            height="100"
            fill="#6B7280"
            stroke="#9CA3AF"
            strokeWidth="2"
            rx="8"
          />
          <text x="500" y="290" fontSize="24" textAnchor="middle" fill="white">
            🚀
          </text>
          <text x="500" y="320" fontSize="12" textAnchor="middle" fill="#E5E7EB" fontWeight="bold">
            Relay Server
          </text>
          <text x="500" y="340" fontSize="10" textAnchor="middle" fill="#D1D5DB">
            (Слепой)
          </text>

          {/* Bob */}
          <circle cx="900" cy="300" r="35" fill="url(#greenGrad)" />
          <text x="900" y="310" fontSize="20" textAnchor="middle" fill="white">
            👨
          </text>

          {/* Flying message */}
          <g opacity={0.7 + (frameIndex % 2) * 0.3}>
            <path
              d="M 135 300 Q 500 150 865 300"
              stroke="#F59E0B"
              strokeWidth="3"
              fill="none"
              strokeDasharray="10,10"
            />
            <rect x="460" y="160" width="80" height="40" fill="#F59E0B" rx="4" />
            <text x="500" y="187" fontSize="10" textAnchor="middle" fill="white" fontWeight="bold">
              Encrypted
            </text>
          </g>
        </g>
      )}

      {frame.phase === 'relay_blindness' && (
        <g>
          {/* Central relay */}
          <circle cx="500" cy="300" r="80" fill="#6B7280" opacity="0.3" />
          <text x="500" y="320" fontSize="48" textAnchor="middle">
            👁️
          </text>
          <text x="500" y="400" fontSize="14" textAnchor="middle" fill="#E5E7EB" fontWeight="bold">
            СЛЕПОЙ КУРЬЕР
          </text>

          {/* Multiple messages flying around */}
          {[0, 1, 2, 3].map((i) => (
            <g key={i} opacity={0.6}>
              <path
                d={`M 150 150 Q 500 300 850 450`}
                stroke="#10B981"
                strokeWidth="2"
                fill="none"
                opacity="0.4"
              />
            </g>
          ))}

          {/* Blindfold lines */}
          <line x1="420" y1="280" x2="580" y2="280" stroke="#EF4444" strokeWidth="2" />
          <line x1="420" y1="320" x2="580" y2="320" stroke="#EF4444" strokeWidth="2" />
        </g>
      )}

      {frame.phase === 'group_chat_demo' && (
        <g>
          {/* Three users in circle */}
          {[
            { x: 500, y: 150, name: '👩 Alice', label: 'Alice' },
            { x: 250, y: 450, name: '👨 Bob', label: 'Bob' },
            { x: 750, y: 450, name: '👨 Charlie', label: 'Charlie' },
          ].map((user, idx) => (
            <g key={idx}>
              <circle cx={user.x} cy={user.y} r="40" fill="url(#blueGrad)" />
              <text x={user.x} y={user.y + 10} fontSize="20" textAnchor="middle" fill="white">
                {user.name.split(' ')[0]}
              </text>
              <text x={user.x} y={user.y + 80} fontSize="12" textAnchor="middle" fill="#3B82F6">
                {user.label}
              </text>
            </g>
          ))}

          {/* Connections */}
          <line x1="500" y1="190" x2="250" y2="410" stroke="#10B981" strokeWidth="2" />
          <line x1="500" y1="190" x2="750" y2="410" stroke="#10B981" strokeWidth="2" />
          <line x1="250" y1="410" x2="750" y2="410" stroke="#10B981" strokeWidth="2" />

          {/* Center: shared key */}
          <circle cx="500" cy="300" r="50" fill="#8B5CF6" opacity="0.3" />
          <text x="500" y="310" fontSize="28" textAnchor="middle" fill="#A78BFA">
            🔐
          </text>
          <text x="500" y="370" fontSize="12" textAnchor="middle" fill="#A78BFA" fontWeight="bold">
            Детерминистический Ключ
          </text>
        </g>
      )}

      {frame.phase === 'epoch_rekey' && (
        <g>
          {/* Timeline of epochs */}
          <line x1="100" y1="300" x2="900" y2="300" stroke="#9CA3AF" strokeWidth="2" />

          {/* Epoch 0 */}
          <circle cx="200" cy="300" r="30" fill="#DC2626" />
          <text x="200" y="310" fontSize="14" textAnchor="middle" fill="white" fontWeight="bold">
            Epoch 0
          </text>
          <text x="200" y="380" fontSize="12" textAnchor="middle" fill="#9CA3AF">
            ❌ Взломан КВК
          </text>

          {/* Rekey arrow */}
          <path d="M 250 300 L 350 300" stroke="#F59E0B" strokeWidth="3" markerEnd="url(#arrowhead)" />
          <circle cx="300" cy="260" r="20" fill="#F59E0B" />
          <text x="300" y="268" fontSize="16" textAnchor="middle" fill="white">
            🔑
          </text>

          {/* Epoch 1 */}
          <circle cx="500" cy="300" r="30" fill="#10B981" />
          <text x="500" y="310" fontSize="14" textAnchor="middle" fill="white" fontWeight="bold">
            Epoch 1
          </text>
          <text x="500" y="380" fontSize="12" textAnchor="middle" fill="#10B981">
            ✅ Защищен
          </text>

          {/* Rekey arrow */}
          <path d="M 550 300 L 650 300" stroke="#F59E0B" strokeWidth="3" markerEnd="url(#arrowhead)" />
          <circle cx="600" cy="260" r="20" fill="#F59E0B" />
          <text x="600" y="268" fontSize="16" textAnchor="middle" fill="white">
            🔑
          </text>

          {/* Epoch 2 */}
          <circle cx="800" cy="300" r="30" fill="#10B981" />
          <text x="800" y="310" fontSize="14" textAnchor="middle" fill="white" fontWeight="bold">
            Epoch 2
          </text>
          <text x="800" y="380" fontSize="12" textAnchor="middle" fill="#10B981">
            ✅ Защищен
          </text>
        </g>
      )}

      {frame.phase === 'outro' && (
        <g>
          <text x="500" y="150" fontSize="48" textAnchor="middle" fill="#10B981" fontWeight="bold">
            ✓ Безопасность Гарантирована
          </text>

          <rect x="150" y="250" width="700" height="280" fill="#1F2937" stroke="#10B981" strokeWidth="2" rx="8" />

          <text x="500" y="300" fontSize="16" textAnchor="middle" fill="#10B981" fontWeight="bold">
            Что Мы Увидели:
          </text>

          <text x="200" y="350" fontSize="14" fill="#9CA3AF">
            ✓ Гибридный Handshake (X25519 + ML-KEM)
          </text>
          <text x="200" y="390" fontSize="14" fill="#9CA3AF">
            ✓ Двойные Подписи (Ed25519 + ML-DSA)
          </text>
          <text x="200" y="430" fontSize="14" fill="#9CA3AF">
            ✓ Double Ratchet (Forward Secrecy)
          </text>
          <text x="200" y="470" fontSize="14" fill="#9CA3AF">
            ✓ Мандатное переключение эпох
          </text>
          <text x="200" y="510" fontSize="14" fill="#9CA3AF">
            ✓ Групповые чаты (детерминистические ключи)
          </text>
        </g>
      )}
    </svg>
  );
}
