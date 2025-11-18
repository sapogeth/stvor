'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ChevronRight, ChevronLeft, X } from 'lucide-react';

type HandshakeStep = 'intro' | 'alice_keygen' | 'bob_keygen' | 'alice_send' | 'bob_encap' | 'alice_decap' | 'shared_secret';

interface HandshakeExplainerProps {
  onClose: () => void;
}

export function HandshakeExplainer({ onClose }: HandshakeExplainerProps) {
  const [currentStep, setCurrentStep] = useState<HandshakeStep>('intro');

  const steps: HandshakeStep[] = [
    'intro',
    'alice_keygen',
    'bob_keygen',
    'alice_send',
    'bob_encap',
    'alice_decap',
    'shared_secret',
  ];
  const currentStepIndex = steps.indexOf(currentStep);

  const handleNext = () => {
    if (currentStepIndex < steps.length - 1) {
      setCurrentStep(steps[currentStepIndex + 1]);
    }
  };

  const handlePrev = () => {
    if (currentStepIndex > 0) {
      setCurrentStep(steps[currentStepIndex - 1]);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-6xl max-h-[95vh] overflow-auto">
        <CardHeader className="flex flex-row items-center justify-between border-b sticky top-0 bg-white dark:bg-gray-900 z-10">
          <CardTitle>Как устроен Гибридный Handshake</CardTitle>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded">
            <X className="w-5 h-5" />
          </button>
        </CardHeader>

        <CardContent className="p-6 sm:p-8">
          {/* Progress */}
          <div className="grid grid-cols-7 gap-1 mb-8 overflow-x-auto">
            {steps.map((step, idx) => (
              <div key={step} className="flex flex-col items-center flex-shrink-0">
                <div
                  className={`w-8 h-8 sm:w-9 sm:h-9 rounded-full flex items-center justify-center text-xs font-bold transition-all cursor-pointer ${
                    idx < currentStepIndex
                      ? 'bg-green-500 text-white'
                      : idx === currentStepIndex
                        ? 'bg-blue-500 text-white'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-600'
                  }`}
                  onClick={() => setCurrentStep(steps[idx])}
                >
                  {idx < currentStepIndex ? '✓' : idx + 1}
                </div>
              </div>
            ))}
          </div>

          {/* Main content */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8 mb-8">
            {/* Left - Steps list */}
            <div className="lg:col-span-1 space-y-2">
              <h3 className="font-semibold text-sm text-gray-600 dark:text-gray-400">ПРОЦЕСС</h3>
              {[
                { id: 'intro', label: '📋 Что это?' },
                { id: 'alice_keygen', label: '🔐 Alice генерирует ключи' },
                { id: 'bob_keygen', label: '🔐 Bob генерирует ключи' },
                { id: 'alice_send', label: '📤 Alice отправляет публичные ключи' },
                { id: 'bob_encap', label: '🔗 Bob encapsulate' },
                { id: 'alice_decap', label: '🔓 Alice decapsulate' },
                { id: 'shared_secret', label: '✅ Общий Secret' },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setCurrentStep(item.id as HandshakeStep)}
                  className={`w-full text-left p-3 rounded-lg transition-all text-sm ${
                    item.id === currentStep
                      ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 border-l-4 border-blue-600'
                      : 'hover:bg-gray-100 dark:hover:bg-gray-800'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>

            {/* Right - Visualization */}
            {/* Right content */}
            <div className="lg:col-span-2 space-y-6">
              {/* Visualization */}
              <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 min-h-80 flex flex-col items-center justify-center">
                <HandshakeVisualization step={currentStep} />
              </div>

              {/* Description */}
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 sm:p-6">
                <h4 className="font-semibold mb-2 text-base sm:text-lg">{getHandshakeStepTitle(currentStep)}</h4>
                <p className="text-sm sm:text-base text-gray-700 dark:text-gray-300 leading-relaxed">{getHandshakeStepDescription(currentStep)}</p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <div className="flex items-center justify-between">
            <Button
              variant="outline"
              onClick={handlePrev}
              disabled={currentStepIndex === 0}
              className="flex items-center gap-2"
            >
              <ChevronLeft className="w-4 h-4" />
              Назад
            </Button>

            <div className="text-sm text-gray-600 dark:text-gray-400">
              Шаг {currentStepIndex + 1} из {steps.length}
            </div>

            {currentStepIndex < steps.length - 1 ? (
              <Button onClick={handleNext} className="flex items-center gap-2">
                Вперед
                <ChevronRight className="w-4 h-4" />
              </Button>
            ) : (
              <Button onClick={onClose} className="bg-green-600 hover:bg-green-700">
                ✅ Понял!
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

interface HandshakeVisualizationProps {
  step: HandshakeStep;
}

function HandshakeVisualization({ step }: HandshakeVisualizationProps) {
  switch (step) {
    case 'intro':
      return (
        <div className="w-full text-center space-y-4">
          <svg className="w-full h-32 mx-auto" viewBox="0 0 200 100">
            {/* Two people */}
            <circle cx="50" cy="30" r="10" fill="#3B82F6" />
            <path d="M 50 40 L 40 50 L 50 50 L 60 50" fill="#3B82F6" />
            <line x1="50" y1="50" x2="50" y2="65" stroke="#3B82F6" strokeWidth="2" />

            <circle cx="150" cy="30" r="10" fill="#10B981" />
            <path d="M 150 40 L 140 50 L 150 50 L 160 50" fill="#10B981" />
            <line x1="150" y1="50" x2="150" y2="65" stroke="#10B981" strokeWidth="2" />

            {/* Keys between them */}
            <path d="M 70 35 L 130 35" stroke="#F59E0B" strokeWidth="2" markerEnd="url(#arrowhead)" />
            <text x="100" y="25" fontSize="10" fill="#F59E0B" fontWeight="bold" textAnchor="middle">
              🔑 Гибридный обмен
            </text>
          </svg>

          <div className="text-left space-y-2">
            <p className="text-sm font-semibold">Гибридный Handshake объединяет:</p>
            <ul className="text-xs text-gray-600 dark:text-gray-400 space-y-1 ml-4 list-disc">
              <li><strong>X25519</strong> - классический эллиптический ключ обмен (мгновенный)</li>
              <li><strong>ML-KEM-768</strong> - пост-квантовый ключ encapsulation (защита от КВК)</li>
            </ul>
          </div>
        </div>
      );

    case 'alice_keygen':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 220 150">
          {/* Alice */}
          <circle cx="50" cy="30" r="10" fill="#3B82F6" />
          <text x="50" y="55" fontSize="11" fontWeight="bold" fill="#1E40AF" textAnchor="middle">
            ALICE
          </text>

          {/* Key generation */}
          <g>
            {/* X25519 */}
            <rect x="20" y="70" width="60" height="35" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="3" />
            <text x="50" y="85" fontSize="9" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              X25519
            </text>
            <text x="50" y="100" fontSize="7" fill="#0C4A6E" textAnchor="middle" fontFamily="monospace">
              sk_x | pk_x
            </text>

            {/* ML-KEM */}
            <rect x="90" y="70" width="60" height="35" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="3" />
            <text x="120" y="85" fontSize="9" fontWeight="bold" fill="#15803D" textAnchor="middle">
              ML-KEM-768
            </text>
            <text x="120" y="100" fontSize="7" fill="#15803D" textAnchor="middle" fontFamily="monospace">
              sk_mlkem | pk_mlkem
            </text>
          </g>

          {/* Generated indicator */}
          <circle cx="50" cy="40" r="20" fill="none" stroke="#3B82F6" strokeWidth="2" opacity="0.5" />
          <text x="50" y="122" fontSize="10" fontWeight="bold" fill="#6B7280" textAnchor="middle">
            ✓ Оба ключа сгенерированы
          </text>
          <text x="50" y="140" fontSize="8" fill="#6B7280" textAnchor="middle">
            Секретные ключи хранятся локально
          </text>
        </svg>
      );

    case 'bob_keygen':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 220 150">
          {/* Bob */}
          <circle cx="170" cy="30" r="10" fill="#10B981" />
          <text x="170" y="55" fontSize="11" fontWeight="bold" fill="#065F46" textAnchor="middle">
            BOB
          </text>

          {/* Key generation */}
          <g>
            {/* X25519 */}
            <rect x="140" y="70" width="60" height="35" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="3" />
            <text x="170" y="85" fontSize="9" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              X25519
            </text>
            <text x="170" y="100" fontSize="7" fill="#0C4A6E" textAnchor="middle" fontFamily="monospace">
              sk_x | pk_x
            </text>
          </g>

          {/* Generated indicator */}
          <circle cx="170" cy="40" r="20" fill="none" stroke="#10B981" strokeWidth="2" opacity="0.5" />
          <text x="170" y="122" fontSize="10" fontWeight="bold" fill="#6B7280" textAnchor="middle">
            ✓ Bob тоже генерирует ключи
          </text>
          <text x="170" y="140" fontSize="8" fill="#6B7280" textAnchor="middle">
            Готов получить публичные ключи Alice
          </text>
        </svg>
      );

    case 'alice_send':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 300 150">
          {/* Alice's keys */}
          <g>
            <circle cx="40" cy="30" r="10" fill="#3B82F6" />

            <rect x="20" y="55" width="40" height="25" fill="#DBEAFE" stroke="#0284C7" strokeWidth="1" rx="2" />
            <text x="40" y="72" fontSize="7" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              pk_x
            </text>

            <rect x="65" y="55" width="40" height="25" fill="#DCFCE7" stroke="#16A34A" strokeWidth="1" rx="2" />
            <text x="85" y="72" fontSize="7" fontWeight="bold" fill="#15803D" textAnchor="middle">
              pk_mlkem
            </text>
          </g>

          {/* Flying to server */}
          <g>
            <path d="M 110 65 L 160 65" stroke="#F59E0B" strokeWidth="3" markerEnd="url(#arrowhead)" />
            <text x="135" y="50" fontSize="10" fontWeight="bold" fill="#F59E0B">
              📤
            </text>
          </g>

          {/* Server/Relay */}
          <rect x="170" y="45" width="60" height="40" fill="#F3F4F6" stroke="#6B7280" strokeWidth="2" rx="4" />
          <text x="200" y="72" fontSize="10" fontWeight="bold" fill="#6B7280" textAnchor="middle">
            Relay
          </text>

          {/* Alice to Bob arrow */}
          <g>
            <path d="M 230 65 L 280 65" stroke="#F59E0B" strokeWidth="3" markerEnd="url(#arrowhead)" />
          </g>

          {/* Bob receives */}
          <circle cx="290" cy="30" r="10" fill="#10B981" />
          <rect x="270" y="55" width="40" height="25" fill="#DBEAFE" stroke="#0284C7" strokeWidth="1" rx="2" />
          <rect x="295" y="55" width="40" height="25" fill="#DCFCE7" stroke="#16A34A" strokeWidth="1" rx="2" />

          {/* Description */}
          <text x="150" y="120" fontSize="9" fontWeight="bold" fill="#6B7280" textAnchor="middle">
            Публичные ключи Alice отправляются на Relay
          </text>
          <text x="150" y="135" fontSize="8" fill="#6B7280" textAnchor="middle">
            Bob получит их оттуда
          </text>
        </svg>
      );

    case 'bob_encap':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 250 150">
          {/* Bob receives keys */}
          <g>
            <circle cx="40" cy="30" r="10" fill="#10B981" />

            <rect x="20" y="55" width="40" height="25" fill="#DBEAFE" stroke="#0284C7" strokeWidth="1" rx="2" />
            <text x="40" y="72" fontSize="7" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              pk_x
            </text>

            <rect x="65" y="55" width="40" height="25" fill="#DCFCE7" stroke="#16A34A" strokeWidth="1" rx="2" />
            <text x="85" y="72" fontSize="7" fontWeight="bold" fill="#15803D" textAnchor="middle">
              pk_mlkem
            </text>
          </g>

          {/* Encapsulation process */}
          <g>
            <circle cx="145" cy="65" r="15" fill="none" stroke="#F59E0B" strokeWidth="2" />
            <text x="145" y="70" fontSize="12" fontWeight="bold" fill="#F59E0B" textAnchor="middle">
              🔗
            </text>
            <text x="145" y="100" fontSize="8" fill="#6B7280" textAnchor="middle">
              Encapsulate
            </text>
          </g>

          {/* Result */}
          <g>
            <rect x="185" y="50" width="60" height="30" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="3" />
            <text x="215" y="65" fontSize="9" fontWeight="bold" fill="#92400E" textAnchor="middle">
              Ciphertext
            </text>
            <text x="215" y="78" fontSize="7" fill="#92400E" textAnchor="middle" fontFamily="monospace">
              0xf3e4d5...
            </text>
          </g>

          {/* Description */}
          <text x="125" y="125" fontSize="9" fontWeight="bold" fill="#6B7280" textAnchor="middle">
            Bob encapsulate MLKEM:
          </text>
          <text x="125" y="140" fontSize="8" fill="#6B7280" textAnchor="middle">
            Создает ciphertext + shared secret (локально хранит)
          </text>
        </svg>
      );

    case 'alice_decap':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 250 150">
          {/* Alice */}
          <circle cx="40" cy="30" r="10" fill="#3B82F6" />

          {/* Secret key */}
          <rect x="20" y="55" width="50" height="25" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="3" />
          <text x="45" y="72" fontSize="8" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
            sk_mlkem
          </text>

          {/* Receives ciphertext */}
          <g>
            <path d="M 95 65 L 130 65" stroke="#F59E0B" strokeWidth="2" markerEnd="url(#arrowhead)" />
            <rect x="95" y="50" width="40" height="30" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="3" />
            <text x="115" y="72" fontSize="7" fontWeight="bold" fill="#92400E" textAnchor="middle">
              Ciphertext
            </text>
          </g>

          {/* Decapsulation */}
          <g>
            <circle cx="170" cy="65" r="15" fill="none" stroke="#10B981" strokeWidth="2" />
            <text x="170" y="70" fontSize="12" fontWeight="bold" fill="#10B981" textAnchor="middle">
              🔓
            </text>
            <text x="170" y="100" fontSize="8" fill="#6B7280" textAnchor="middle">
              Decapsulate
            </text>
          </g>

          {/* Result */}
          <g>
            <rect x="210" y="50" width="40" height="30" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="3" />
            <text x="230" y="72" fontSize="8" fontWeight="bold" fill="#15803D" textAnchor="middle">
              Shared
            </text>
            <text x="230" y="78" fontSize="8" fontWeight="bold" fill="#15803D" textAnchor="middle">
              Secret
            </text>
          </g>

          {/* Description */}
          <text x="125" y="125" fontSize="9" fontWeight="bold" fill="#6B7280" textAnchor="middle">
            Alice decapsulate MLKEM:
          </text>
          <text x="125" y="140" fontSize="8" fill="#6B7280" textAnchor="middle">
            Извлекает тот же shared secret, что и Bob
          </text>
        </svg>
      );

    case 'shared_secret':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 250 150">
          {/* Alice */}
          <circle cx="50" cy="30" r="10" fill="#3B82F6" />
          <text x="50" y="55" fontSize="10" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
            ALICE
          </text>

          {/* Bob */}
          <circle cx="200" cy="30" r="10" fill="#10B981" />
          <text x="200" y="55" fontSize="10" fontWeight="bold" fill="#15803D" textAnchor="middle">
            BOB
          </text>

          {/* Shared secrets */}
          <rect x="30" y="70" width="40" height="30" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="3" />
          <text x="50" y="92" fontSize="7" fontWeight="bold" fill="#3730A3" textAnchor="middle">
            ss_hybrid
          </text>

          <rect x="180" y="70" width="40" height="30" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="3" />
          <text x="200" y="92" fontSize="7" fontWeight="bold" fill="#3730A3" textAnchor="middle">
            ss_hybrid
          </text>

          {/* Equals sign */}
          <text x="125" y="92" fontSize="20" fontWeight="bold" fill="#10B981" textAnchor="middle">
            =
          </text>

          {/* Checkmark */}
          <circle cx="125" cy="115" r="8" fill="#10B981" />
          <text x="125" y="120" fontSize="14" fontWeight="bold" fill="white" textAnchor="middle">
            ✓
          </text>

          {/* Description */}
          <text x="125" y="135" fontSize="9" fontWeight="bold" fill="#6B7280" textAnchor="middle">
            Оба знают один и тот же гибридный shared secret!
          </text>
        </svg>
      );

    default:
      return null;
  }
}

function getHandshakeStepTitle(step: HandshakeStep): string {
  const titles: Record<HandshakeStep, string> = {
    intro: '📋 Что такое гибридный handshake?',
    alice_keygen: '🔐 Alice генерирует ключи',
    bob_keygen: '🔐 Bob генерирует ключи',
    alice_send: '📤 Alice отправляет публичные ключи',
    bob_encap: '🔗 Bob encapsulate ML-KEM',
    alice_decap: '🔓 Alice decapsulate ML-KEM',
    shared_secret: '✅ Общий гибридный Secret',
  };
  return titles[step];
}

function getHandshakeStepDescription(step: HandshakeStep): string {
  const descriptions: Record<HandshakeStep, string> = {
    intro:
      'Гибридный handshake одновременно использует классическую и пост-квантовую криптографию. Это обеспечивает защиту от обоих типов компьютеров (классических и квантовых).',
    alice_keygen:
      'Alice генерирует два набора ключей: X25519 (классический) и ML-KEM-768 (пост-квантовый). Оба наиболее секретные ключи хранятся локально и никогда не отправляются.',
    bob_keygen:
      'Bob также генерирует свои ключи независимо. Это необходимо для асимметричного ключа обмена.',
    alice_send:
      'Alice отправляет только публичные ключи на Relay Server. Никакие секретные ключи не отправляются! Relay просто передает их Bob.',
    bob_encap:
      'Bob получает публичные ключи Alice и использует их для encapsulation: создает ciphertext, который может расшифровать только Alice. Локально Bob вычисляет shared secret.',
    alice_decap:
      'Alice получает ciphertext от Bob и использует свой секретный ключ для decapsulation. Она получает тот же shared secret, что и Bob, потому что алгоритм детерминирован.',
    shared_secret:
      'Теперь Alice и Bob знают один и тот же гибридный shared secret. Этот secret используется как корень для всех остальных ключей (Root Key в ratchet).',
  };
  return descriptions[step];
}
