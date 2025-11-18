'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ChevronRight, ChevronLeft, X } from 'lucide-react';

type SignaturesStep = 'intro' | 'ed25519' | 'mldsa' | 'process' | 'verification' | 'final';

interface SignaturesExplainerProps {
  onClose: () => void;
}

export function SignaturesExplainer({ onClose }: SignaturesExplainerProps) {
  const [currentStep, setCurrentStep] = useState<SignaturesStep>('intro');

  const steps: SignaturesStep[] = ['intro', 'ed25519', 'mldsa', 'process', 'verification', 'final'];
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
      <Card className="w-full max-w-4xl max-h-[90vh] overflow-auto">
        <CardHeader className="flex flex-row items-center justify-between border-b">
          <CardTitle>Двойные Подписи: Аутентификация</CardTitle>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded">
            <X className="w-5 h-5" />
          </button>
        </CardHeader>

        <CardContent className="p-8">
          <div className="grid grid-cols-2 gap-8 mb-8">
            <div className="space-y-2">
              <h3 className="font-semibold text-sm text-gray-600 dark:text-gray-400">ПРОЦЕСС</h3>
              {[
                { id: 'intro', label: '📝 Введение' },
                { id: 'ed25519', label: '✓ Ed25519 (Классическая)' },
                { id: 'mldsa', label: '✓ ML-DSA (Пост-квантовая)' },
                { id: 'process', label: '📋 Процесс подписания' },
                { id: 'verification', label: '🔍 Верификация' },
                { id: 'final', label: '✅ Гарантии' },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setCurrentStep(item.id as SignaturesStep)}
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

            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 min-h-96 flex flex-col items-center justify-center">
              <SignaturesVisualization step={currentStep} />
            </div>
          </div>

          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-8">
            <h4 className="font-semibold mb-2">{getSignaturesStepTitle(currentStep)}</h4>
            <p className="text-sm text-gray-700 dark:text-gray-300">{getSignaturesStepDescription(currentStep)}</p>
          </div>

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

interface SignaturesVisualizationProps {
  step: SignaturesStep;
}

function SignaturesVisualization({ step }: SignaturesVisualizationProps) {
  switch (step) {
    case 'intro':
      return (
        <div className="w-full text-center space-y-4">
          <div className="text-6xl">✍️</div>
          <p className="text-lg font-semibold">Двойные подписи = Двойная аутентификация</p>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Каждое сообщение подписано дважды для максимальной безопасности
          </p>
        </div>
      );

    case 'ed25519':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 300 200">
          <rect x="20" y="30" width="260" height="140" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="8" />
          <text x="150" y="60" fontSize="16" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
            Ed25519 (Классическая подпись)
          </text>
          <text x="150" y="90" fontSize="12" fill="#0C4A6E" textAnchor="middle">
            • Быстрая (миллисекунды)
          </text>
          <text x="150" y="110" fontSize="12" fill="#0C4A6E" textAnchor="middle">
            • Сертифицирована NIST
          </text>
          <text x="150" y="130" fontSize="12" fill="#0C4A6E" textAnchor="middle">
            • Уязвима к квантовым компьютерам
          </text>
          <text x="150" y="155" fontSize="11" fill="#6B7280" fontFamily="monospace" textAnchor="middle">
            Signature: 0x4a2f8b3d...
          </text>
        </svg>
      );

    case 'mldsa':
      return (
        <svg className="w-full h-48 mx-auto" viewBox="0 0 300 200">
          <rect x="20" y="30" width="260" height="140" fill="#E9D5FF" stroke="#7C3AED" strokeWidth="2" rx="8" />
          <text x="150" y="60" fontSize="16" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
            ML-DSA (Пост-квантовая подпись)
          </text>
          <text x="150" y="90" fontSize="12" fill="#5B21B6" textAnchor="middle">
            • Медленнее (но все еще быстро)
          </text>
          <text x="150" y="110" fontSize="12" fill="#5B21B6" textAnchor="middle">
            • Устойчива к квантовым компьютерам
          </text>
          <text x="150" y="130" fontSize="12" fill="#5B21B6" textAnchor="middle">
            • NIST стандарт (2024)
          </text>
          <text x="150" y="155" fontSize="11" fill="#6B7280" fontFamily="monospace" textAnchor="middle">
            Signature: 0x8d1e5c9a...
          </text>
        </svg>
      );

    case 'process':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 400 400">
          {/* Message */}
          <rect x="50" y="20" width="300" height="60" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="4" />
          <text x="200" y="55" fontSize="14" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
            Сообщение: "Привет, Bob!"
          </text>

          {/* Arrows down */}
          <path d="M 120 80 L 120 120" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />
          <path d="M 280 80 L 280 120" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

          {/* Ed25519 signing */}
          <rect x="60" y="120" width="120" height="80" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="4" />
          <text x="120" y="150" fontSize="12" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
            Подписать
          </text>
          <text x="120" y="172" fontSize="11" fill="#0C4A6E" textAnchor="middle">
            Ed25519
          </text>
          <text x="120" y="190" fontSize="9" fill="#0C4A6E" fontFamily="monospace" textAnchor="middle">
            Sig_ED
          </text>

          {/* ML-DSA signing */}
          <rect x="220" y="120" width="120" height="80" fill="#E9D5FF" stroke="#7C3AED" strokeWidth="2" rx="4" />
          <text x="280" y="150" fontSize="12" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
            Подписать
          </text>
          <text x="280" y="172" fontSize="11" fill="#5B21B6" textAnchor="middle">
            ML-DSA
          </text>
          <text x="280" y="190" fontSize="9" fill="#5B21B6" fontFamily="monospace" textAnchor="middle">
            Sig_MLDSA
          </text>

          {/* Arrows down */}
          <path d="M 120 200 L 120 240" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />
          <path d="M 280 200 L 280 240" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

          {/* Result */}
          <rect x="50" y="240" width="300" height="120" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
          <text x="200" y="270" fontSize="13" fontWeight="bold" fill="#15803D" textAnchor="middle">
            Подписанное сообщение
          </text>
          <text x="200" y="295" fontSize="10" fill="#15803D" fontFamily="monospace" textAnchor="middle">
            Сообщение + Sig_ED + Sig_MLDSA
          </text>
          <text x="200" y="330" fontSize="12" fill="#15803D" textAnchor="middle" fontWeight="bold">
            ✓ Двойно защищено от подделки
          </text>
        </svg>
      );

    case 'verification':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 400 300">
          {/* Received message */}
          <rect x="50" y="20" width="300" height="60" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="4" />
          <text x="200" y="55" fontSize="13" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
            Получено: Сообщение + Sig_ED + Sig_MLDSA
          </text>

          {/* Verification arrows */}
          <path d="M 120 80 L 120 120" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />
          <path d="M 280 80 L 280 120" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

          {/* Ed25519 verify */}
          <circle cx="120" cy="160" r="30" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" />
          <text x="120" y="165" fontSize="20" textAnchor="middle" fill="#0284C7">
            ✓
          </text>
          <text x="120" y="210" fontSize="11" textAnchor="middle" fill="#0C4A6E" fontWeight="bold">
            Ed25519 OK
          </text>

          {/* ML-DSA verify */}
          <circle cx="280" cy="160" r="30" fill="#E9D5FF" stroke="#7C3AED" strokeWidth="2" />
          <text x="280" y="165" fontSize="20" textAnchor="middle" fill="#7C3AED">
            ✓
          </text>
          <text x="280" y="210" fontSize="11" textAnchor="middle" fill="#5B21B6" fontWeight="bold">
            ML-DSA OK
          </text>

          {/* Result */}
          <rect x="50" y="240" width="300" height="50" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
          <text x="200" y="270" fontSize="13" fontWeight="bold" fill="#15803D" textAnchor="middle">
            ✅ Обе подписи верны = Сообщение аутентично
          </text>
        </svg>
      );

    case 'final':
      return (
        <div className="w-full space-y-4">
          <svg className="w-full h-32 mx-auto" viewBox="0 0 300 150">
            <circle cx="150" cy="75" r="50" fill="#10B981" opacity="0.2" />
            <text x="150" y="85" fontSize="48" textAnchor="middle">
              ✓✓
            </text>
          </svg>

          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 space-y-2">
            <p className="font-semibold text-green-700 dark:text-green-300">Гарантии двойной подписи:</p>
            <ul className="text-xs text-green-600 dark:text-green-400 space-y-1 ml-4 list-disc">
              <li>Даже если классическая подпись взломана → ML-DSA защищает</li>
              <li>Даже если ML-DSA проверка пропущена → Ed25519 защищает</li>
              <li>Невозможно подделать сообщение без обеих подписей</li>
              <li>Не отрицание (Non-repudiation) = автор не может отрицать</li>
            </ul>
          </div>
        </div>
      );

    default:
      return null;
  }
}

function getSignaturesStepTitle(step: SignaturesStep): string {
  const titles: Record<SignaturesStep, string> = {
    intro: '📝 Что такое двойные подписи?',
    ed25519: '✓ Ed25519: Классическая подпись',
    mldsa: '✓ ML-DSA: Пост-квантовая подпись',
    process: '📋 Процесс подписания сообщения',
    verification: '🔍 Верификация подписей',
    final: '✅ Гарантии безопасности',
  };
  return titles[step];
}

function getSignaturesStepDescription(step: SignaturesStep): string {
  const descriptions: Record<SignaturesStep, string> = {
    intro:
      'Двойная подпись означает, что каждое сообщение подписано дважды: классической (Ed25519) и пост-квантовой (ML-DSA) подписями. Это обеспечивает максимальную аутентификацию.',
    ed25519:
      'Ed25519 — это быстрая классическая цифровая подпись на основе эллиптических кривых. Она сертифицирована NIST и используется в OpenSSH и других стандартах. Однако она уязвима к квантовым компьютерам.',
    mldsa:
      'ML-DSA (Модульная Решетчатая Цифровая Подпись Алгоритм) — это новый стандарт NIST (2024) для пост-квантовых подписей. Она устойчива к квантовым атакам, но немного медленнее, чем Ed25519.',
    process:
      'Процесс подписания: 1) Берется сообщение, 2) Подписывается Ed25519 (быстро), 3) Подписывается ML-DSA (безопасно). Результат: одно сообщение с двумя независимыми подписями.',
    verification:
      'Bob получает подписанное сообщение. Он проверяет обе подписи: сначала Ed25519, потом ML-DSA. Если обе верны, сообщение аутентично и не могло быть подделано.',
    final:
      'Двойная подпись обеспечивает: (1) Аутентификацию от обоих алгоритмов, (2) Невозможность подделки (требуется оба секретных ключа), (3) Non-repudiation (автор не может отрицать авторство).',
  };
  return descriptions[step];
}
