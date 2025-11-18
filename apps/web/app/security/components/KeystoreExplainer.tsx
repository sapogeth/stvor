'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ChevronRight, ChevronLeft, X } from 'lucide-react';

type KeystoreStep = 'password' | 'salt' | 'pbkdf2' | 'encryption' | 'storage' | 'final';

interface KeystoreExplainerProps {
  onClose: () => void;
}

export function KeystoreExplainer({ onClose }: KeystoreExplainerProps) {
  const [currentStep, setCurrentStep] = useState<KeystoreStep>('password');
  const [progress, setProgress] = useState(0);

  const steps: KeystoreStep[] = ['password', 'salt', 'pbkdf2', 'encryption', 'storage', 'final'];
  const currentStepIndex = steps.indexOf(currentStep);

  useEffect(() => {
    if (currentStep === 'pbkdf2') {
      // Simulate PBKDF2 progress
      const interval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 100) {
            clearInterval(interval);
            return 100;
          }
          return prev + Math.random() * 15;
        });
      }, 50);
      return () => clearInterval(interval);
    } else {
      setProgress(0);
    }
  }, [currentStep]);

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
          <CardTitle>Где твои ключи хранятся безопасно</CardTitle>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded">
            <X className="w-5 h-5" />
          </button>
        </CardHeader>

        <CardContent className="p-8">
          <div className="grid grid-cols-4 gap-2 mb-8">
            {steps.map((step, idx) => (
              <div key={step} className="flex flex-col items-center">
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold transition-all ${
                    idx < currentStepIndex
                      ? 'bg-green-500 text-white'
                      : idx === currentStepIndex
                        ? 'bg-blue-500 text-white'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-600'
                  }`}
                >
                  {idx < currentStepIndex ? '✓' : idx + 1}
                </div>
                <div className="text-xs mt-2 text-center">
                  {[
                    'Пароль',
                    'Соль',
                    'PBKDF2',
                    'Шифрование',
                    'Хранение',
                    'Готово',
                  ][idx]}
                </div>
              </div>
            ))}
          </div>

          {/* Step content */}
          <div className="grid grid-cols-2 gap-8 mb-8">
            {/* Left column - Step list */}
            <div className="space-y-3">
              <h3 className="font-semibold text-sm text-gray-600 dark:text-gray-400">ЭТАПЫ</h3>
              {steps.map((step, idx) => (
                <button
                  key={step}
                  onClick={() => setCurrentStep(step)}
                  className={`w-full text-left p-3 rounded-lg transition-all ${
                    step === currentStep
                      ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 border-l-4 border-blue-600'
                      : 'hover:bg-gray-100 dark:hover:bg-gray-800'
                  }`}
                >
                  <div className="text-sm font-medium">
                    {['🔐 Пароль', '🧂 Соль', '⚙️ PBKDF2', '🔒 Шифрование', '💾 Хранение', '✅ Готово'][
                      idx
                    ]}
                  </div>
                </button>
              ))}
            </div>

            {/* Right column - Visualization */}
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 min-h-96 flex flex-col items-center justify-center">
              <KeystoreVisualization step={currentStep} progress={progress} />
            </div>
          </div>

          {/* Step description */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-8">
            <h4 className="font-semibold mb-2">{getStepTitle(currentStep)}</h4>
            <p className="text-sm text-gray-700 dark:text-gray-300">{getStepDescription(currentStep)}</p>
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

interface KeystoreVisualizationProps {
  step: KeystoreStep;
  progress: number;
}

function KeystoreVisualization({ step, progress }: KeystoreVisualizationProps) {
  switch (step) {
    case 'password':
      return (
        <div className="w-full space-y-4">
          <svg className="w-full h-32 mx-auto" viewBox="0 0 200 120">
            {/* Browser window */}
            <rect x="20" y="10" width="160" height="100" fill="none" stroke="#6B7280" strokeWidth="2" rx="4" />
            <rect x="20" y="10" width="160" height="20" fill="#E5E7EB" />
            <circle cx="30" cy="20" r="2" fill="#6B7280" />
            <circle cx="38" cy="20" r="2" fill="#6B7280" />
            <circle cx="46" cy="20" r="2" fill="#6B7280" />

            {/* Password field */}
            <rect x="35" y="45" width="130" height="30" fill="white" stroke="#D1D5DB" strokeWidth="1" rx="4" />
            <text x="45" y="65" fontSize="18" fill="#3B82F6" fontWeight="bold">
              • • • • • • •
            </text>
            <text x="45" y="40" fontSize="12" fill="#6B7280" fontWeight="600">
              Введите пароль:
            </text>

            {/* Hint */}
            <text x="45" y="90" fontSize="11" fill="#10B981" fontWeight="600">
              Plaintext: !Qwerty123
            </text>
          </svg>
        </div>
      );

    case 'salt':
      return (
        <div className="w-full space-y-4">
          <svg className="w-full h-32 mx-auto" viewBox="0 0 200 120">
            {/* Password */}
            <g>
              <rect x="20" y="10" width="70" height="40" fill="#E0E7FF" stroke="#6366F1" strokeWidth="2" rx="4" />
              <text x="30" y="35" fontSize="12" fontWeight="bold" fill="#4F46E5">
                Password
              </text>
              <text x="30" y="48" fontSize="9" fill="#6B7280" fontFamily="monospace">
                !Qwerty123
              </text>
            </g>

            {/* Plus */}
            <text x="100" y="35" fontSize="20" fontWeight="bold" fill="#6B7280">
              +
            </text>

            {/* Salt */}
            <g>
              <rect x="110" y="10" width="70" height="40" fill="#FEF3C7" stroke="#F59E0B" strokeWidth="2" rx="4" />
              <text x="120" y="35" fontSize="12" fontWeight="bold" fill="#B45309">
                Salt
              </text>
              <text x="120" y="48" fontSize="9" fill="#6B7280" fontFamily="monospace">
                0x7f42a9c2...
              </text>
            </g>

            {/* Arrow */}
            <path d="M 100 70 L 100 90" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

            {/* Result */}
            <rect x="35" y="95" width="130" height="20" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="4" />
            <text x="45" y="110" fontSize="11" fill="#0C4A6E" fontWeight="600">
              256-bit Random Salt
            </text>
          </svg>
        </div>
      );

    case 'pbkdf2':
      return (
        <div className="w-full space-y-4">
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-center">PBKDF2: 600,000 раундов хеширования</h4>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden">
              <div
                className="bg-gradient-to-r from-blue-500 to-blue-600 h-full transition-all duration-100"
                style={{ width: `${Math.min(progress, 100)}%` }}
              />
            </div>
            <p className="text-xs text-center text-gray-600 dark:text-gray-400">
              {Math.round(Math.min(progress, 100))}% завершено
            </p>
          </div>

          <svg className="w-full h-24 mx-auto" viewBox="0 0 200 100">
            {/* Mill */}
            <circle cx="100" cy="50" r="30" fill="none" stroke="#6B7280" strokeWidth="2" />
            <circle
              cx="100"
              cy="50"
              r="28"
              fill="none"
              stroke="#3B82F6"
              strokeWidth="1"
              opacity="0.5"
              style={{
                transform: `rotate(${progress * 3.6}deg)`,
                transformOrigin: '100px 50px',
                transition: 'transform 0.1s linear',
              }}
            >
              <animate attributeName="opacity" values="1;0.5;1" dur="1s" repeatCount="indefinite" />
            </circle>

            {/* Labels */}
            <text x="50" y="85" fontSize="10" fill="#6B7280" textAnchor="middle">
              Пароль + Соль
            </text>
            <text x="150" y="85" fontSize="10" fill="#6B7280" textAnchor="middle">
              Master Key
            </text>

            {/* Arrow */}
            <path d="M 70 50 L 130 50" stroke="#6B7280" strokeWidth="1" />
          </svg>

          <p className="text-xs text-center text-gray-600 dark:text-gray-400">
            Это медленно для компьютера, но ОЧЕНЬ медленно для взломщика
          </p>
        </div>
      );

    case 'encryption':
      return (
        <div className="w-full space-y-4">
          <svg className="w-full h-32 mx-auto" viewBox="0 0 200 140">
            {/* Master Key */}
            <g>
              <rect x="10" y="10" width="50" height="30" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="4" />
              <text x="35" y="30" fontSize="10" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
                Master Key
              </text>
            </g>

            {/* Arrow */}
            <path d="M 70 25 L 90 25" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

            {/* Chests being encrypted */}
            <g>
              <rect x="100" y="10" width="35" height="35" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="2" />
              <text x="117" y="35" fontSize="9" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
                🔑 Ident.
              </text>
            </g>

            <g>
              <rect x="140" y="10" width="35" height="35" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="2" />
              <text x="157" y="35" fontSize="9" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
                🔗 Handsh.
              </text>
            </g>

            {/* Wrapping effect (animated chain) */}
            <path
              d="M 105 15 Q 110 5 115 10 Q 120 15 115 20 Q 110 25 105 20"
              fill="none"
              stroke="#EAB308"
              strokeWidth="2"
              opacity="0.7"
              style={{
                animation: 'dash 2s linear infinite',
              }}
            />

            {/* Result */}
            <g>
              <rect x="10" y="60" width="170" height="70" fill="#F0FDF4" stroke="#22C55E" strokeWidth="2" rx="4" />
              <text x="20" y="85" fontSize="11" fontWeight="bold" fill="#15803D">
                IndexedDB (Зашифровано):
              </text>

              <rect x="20" y="95" width="80" height="15" fill="white" stroke="#D1D5DB" strokeWidth="1" rx="2" />
              <text x="25" y="106" fontSize="8" fill="#6B7280" fontFamily="monospace">
                identity: 0x4f...
              </text>

              <rect x="100" y="95" width="70" height="15" fill="white" stroke="#D1D5DB" strokeWidth="1" rx="2" />
              <text x="105" y="106" fontSize="8" fill="#6B7280" fontFamily="monospace">
                sessions: 0x9e...
              </text>

              <rect x="20" y="115" width="150" height="15" fill="white" stroke="#D1D5DB" strokeWidth="1" rx="2" />
              <text x="25" y="126" fontSize="8" fill="#6B7280" fontFamily="monospace">
                prekeys: 0x2c...
              </text>
            </g>
          </svg>
        </div>
      );

    case 'storage':
      return (
        <div className="w-full space-y-4">
          <svg className="w-full h-32 mx-auto" viewBox="0 0 200 130">
            {/* Database cylinder */}
            <ellipse cx="100" cy="25" rx="30" ry="10" fill="none" stroke="#6B7280" strokeWidth="2" />
            <rect x="70" y="25" width="60" height="60" fill="none" stroke="#6B7280" strokeWidth="2" />
            <ellipse cx="100" cy="85" rx="30" ry="10" fill="#E5E7EB" stroke="#6B7280" strokeWidth="2" />

            {/* Database label */}
            <text x="100" y="60" fontSize="12" fontWeight="bold" fill="#6B7280" textAnchor="middle">
              IndexedDB
            </text>

            {/* Three tables */}
            <g>
              {/* identity */}
              <rect x="15" y="110" width="50" height="15" fill="#DBEAFE" stroke="#0284C7" strokeWidth="1" rx="2" />
              <text x="40" y="121" fontSize="9" fontWeight="600" fill="#0C4A6E" textAnchor="middle">
                identity
              </text>

              {/* sessions */}
              <rect x="75" y="110" width="50" height="15" fill="#DCFCE7" stroke="#16A34A" strokeWidth="1" rx="2" />
              <text x="100" y="121" fontSize="9" fontWeight="600" fill="#15803D" textAnchor="middle">
                sessions
              </text>

              {/* prekeys */}
              <rect x="135" y="110" width="50" height="15" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="1" rx="2" />
              <text x="160" y="121" fontSize="9" fontWeight="600" fill="#5B21B6" textAnchor="middle">
                prekeys
              </text>
            </g>

            {/* Arrows */}
            <path d="M 100 85 L 40 110" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" opacity="0.5" />
            <path d="M 100 85 L 100 110" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" opacity="0.5" />
            <path d="M 100 85 L 160 110" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" opacity="0.5" />
          </svg>

          <p className="text-xs text-center text-gray-600 dark:text-gray-400">
            Зашифрованные ключи хранятся в браузере. Если ты откроешь другой браузер — их там не будет.
          </p>
        </div>
      );

    case 'final':
      return (
        <div className="w-full space-y-6">
          <div className="text-center">
            <div className="text-6xl mb-4">✅</div>
            <h3 className="text-2xl font-bold text-green-600 mb-2">Безопасность гарантирована</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Только ты можешь прочитать твои ключи
            </p>
          </div>

          <svg className="w-full h-24 mx-auto" viewBox="0 0 200 100">
            {/* Lock */}
            <g>
              <rect x="70" y="40" width="60" height="40" fill="none" stroke="#22C55E" strokeWidth="2" rx="4" />
              <path d="M 80 40 Q 80 30 100 30 Q 120 30 120 40" fill="none" stroke="#22C55E" strokeWidth="2" />
              <circle cx="100" cy="55" r="3" fill="#22C55E" />
            </g>

            {/* Label */}
            <text x="100" y="85" fontSize="10" fontWeight="bold" fill="#16A34A" textAnchor="middle">
              EBCCFE Encrypted Storage
            </text>
          </svg>

          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 text-sm">
            <p className="font-semibold text-green-700 dark:text-green-300 mb-2">Итоговая гарантия:</p>
            <ul className="text-xs text-green-600 dark:text-green-400 space-y-1">
              <li>✓ Даже если Ilyazh взломают, твои ключи остаются в безопасности</li>
              <li>✓ PBKDF2 защищает от атак по словарю</li>
              <li>✓ AES-GCM обеспечивает конфиденциальность и аутентичность</li>
              <li>✓ IndexedDB изолирует ключи от других сайтов</li>
            </ul>
          </div>
        </div>
      );

    default:
      return null;
  }
}

function getStepTitle(step: KeystoreStep): string {
  const titles: Record<KeystoreStep, string> = {
    password: '🔐 Шаг 1: Пароль',
    salt: '🧂 Шаг 2: Генерация Соли',
    pbkdf2: '⚙️ Шаг 3: Key Derivation с PBKDF2',
    encryption: '🔒 Шаг 4: Шифрование Ключей',
    storage: '💾 Шаг 5: Хранение в IndexedDB',
    final: '✅ Итог: Полная Безопасность',
  };
  return titles[step];
}

function getStepDescription(step: KeystoreStep): string {
  const descriptions: Record<KeystoreStep, string> = {
    password:
      'Ты создаешь пароль (например, "!Qwerty123"). Только ты его знаешь. Этот пароль — основа всей безопасности системы.',
    salt: 'Система генерирует случайную "соль" (256 бит). Разные юзеры имеют разные соли, даже если используют одинаковый пароль.',
    pbkdf2:
      'PBKDF2 запускает 600,000 раундов хеширования. Это медленно для компьютера (несколько секунд) и ОЧЕНЬ медленно для взломщика, пытающегося подобрать пароль.',
    encryption:
      'Master Key, полученный из PBKDF2, используется для шифрования всех криптографических ключей (Identity, Handshake, Ratchet) через AES-GCM.',
    storage:
      'Зашифрованные ключи сохраняются в IndexedDB браузера. Если браузер закроется, они останутся. Если ты откроешь другой браузер — их там не будет.',
    final:
      'Итоговая гарантия: даже если Ilyazh серверы взломают, твои ключи остаются защищены, потому что они зашифрованы на ТВОЕМ девайсе с ТВОИМ паролем.',
  };
  return descriptions[step];
}
