'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ChevronRight, ChevronLeft, X } from 'lucide-react';

type RatchetStep =
  | 'initial_state'
  | 'message_1'
  | 'ratchet_step'
  | 'message_2'
  | 'out_of_order'
  | 'epoch_refresh'
  | 'final';

interface RatchetExplainerProps {
  onClose: () => void;
}

export function RatchetExplainer({ onClose }: RatchetExplainerProps) {
  const [currentStep, setCurrentStep] = useState<RatchetStep>('initial_state');

  const steps: RatchetStep[] = [
    'initial_state',
    'message_1',
    'ratchet_step',
    'message_2',
    'out_of_order',
    'epoch_refresh',
    'final',
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
      <Card className="w-full max-w-4xl max-h-[90vh] overflow-auto">
        <CardHeader className="flex flex-row items-center justify-between border-b">
          <CardTitle>Почему каждое сообщение — новое начало</CardTitle>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded">
            <X className="w-5 h-5" />
          </button>
        </CardHeader>

        <CardContent className="p-8">
          {/* Progress */}
          <div className="grid grid-cols-7 gap-1 mb-8">
            {steps.map((step, idx) => (
              <div key={step} className="flex flex-col items-center">
                <div
                  className={`w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold transition-all cursor-pointer hover:scale-110 ${
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
          <div className="grid grid-cols-2 gap-8 mb-8">
            {/* Left - Steps list */}
            <div className="space-y-2">
              <h3 className="font-semibold text-sm text-gray-600 dark:text-gray-400">ПРОЦЕСС</h3>
              {[
                { id: 'initial_state', label: '🔑 Исходное состояние' },
                { id: 'message_1', label: '📝 Сообщение #1' },
                { id: 'ratchet_step', label: '🔄 Ratchet шаг' },
                { id: 'message_2', label: '📝 Сообщение #2' },
                { id: 'out_of_order', label: '🔀 Out-of-Order' },
                { id: 'epoch_refresh', label: '🔐 Переключение эпох' },
                { id: 'final', label: '✅ Forward Secrecy' },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setCurrentStep(item.id as RatchetStep)}
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
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 min-h-96 flex flex-col items-center justify-center">
              <RatchetVisualization step={currentStep} />
            </div>
          </div>

          {/* Description */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-8">
            <h4 className="font-semibold mb-2">{getRatchetStepTitle(currentStep)}</h4>
            <p className="text-sm text-gray-700 dark:text-gray-300">{getRatchetStepDescription(currentStep)}</p>
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

interface RatchetVisualizationProps {
  step: RatchetStep;
}

function RatchetVisualization({ step }: RatchetVisualizationProps) {
  switch (step) {
    case 'initial_state':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 300 200">
          {/* Alice */}
          <g>
            <rect x="20" y="20" width="60" height="60" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="4" />
            <text x="50" y="55" fontSize="12" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              ALICE
            </text>
          </g>

          {/* Bob */}
          <g>
            <rect x="220" y="20" width="60" height="60" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
            <text x="250" y="55" fontSize="12" fontWeight="bold" fill="#15803D" textAnchor="middle">
              BOB
            </text>
          </g>

          {/* Keys */}
          <g>
            {/* Root Key */}
            <rect x="100" y="30" width="100" height="20" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="3" />
            <text x="150" y="45" fontSize="10" fontWeight="bold" fill="#92400E" textAnchor="middle">
              Root Key
            </text>

            {/* Chain Keys */}
            <rect x="100" y="60" width="45" height="20" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="3" />
            <text x="122" y="75" fontSize="9" fontWeight="bold" fill="#3730A3" textAnchor="middle">
              ChainKey
            </text>

            <rect x="155" y="60" width="45" height="20" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="3" />
            <text x="177" y="75" fontSize="9" fontWeight="bold" fill="#3730A3" textAnchor="middle">
              ChainKey
            </text>

            {/* Message Keys */}
            <rect x="100" y="90" width="45" height="20" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="3" />
            <text x="122" y="105" fontSize="9" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
              MsgKey[0]
            </text>

            <rect x="155" y="90" width="45" height="20" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="3" />
            <text x="177" y="105" fontSize="9" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
              MsgKey[0]
            </text>
          </g>

          {/* Arrows showing derivation */}
          <path d="M 150 50 L 122 60" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" opacity="0.5" />
          <path d="M 150 50 L 177 60" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" opacity="0.5" />
          <path d="M 122 60 L 122 90" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" opacity="0.5" />
          <path d="M 177 60 L 177 90" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" opacity="0.5" />

          {/* Legend */}
          <text x="150" y="150" fontSize="11" textAnchor="middle" fill="#6B7280" fontWeight="bold">
            После handshake оба знают Root Key
          </text>
          <text x="150" y="170" fontSize="10" textAnchor="middle" fill="#6B7280">
            Из него выводятся все остальные ключи
          </text>
        </svg>
      );

    case 'message_1':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 300 220">
          {/* Timeline */}
          <g>
            <rect x="20" y="20" width="80" height="40" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="4" />
            <text x="60" y="50" fontSize="11" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              ALICE
            </text>

            <rect x="200" y="20" width="80" height="40" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
            <text x="240" y="50" fontSize="11" fontWeight="bold" fill="#15803D" textAnchor="middle">
              BOB
            </text>

            {/* Message Key derivation */}
            <rect x="60" y="80" width="40" height="25" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="3" />
            <text x="80" y="98" fontSize="9" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
              MsgKey[1]
            </text>
            <text x="80" y="115" fontSize="8" fill="#6B7280" textAnchor="middle">
              (из ChainKey)
            </text>

            {/* Arrow down */}
            <path d="M 80 50 L 80 80" stroke="#6B7280" strokeWidth="1" markerEnd="url(#arrowhead)" />

            {/* Encryption box */}
            <rect x="30" y="125" width="100" height="50" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="4" />
            <text x="80" y="145" fontSize="10" fontWeight="bold" fill="#92400E" textAnchor="middle">
              Шифрование AES-GCM
            </text>
            <text x="80" y="162" fontSize="8" fill="#92400E" textAnchor="middle" fontFamily="monospace">
              Ciphertext: 0x42a...
            </text>

            {/* Flying message */}
            <g opacity="0.7">
              <path
                d="M 130 150 Q 150 100 190 80"
                stroke="#0284C7"
                strokeWidth="2"
                fill="none"
                markerEnd="url(#arrowhead-blue)"
              />
              <rect x="140" y="115" width="20" height="20" fill="#3B82F6" rx="2" />
            </g>

            {/* Message deletion */}
            <g>
              <text x="80" y="190" fontSize="9" fill="#EF4444" fontWeight="bold" textAnchor="middle">
                ✕ Ключ удален
              </text>
              <text x="80" y="205" fontSize="8" fill="#6B7280" textAnchor="middle">
                (не хранится!)
              </text>
            </g>
          </g>

          {/* Decorative elements */}
          <defs>
            <marker id="arrowhead-blue" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
              <polygon points="0 0, 10 3, 0 6" fill="#3B82F6" />
            </marker>
          </defs>
        </svg>
      );

    case 'ratchet_step':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 300 220">
          {/* Before */}
          <g>
            <text x="60" y="20" fontSize="10" fontWeight="bold" fill="#6B7280">
              До:
            </text>
            <rect x="30" y="30" width="60" height="30" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="3" />
            <text x="60" y="50" fontSize="9" fontWeight="bold" fill="#3730A3" textAnchor="middle">
              ChainKey[0]
            </text>
          </g>

          {/* Ratchet operation */}
          <g>
            <circle cx="150" cy="45" r="15" fill="none" stroke="#D97706" strokeWidth="2" />
            <text x="150" y="50" fontSize="14" fontWeight="bold" fill="#D97706" textAnchor="middle">
              🔄
            </text>
            <text x="150" y="70" fontSize="8" fill="#6B7280" textAnchor="middle">
              HMAC-SHA256
            </text>
          </g>

          {/* After */}
          <g>
            <text x="210" y="20" fontSize="10" fontWeight="bold" fill="#6B7280">
              После:
            </text>
            <rect x="180" y="30" width="60" height="30" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="3" />
            <text x="210" y="50" fontSize="9" fontWeight="bold" fill="#15803D" textAnchor="middle">
              ChainKey[1]
            </text>
          </g>

          {/* Arrow */}
          <path d="M 95 45 L 135 45" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />
          <path d="M 165 45 L 180 45" stroke="#6B7280" strokeWidth="2" markerEnd="url(#arrowhead)" />

          {/* Chain visualization */}
          <g>
            <text x="150" y="120" fontSize="11" fontWeight="bold" fill="#6B7280" textAnchor="middle">
              История цепи:
            </text>

            {/* Chain links */}
            <rect x="40" y="135" width="35" height="25" fill="#D1D5DB" stroke="#6B7280" strokeWidth="1" rx="2" />
            <text x="57" y="153" fontSize="8" fill="#4B5563" textAnchor="middle" fontFamily="monospace">
              Key[0]
            </text>

            <circle cx="80" cy="148" r="4" fill="#6B7280" />

            <rect x="90" y="135" width="35" height="25" fill="#10B981" stroke="#059669" strokeWidth="2" rx="2" />
            <text x="107" y="153" fontSize="8" fill="white" textAnchor="middle" fontFamily="monospace">
              Key[1]
            </text>

            <circle cx="130" cy="148" r="4" fill="#6B7280" />

            <rect x="140" y="135" width="35" height="25" fill="#E5E7EB" stroke="#9CA3AF" strokeWidth="1" rx="2" />
            <text x="157" y="153" fontSize="8" fill="#4B5563" textAnchor="middle" fontFamily="monospace">
              Key[2]
            </text>

            <circle cx="180" cy="148" r="4" fill="#6B7280" />

            <text x="195" y="153" fontSize="14" fill="#6B7280">
              ...
            </text>
          </g>

          {/* Legend */}
          <g>
            <text x="150" y="190" fontSize="9" fill="#6B7280" fontWeight="bold" textAnchor="middle">
              Каждое сообщение использует обновленный ключ
            </text>
            <text x="150" y="205" fontSize="8" fill="#6B7280" textAnchor="middle">
              Старые ключи выделены серым (больше не используются)
            </text>
          </g>
        </svg>
      );

    case 'message_2':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 300 220">
          {/* Alice */}
          <g>
            <rect x="20" y="20" width="80" height="40" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="4" />
            <text x="60" y="50" fontSize="11" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              ALICE
            </text>

            {/* Alice's message 2 */}
            <rect x="30" y="80" width="60" height="30" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="4" />
            <text x="60" y="100" fontSize="9" fontWeight="bold" fill="#92400E" textAnchor="middle">
              Msg #2
            </text>
          </g>

          {/* Bob */}
          <g>
            <rect x="200" y="20" width="80" height="40" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
            <text x="240" y="50" fontSize="11" fontWeight="bold" fill="#15803D" textAnchor="middle">
              BOB
            </text>

            {/* Bob's decryption */}
            <rect x="190" y="80" width="100" height="30" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="4" />
            <text x="240" y="100" fontSize="9" fontWeight="bold" fill="#3730A3" textAnchor="middle">
              Расшифровка ✓
            </text>
          </g>

          {/* Sync status */}
          <g>
            <text x="150" y="140" fontSize="10" fontWeight="bold" fill="#10B981" textAnchor="middle">
              ✅ Ключи синхронизированы
            </text>
          </g>

          {/* Keys state */}
          <g>
            <text x="60" y="170" fontSize="9" fill="#6B7280" textAnchor="middle" fontWeight="bold">
              ChainKey[2]
            </text>
            <text x="240" y="170" fontSize="9" fill="#6B7280" textAnchor="middle" fontWeight="bold">
              ChainKey[2]
            </text>

            <path d="M 60 175 L 240 175" stroke="#10B981" strokeWidth="2" markerEnd="url(#arrowhead-green)" />
          </g>

          {/* Message counter */}
          <g>
            <text x="150" y="200" fontSize="10" fill="#6B7280" textAnchor="middle">
              Сообщений: 2/1,048,576
            </text>
            <rect x="100" y="205" width="100" height="4" fill="#E5E7EB" rx="2" />
            <rect x="100" y="205" width="0.2" height="4" fill="#10B981" rx="2" />
          </g>
        </svg>
      );

    case 'out_of_order':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 300 220">
          {/* Alice */}
          <g>
            <rect x="20" y="20" width="80" height="40" fill="#DBEAFE" stroke="#0284C7" strokeWidth="2" rx="4" />
            <text x="60" y="50" fontSize="11" fontWeight="bold" fill="#0C4A6E" textAnchor="middle">
              ALICE
            </text>
          </g>

          {/* Bob */}
          <g>
            <rect x="200" y="20" width="80" height="40" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
            <text x="240" y="50" fontSize="11" fontWeight="bold" fill="#15803D" textAnchor="middle">
              BOB
            </text>
          </g>

          {/* Out of order - message #4 arrives first */}
          <g>
            {/* Message 4 flies */}
            <g opacity="0.7">
              <path
                d="M 100 70 Q 150 40 200 70"
                stroke="#EF4444"
                strokeWidth="2"
                fill="none"
                markerEnd="url(#arrowhead-red)"
              />
              <rect x="140" y="50" width="20" height="20" fill="#EF4444" rx="2" />
              <text x="150" y="62" fontSize="9" fontWeight="bold" fill="white" textAnchor="middle">
                4
              </text>
            </g>

            {/* Bob's state */}
            <rect x="190" y="90" width="100" height="35" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="4" />
            <text x="240" y="105" fontSize="9" fontWeight="bold" fill="#92400E" textAnchor="middle">
              ⏳ Ожидание #2
            </text>
            <text x="240" y="120" fontSize="8" fill="#92400E" textAnchor="middle">
              (кэш #4)
            </text>
          </g>

          {/* Later - message #2 arrives */}
          <g>
            {/* Message 2 flies */}
            <g opacity="0.7" style={{ animation: 'fadeInUp 1s ease-out forwards' }}>
              <path
                d="M 100 140 Q 150 110 200 140"
                stroke="#10B981"
                strokeWidth="2"
                fill="none"
                markerEnd="url(#arrowhead-green)"
              />
              <rect x="140" y="120" width="20" height="20" fill="#10B981" rx="2" />
              <text x="150" y="132" fontSize="9" fontWeight="bold" fill="white" textAnchor="middle">
                2
              </text>
            </g>

            {/* Decryption status */}
            <rect x="190" y="160" width="100" height="35" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
            <text x="240" y="175" fontSize="9" fontWeight="bold" fill="#15803D" textAnchor="middle">
              ✅ Обе расшифрованы
            </text>
            <text x="240" y="190" fontSize="8" fill="#15803D" textAnchor="middle">
              (#2 и #4)
            </text>
          </g>

          {/* Legend */}
          <g>
            <defs>
              <marker id="arrowhead-red" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
                <polygon points="0 0, 10 3, 0 6" fill="#EF4444" />
              </marker>
              <marker id="arrowhead-green" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
                <polygon points="0 0, 10 3, 0 6" fill="#10B981" />
              </marker>
            </defs>
          </g>
        </svg>
      );

    case 'epoch_refresh':
      return (
        <svg className="w-full h-264 mx-auto" viewBox="0 0 300 220">
          {/* Timeline */}
          <g>
            <line x1="30" y1="50" x2="270" y2="50" stroke="#6B7280" strokeWidth="2" />

            {/* Epoch 0 */}
            <rect x="30" y="30" width="80" height="40" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="4" />
            <text x="70" y="50" fontSize="10" fontWeight="bold" fill="#3730A3" textAnchor="middle">
              Epoch 0
            </text>
            <text x="70" y="65" fontSize="8" fill="#6B7280" textAnchor="middle">
              1,048,576 msg
            </text>

            {/* Arrow and rekey */}
            <path d="M 115 50 L 130 50" stroke="#D97706" strokeWidth="3" markerEnd="url(#arrowhead)" />
            <circle cx="122" cy="50" r="8" fill="#D97706" />
            <text x="122" y="54" fontSize="10" fontWeight="bold" fill="white" textAnchor="middle">
              🔑
            </text>

            {/* Epoch 1 */}
            <rect x="140" y="30" width="80" height="40" fill="#DCFCE7" stroke="#16A34A" strokeWidth="2" rx="4" />
            <text x="180" y="50" fontSize="10" fontWeight="bold" fill="#15803D" textAnchor="middle">
              Epoch 1
            </text>
            <text x="180" y="65" fontSize="8" fill="#6B7280" textAnchor="middle">
              1,048,576 msg
            </text>

            {/* Arrow and rekey */}
            <path d="M 225 50 L 240 50" stroke="#D97706" strokeWidth="3" markerEnd="url(#arrowhead)" />
            <circle cx="232" cy="50" r="8" fill="#D97706" />
            <text x="232" y="54" fontSize="10" fontWeight="bold" fill="white" textAnchor="middle">
              🔑
            </text>

            {/* Epoch 2 */}
            <rect x="250" y="30" width="40" height="40" fill="#E5E7EB" stroke="#6B7280" strokeWidth="2" rx="4" />
            <text x="270" y="50" fontSize="9" fontWeight="bold" fill="#4B5563" textAnchor="middle">
              Ep 2
            </text>
            <text x="270" y="65" fontSize="8" fill="#6B7280" textAnchor="middle">
              ...
            </text>
          </g>

          {/* Post-quantum key refresh */}
          <g>
            <text x="150" y="100" fontSize="11" fontWeight="bold" fill="#D97706" textAnchor="middle">
              При переключении эпох:
            </text>

            <g>
              <rect x="20" y="110" width="130" height="50" fill="#FEF3C7" stroke="#D97706" strokeWidth="2" rx="4" />
              <text x="85" y="130" fontSize="10" fontWeight="bold" fill="#92400E" textAnchor="middle">
                ✓ Root Key обновлен
              </text>
              <text x="85" y="148" fontSize="9" fill="#92400E" textAnchor="middle">
                ✓ ML-KEM ключи переделаны
              </text>
              <text x="85" y="160" fontSize="9" fill="#92400E" textAnchor="middle">
                ✓ Старые ключи удалены
              </text>
            </g>

            {/* Attack visualization */}
            <g>
              <rect x="160" y="110" width="130" height="50" fill="#F3E8FF" stroke="#7C3AED" strokeWidth="2" rx="4" />
              <text x="225" y="130" fontSize="10" fontWeight="bold" fill="#5B21B6" textAnchor="middle">
                Даже КВК не поможет:
              </text>
              <text x="225" y="148" fontSize="9" fill="#5B21B6" textAnchor="middle">
                🔓 Взломан Epoch 0
              </text>
              <text x="225" y="160" fontSize="9" fill="#5B21B6" textAnchor="middle">
                🔒 Epoch 1 в безопасности
              </text>
            </g>
          </g>

          {/* Trigger reasons */}
          <g>
            <text x="150" y="190" fontSize="10" fontWeight="bold" fill="#6B7280" textAnchor="middle">
              Переключение по причине:
            </text>
            <text x="150" y="210" fontSize="9" fill="#6B7280" textAnchor="middle">
              • 1,048,576 сообщений за эпоху ИЛИ • 24 часа истекло
            </text>
          </g>
        </svg>
      );

    case 'final':
      return (
        <svg className="w-full h-64 mx-auto" viewBox="0 0 300 220">
          {/* Timeline with attack */}
          <g>
            <line x1="30" y1="50" x2="270" y2="50" stroke="#6B7280" strokeWidth="2" />

            {/* Epochs */}
            <rect x="30" y="35" width="50" height="30" fill="#10B981" stroke="#059669" strokeWidth="2" rx="3" />
            <text x="55" y="55" fontSize="9" fontWeight="bold" fill="white" textAnchor="middle">
              Epoch 0
            </text>

            <rect x="90" y="35" width="50" height="30" fill="#10B981" stroke="#059669" strokeWidth="2" rx="3" />
            <text x="115" y="55" fontSize="9" fontWeight="bold" fill="white" textAnchor="middle">
              Epoch 1
            </text>

            <rect x="150" y="35" width="50" height="30" fill="#10B981" stroke="#059669" strokeWidth="2" rx="3" />
            <text x="175" y="55" fontSize="9" fontWeight="bold" fill="white" textAnchor="middle">
              Epoch 2
            </text>

            <rect x="210" y="35" width="50" height="30" fill="#10B981" stroke="#059669" strokeWidth="2" rx="3" />
            <text x="235" y="55" fontSize="9" fontWeight="bold" fill="white" textAnchor="middle">
              Epoch 3
            </text>
          </g>

          {/* Attack visualization */}
          <g>
            {/* Attack breaks Epoch 0 */}
            <path d="M 30 80 L 80 110" stroke="#EF4444" strokeWidth="3" markerEnd="url(#arrowhead-red)" />
            <circle cx="40" cy="90" r="8" fill="#EF4444" />
            <text x="40" y="94" fontSize="10" fontWeight="bold" fill="white" textAnchor="middle">
              💣
            </text>

            {/* Epoch 0 broken */}
            <rect x="30" y="115" width="50" height="25" fill="#FFECEC" stroke="#EF4444" strokeWidth="2" rx="3" />
            <text x="55" y="133" fontSize="8" fill="#991B1B" textAnchor="middle" fontWeight="bold">
              ✕ Взломан
            </text>

            {/* But others are safe */}
            <g opacity="0.8">
              <path d="M 85 115 L 160 110" stroke="#10B981" strokeWidth="2" markerEnd="url(#arrowhead-green)" />
              <text x="125" y="108" fontSize="9" fill="#10B981" fontWeight="bold">
                Forward Secrecy
              </text>
            </g>

            {/* Safe epochs */}
            <rect x="90" y="115" width="50" height="25" fill="#ECFDF5" stroke="#10B981" strokeWidth="2" rx="3" />
            <text x="115" y="133" fontSize="8" fill="#065F46" textAnchor="middle" fontWeight="bold">
              ✓ Защищены
            </text>

            <rect x="150" y="115" width="50" height="25" fill="#ECFDF5" stroke="#10B981" strokeWidth="2" rx="3" />
            <text x="175" y="133" fontSize="8" fill="#065F46" textAnchor="middle" fontWeight="bold">
              ✓ Защищены
            </text>

            <rect x="210" y="115" width="50" height="25" fill="#ECFDF5" stroke="#10B981" strokeWidth="2" rx="3" />
            <text x="235" y="133" fontSize="8" fill="#065F46" textAnchor="middle" fontWeight="bold">
              ✓ Защищены
            </text>
          </g>

          {/* Summary */}
          <g>
            <rect x="30" y="165" width="240" height="45" fill="#E0E7FF" stroke="#4F46E5" strokeWidth="2" rx="4" />
            <text x="150" y="185" fontSize="11" fontWeight="bold" fill="#3730A3" textAnchor="middle">
              Forward Secrecy гарантирует:
            </text>
            <text x="150" y="205" fontSize="9" fill="#3730A3" textAnchor="middle">
              Даже если КВК взломает Key[N], он не сможет прочитать Key[N+1]
            </text>
          </g>

          <defs>
            <marker id="arrowhead-red" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
              <polygon points="0 0, 10 3, 0 6" fill="#EF4444" />
            </marker>
            <marker id="arrowhead-green" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
              <polygon points="0 0, 10 3, 0 6" fill="#10B981" />
            </marker>
          </defs>
        </svg>
      );

    default:
      return null;
  }
}

function getRatchetStepTitle(step: RatchetStep): string {
  const titles: Record<RatchetStep, string> = {
    initial_state: '🔑 Исходное состояние',
    message_1: '📝 Отправка сообщения #1',
    ratchet_step: '🔄 Ratchet шаг — обновление Chain Key',
    message_2: '📝 Отправка сообщения #2',
    out_of_order: '🔀 Обработка Out-of-Order сообщений',
    epoch_refresh: '🔐 Мандатное переключение эпох',
    final: '✅ Forward Secrecy гарантирована',
  };
  return titles[step];
}

function getRatchetStepDescription(step: RatchetStep): string {
  const descriptions: Record<RatchetStep, string> = {
    initial_state:
      'После handshake у Алисы и Боба есть общий Root Key. Из него выводятся все остальные ключи: Chain Keys и Message Keys.',
    message_1:
      'Алиса вводит сообщение. Для каждого сообщения выводится новый Message Key из Chain Key. После использования он стирается навсегда.',
    ratchet_step:
      'После отправки сообщения Chain Key обновляется через HMAC: ChainKey[N+1] = HMAC(ChainKey[N], 0x01). Старый ключ больше не используется.',
    message_2:
      'Боб тоже обновляет свой Chain Key. Оба остаются синхронизированы. Это гарантирует, что они оба вычисляют одинаковые ключи.',
    out_of_order:
      'Если сообщение приходит не по порядку, Боб может хранить пропущенные ключи в кэше. Это обеспечивает надежность доставки в ненадежных сетях.',
    epoch_refresh:
      'После 1 млн сообщений или 24 часов система создает новые пост-квантовые ключи (ML-KEM). Все старые ключи удаляются. Даже КВК не поможет взломать Epoch 0.',
    final:
      'Forward Secrecy гарантирует: даже если квантовый компьютер взломает Key[N], он не сможет прочитать Key[N+1]. Каждый месяц переписки имеет свой "заряд защиты".',
  };
  return descriptions[step];
}
