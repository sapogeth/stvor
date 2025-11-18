'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Play, RotateCcw, Zap } from 'lucide-react';

interface ChatVisState {
  phase: 'ready' | 'handshake' | 'messaging' | 'rekeying';
  epoch: number;
  messagesThisEpoch: number;
  aliceInput: string;
  aliceMessage: string;
  bobMessage: string;
  showCiphertext: boolean;
  ciphertext: string;
  relayBlind: boolean;
  isAnimating: boolean;
}

export function ChatVisualization() {
  const [state, setState] = useState<ChatVisState>({
    phase: 'ready',
    epoch: 0,
    messagesThisEpoch: 0,
    aliceInput: '',
    aliceMessage: '',
    bobMessage: '',
    showCiphertext: false,
    ciphertext: '',
    relayBlind: false,
    isAnimating: false,
  });

  const startHandshake = async () => {
    setState((prev) => ({
      ...prev,
      isAnimating: true,
      phase: 'handshake',
    }));

    // Simulate handshake
    await new Promise((resolve) => setTimeout(resolve, 2000));

    setState((prev) => ({
      ...prev,
      phase: 'messaging',
      isAnimating: false,
    }));
  };

  const sendMessage = async () => {
    if (!state.aliceInput.trim()) return;

    setState((prev) => ({
      ...prev,
      isAnimating: true,
      showCiphertext: true,
      aliceMessage: prev.aliceInput,
      ciphertext: generateFakeCiphertext(),
      relayBlind: true,
    }));

    // Simulate transmission
    await new Promise((resolve) => setTimeout(resolve, 1500));

    setState((prev) => ({
      ...prev,
      bobMessage: prev.aliceMessage,
      messagesThisEpoch: prev.messagesThisEpoch + 1,
      aliceInput: '',
      isAnimating: false,
    }));
  };

  const simulateMonth = async () => {
    setState((prev) => ({
      ...prev,
      isAnimating: true,
      phase: 'rekeying',
    }));

    // Simulate rapid message counting
    for (let i = 0; i < 20; i++) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      setState((prev) => ({
        ...prev,
        messagesThisEpoch: Math.floor((i + 1) * 52428.8), // 1,048,576 / 20
      }));
    }

    // Handshake for new epoch
    await new Promise((resolve) => setTimeout(resolve, 1500));

    setState((prev) => ({
      ...prev,
      epoch: prev.epoch + 1,
      messagesThisEpoch: 0,
      phase: 'messaging',
      isAnimating: false,
    }));
  };

  const reset = () => {
    setState({
      phase: 'ready',
      epoch: 0,
      messagesThisEpoch: 0,
      aliceInput: '',
      aliceMessage: '',
      bobMessage: '',
      showCiphertext: false,
      ciphertext: '',
      relayBlind: false,
      isAnimating: false,
    });
  };

  const messageLimit = 1048576; // 2^20
  const progressPercent = (state.messagesThisEpoch / messageLimit) * 100;

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Визуализация чата 1-на-1: Как работает безопасность</CardTitle>
      </CardHeader>

      <CardContent className="space-y-8">
        {/* Status bar */}
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-semibold">
              {state.phase === 'ready'
                ? '⏳ Нажми "Начать чат" для инициализации'
                : state.phase === 'handshake'
                  ? '🔄 Выполняется handshake...'
                  : state.phase === 'rekeying'
                    ? '✨ Переключение эпох...'
                    : `✅ Канал защищен (Epoch ${state.epoch})`}
            </h3>
            <span className="text-sm font-mono text-gray-600 dark:text-gray-400">
              {state.messagesThisEpoch.toLocaleString()} / {messageLimit.toLocaleString()} сообщений
            </span>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 overflow-hidden">
            <div
              className="bg-gradient-to-r from-green-500 to-green-600 h-full transition-all duration-300"
              style={{ width: `${Math.min(progressPercent, 100)}%` }}
            />
          </div>
        </div>

        {/* Visualization */}
        <div className="flex items-center justify-between gap-8">
          {/* Alice's phone */}
          <PhoneDisplay
            name="ALICE"
            color="bg-blue-50 border-blue-300"
            input={state.aliceInput}
            onInputChange={(e) => setState((prev) => ({ ...prev, aliceInput: e.target.value }))}
            message={state.aliceMessage}
            isAnimating={state.isAnimating && state.phase === 'handshake'}
            onSend={sendMessage}
            disabled={state.phase !== 'messaging' || state.isAnimating}
          />

          {/* Relay Server */}
          <div className="flex flex-col items-center gap-4">
            <div
              className={`w-20 h-20 rounded-lg flex items-center justify-center text-3xl transition-all ${
                state.relayBlind ? 'bg-yellow-100 scale-110' : 'bg-gray-100'
              }`}
            >
              {state.relayBlind ? '👁️' : '🚀'}
            </div>
            <div className="text-center">
              <p className="text-sm font-semibold">Relay</p>
              <p className="text-xs text-gray-600 dark:text-gray-400">
                {state.relayBlind ? '(не видит)' : '(слепой)'}
              </p>
            </div>
          </div>

          {/* Bob's phone */}
          <PhoneDisplay
            name="BOB"
            color="bg-green-50 border-green-300"
            message={state.bobMessage}
            isAnimating={state.isAnimating && state.phase === 'handshake'}
            disabled={true}
          />
        </div>

        {/* Ciphertext visualization */}
        {state.showCiphertext && (
          <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4 space-y-2">
            <p className="text-sm font-semibold">Plaintext:</p>
            <p className="font-mono text-sm p-2 bg-white dark:bg-gray-800 rounded break-all border">
              "{state.aliceMessage}"
            </p>

            <div className="my-3 text-center">
              <div className="inline-block px-3 py-1 bg-purple-200 dark:bg-purple-800 rounded text-xs font-semibold">
                🔐 AES-GCM Encryption
              </div>
            </div>

            <p className="text-sm font-semibold">Ciphertext (hex):</p>
            <p className="font-mono text-xs p-2 bg-white dark:bg-gray-800 rounded break-all border text-purple-600">
              {state.ciphertext}
            </p>

            <p className="text-xs text-gray-600 dark:text-gray-400 mt-3">
              + AAD (Session ID + Counter + Epoch) + Nonce (R64 || C32)
            </p>
          </div>
        )}

        {/* Handshake explanation */}
        {state.phase === 'handshake' && (
          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 space-y-2">
            <p className="font-semibold text-green-700 dark:text-green-300">🤝 Handshake в процессе:</p>
            <ol className="text-sm text-green-600 dark:text-green-400 space-y-1 ml-4 list-decimal">
              <li>Alice генерирует X25519 + ML-KEM-768 key pair</li>
              <li>Публичные ключи → Relay Server</li>
              <li>Bob генерирует свои ключи</li>
              <li>Bob encapsulate → Relay</li>
              <li>Alice decapsulate → Shared Secret ✅</li>
            </ol>
          </div>
        )}

        {/* Rekeying explanation */}
        {state.phase === 'rekeying' && (
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 space-y-2">
            <p className="font-semibold text-blue-700 dark:text-blue-300">✨ Переключение эпох:</p>
            <p className="text-sm text-blue-600 dark:text-blue-400">
              После 1,048,576 сообщений (или 24 часа) система выполняет новый handshake с НОВЫМИ пост-квантовыми
              ключами. Старые ключи Epoch {state.epoch} удалены и недоступны даже для квантового компьютера.
            </p>
          </div>
        )}

        {/* Controls */}
        <div className="flex flex-wrap gap-3">
          {state.phase === 'ready' && (
            <Button
              onClick={startHandshake}
              disabled={state.isAnimating}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700"
            >
              <Play className="w-4 h-4" />
              Начать чат
            </Button>
          )}

          {state.phase === 'messaging' && (
            <>
              <Button
                onClick={simulateMonth}
                disabled={state.isAnimating}
                className="flex items-center gap-2 bg-orange-600 hover:bg-orange-700"
              >
                <Zap className="w-4 h-4" />
                Симулировать 1 месяц
              </Button>

              <Button
                onClick={reset}
                variant="outline"
                className="flex items-center gap-2"
              >
                <RotateCcw className="w-4 h-4" />
                Сброс
              </Button>
            </>
          )}

          {(state.phase === 'handshake' || state.phase === 'rekeying' || state.showCiphertext) && (
            <Button onClick={reset} variant="outline" className="flex items-center gap-2">
              <RotateCcw className="w-4 h-4" />
              Сброс
            </Button>
          )}
        </div>

        {/* Educational callout */}
        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 text-sm">
          <p className="font-semibold text-amber-700 dark:text-amber-300 mb-2">💡 Ключные моменты:</p>
          <ul className="text-xs text-amber-600 dark:text-amber-400 space-y-1 ml-4 list-disc">
            <li>
              <strong>Hybrid</strong>: X25519 (классический) + ML-KEM (пост-квантовый) ← устойчив к обоим типам
              взломов
            </li>
            <li>
              <strong>Relay Blind</strong>: Сервер не может прочитать сообщения, только маршрутизирует
            </li>
            <li>
              <strong>Forward Secrecy</strong>: Каждое сообщение имеет свой ключ, удаляется после использования
            </li>
            <li>
              <strong>Mandated Rekey</strong>: После 1М сообщений/24ч создаются новые пост-квантовые ключи
            </li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}

interface PhoneDisplayProps {
  name: string;
  color: string;
  input?: string;
  onInputChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  message?: string;
  isAnimating?: boolean;
  onSend?: () => void;
  disabled?: boolean;
}

function PhoneDisplay({
  name,
  color,
  input,
  onInputChange,
  message,
  isAnimating,
  onSend,
  disabled,
}: PhoneDisplayProps) {
  return (
    <div className={`border-4 ${color} rounded-2xl p-4 w-32 h-56 flex flex-col gap-2 transition-all ${
      isAnimating ? 'scale-95 opacity-75' : ''
    }`}>
      {/* Phone header */}
      <div className="text-center text-xs font-bold">{name}</div>

      {/* Screen */}
      <div className="flex-1 bg-white dark:bg-gray-900 rounded border border-gray-300 dark:border-gray-700 p-2 flex flex-col">
        {/* Message display */}
        {message && (
          <div className="text-xs bg-blue-100 dark:bg-blue-900 text-blue-900 dark:text-blue-100 rounded p-2 mb-2 break-words">
            {message}
          </div>
        )}

        {/* Input area */}
        {input !== undefined && (
          <input
            type="text"
            value={input}
            onChange={onInputChange}
            placeholder="Сообщение..."
            disabled={disabled}
            className="text-xs border border-gray-300 dark:border-gray-700 rounded p-1 dark:bg-gray-800"
          />
        )}

        {/* Send button */}
        {onSend && (
          <button
            onClick={onSend}
            disabled={disabled || !input?.trim()}
            className="mt-auto text-xs bg-blue-500 text-white rounded px-2 py-1 disabled:opacity-50"
          >
            Отправить
          </button>
        )}
      </div>

      {/* Phone footer */}
      <div className="text-center text-xs text-gray-600 dark:text-gray-400">📱</div>
    </div>
  );
}

function generateFakeCiphertext(): string {
  let hex = '0x';
  for (let i = 0; i < 64; i++) {
    hex += Math.floor(Math.random() * 16).toString(16);
  }
  return hex;
}
