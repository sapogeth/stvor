'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  Lock,
  Link as ChainLink,
  Vault,
  Signature,
  Server,
  Users,
  X,
} from 'lucide-react';

export interface SecurityComponent {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  details: string;
}

export const SECURITY_COMPONENTS: SecurityComponent[] = [
  {
    id: 'handshake',
    title: 'Гибридный Handshake',
    description: 'X25519 + ML-KEM-768 — лучшее из классического и пост-квантового',
    icon: <Lock className="w-8 h-8" />,
    color: 'text-blue-600',
    bgColor: 'bg-blue-50 dark:bg-blue-900/20',
    details:
      'Когда вы начинаете чат, система создает два замка на одной двери. Один — классический (X25519), второй — пост-квантовый (ML-KEM). Взломать оба одновременно невозможно.',
  },
  {
    id: 'ratchet',
    title: 'Пост-квантовый Ratchet',
    description: 'Каждое сообщение — новые ключи. Forward secrecy на стероидах',
    icon: <ChainLink className="w-8 h-8" />,
    color: 'text-green-600',
    bgColor: 'bg-green-50 dark:bg-green-900/20',
    details:
      'Каждое сообщение — это новое звено в цепи. Даже если кто-то украдет одно звено, остальная цепь остается целой.',
  },
  {
    id: 'keystore',
    title: 'Secure Keystore',
    description: 'Твои ключи зашифрованы локально. Даже мы их не видим',
    icon: <Vault className="w-8 h-8" />,
    color: 'text-purple-600',
    bgColor: 'bg-purple-50 dark:bg-purple-900/20',
    details:
      'Все твои криптографические ключи зашифрованы на твоем устройстве PBKDF2 + AES-GCM. Даже если Ilyazh серверы взломают, они не смогут расшифровать твои ключи.',
  },
  {
    id: 'signatures',
    title: 'Двойные Подписи',
    description: 'Каждое сообщение подписано дважды — невозможно подделать',
    icon: <Signature className="w-8 h-8" />,
    color: 'text-orange-600',
    bgColor: 'bg-orange-50 dark:bg-orange-900/20',
    details:
      'Каждое сообщение подписано классической (Ed25519) и пост-квантовой (ML-DSA) подписью. Это гарантирует аутентичность и невозможность отрицания.',
  },
  {
    id: 'relay',
    title: 'Relay Server',
    description: 'Сервер маршрутизирует, но не видит содержимое',
    icon: <Server className="w-8 h-8" />,
    color: 'text-gray-600',
    bgColor: 'bg-gray-50 dark:bg-gray-900/20',
    details:
      'Relay — это слепой курьер. Он доставляет зашифрованные письма, но не может открыть их и прочитать, что внутри.',
  },
  {
    id: 'group-chat',
    title: 'Групповые Чаты',
    description: 'Детерминистические ключи — масштабируемость без компромиссов',
    icon: <Users className="w-8 h-8" />,
    color: 'text-indigo-600',
    bgColor: 'bg-indigo-50 dark:bg-indigo-900/20',
    details:
      'В групповых чатах все участники имеют доступ к одним и тем же ключам, вычисленным детерминистически. Это обеспечивает масштабируемость без потери безопасности.',
  },
];

interface SecurityHubProps {
  onSelectComponent: (componentId: string) => void;
}

export function SecurityHub({ onSelectComponent }: SecurityHubProps) {
  return (
    <div className="space-y-8">
      {/* Intro section */}
      <div className="space-y-2">
        <h1 className="text-4xl font-bold">🔒 Центр Безопасности</h1>
        <p className="text-lg text-gray-600 dark:text-gray-400">
          Давайте разберемся, как работает криптография в Ilyazh. Нажми на любой компонент,
          чтобы увидеть пошаговую визуализацию.
        </p>
      </div>

      {/* Security components grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {SECURITY_COMPONENTS.map((component) => (
          <SecurityComponentCard
            key={component.id}
            component={component}
            onSelect={() => onSelectComponent(component.id)}
          />
        ))}
      </div>
    </div>
  );
}

interface SecurityComponentCardProps {
  component: SecurityComponent;
  onSelect: () => void;
}

function SecurityComponentCard({ component, onSelect }: SecurityComponentCardProps) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <button
      onClick={onSelect}
      className="text-left transition-all duration-300 ease-out"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <Card
        className={`h-full cursor-pointer border-2 border-transparent transition-all duration-300 ${
          isHovered ? 'shadow-lg scale-105' : 'shadow-md'
        } ${component.bgColor}`}
      >
        <CardHeader>
          <div className={`w-12 h-12 rounded-lg ${component.bgColor} flex items-center justify-center mb-4`}>
            <span className={component.color}>{component.icon}</span>
          </div>
          <CardTitle className="text-xl">{component.title}</CardTitle>
          <CardDescription className="text-sm">{component.description}</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-2">{component.details}</p>
        </CardContent>
      </Card>
    </button>
  );
}
