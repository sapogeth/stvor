/**
 * Оптимизированные конфигурации для Argon2id KDF
 *
 * SECURITY vs PERFORMANCE:
 *
 * SENSITIVE (текущий режим):
 *   - memoryLimit: 268,435,456 bytes (256 MB)
 *   - opsLimit: 4
 *   - Время: 2-5 секунд на среднем ноутбуке
 *   - Защита: максимальная против GPU-атак
 *   - Проблема: ОЧЕНЬ медленно на браузере
 *
 * MODERATE (рекомендуется):
 *   - memoryLimit: 67,108,864 bytes (64 MB)
 *   - opsLimit: 2
 *   - Время: 500ms - 1.5 секунды на среднем ноутбуке
 *   - Защита: хорошая против GPU-атак
 *   - Баланс: приемлемо для пользователя
 *
 * INTERACTIVE (быстро):
 *   - memoryLimit: 16,777,216 bytes (16 MB)
 *   - opsLimit: 1
 *   - Время: 100-300ms
 *   - Защита: базовая, НЕ рекомендуется для production
 *   - Проблема: уязвим для brute-force атак
 *
 * РЕКОМЕНДАЦИЯ:
 * - Использовать MODERATE как баланс
 * - Для максимальной безопасности и если приемлема задержка: SENSITIVE
 * - Для быстрой демонстрации: INTERACTIVE (НЕ production)
 *
 * References:
 * - Argon2 paper: https://github.com/P-H-C/phc-winner-argon2
 * - libsodium docs: https://doc.libsodium.org/password_hashing/the_argon2i_function
 */

export enum Argon2Mode {
  SENSITIVE = 'sensitive',
  MODERATE = 'moderate',
  INTERACTIVE = 'interactive',
}

export interface Argon2Config {
  memoryLimit: number; // bytes
  opsLimit: number;
  mode: Argon2Mode;
}

/**
 * SENSITIVE - максимальная защита
 * Рекомендуется когда задержка 2-5 секунд приемлема
 * (например, при первой регистрации или восстановлении аккаунта)
 */
export const ARGON2_SENSITIVE: Argon2Config = {
  memoryLimit: 268_435_456, // 256 MB
  opsLimit: 4,
  mode: Argon2Mode.SENSITIVE,
};

/**
 * MODERATE - баланс между безопасностью и UX
 * Рекомендуется для обычного login/init
 * Защита от GPU-атак остается хорошей
 * Время: ~1 секунда
 */
export const ARGON2_MODERATE: Argon2Config = {
  memoryLimit: 67_108_864, // 64 MB
  opsLimit: 2,
  mode: Argon2Mode.MODERATE,
};

/**
 * INTERACTIVE - быстро
 * НЕ рекомендуется для production
 * Используется только для демонстрации или разработки
 * Время: ~300ms
 */
export const ARGON2_INTERACTIVE: Argon2Config = {
  memoryLimit: 16_777_216, // 16 MB
  opsLimit: 1,
  mode: Argon2Mode.INTERACTIVE,
};

/**
 * Получает конфигурацию по названию режима
 */
export function getArgon2Config(mode: Argon2Mode): Argon2Config {
  switch (mode) {
    case Argon2Mode.SENSITIVE:
      return ARGON2_SENSITIVE;
    case Argon2Mode.MODERATE:
      return ARGON2_MODERATE;
    case Argon2Mode.INTERACTIVE:
      return ARGON2_INTERACTIVE;
    default:
      return ARGON2_MODERATE; // Безопасное значение по умолчанию
  }
}

/**
 * Возвращает режим Argon2 в зависимости от контекста
 *
 * CONTEXT:
 * - 'registration': первая регистрация (можно медленнее)
 * - 'login': обычный login (баланс)
 * - 'init': инициализация PQ (быстро)
 * - 'device-recovery': восстановление устройства (медленно, если нужно)
 */
export function getArgon2ModeForContext(
  context:
    | 'registration'
    | 'login'
    | 'init'
    | 'device-recovery'
    | 'interactive'
): Argon2Mode {
  switch (context) {
    case 'registration':
      // При регистрации можно потратить время на защиту
      return Argon2Mode.MODERATE;

    case 'login':
      // При login баланс между UX и безопасностью
      return Argon2Mode.MODERATE;

    case 'init':
      // При инициализации PQ нужна скорость
      // (крипто уже защищен другими механизмами)
      return Argon2Mode.INTERACTIVE;

    case 'device-recovery':
      // При восстановлении можно потратить время
      return Argon2Mode.SENSITIVE;

    case 'interactive':
      // Для интерактивных операций (смена пароля)
      return Argon2Mode.MODERATE;

    default:
      return Argon2Mode.MODERATE;
  }
}

/**
 * Оценивает предположительное время выполнения Argon2 на текущем устройстве
 * (грубая оценка, варьируется в зависимости от CPU/RAM)
 */
export function estimateArgon2Duration(config: Argon2Config): string {
  switch (config.mode) {
    case Argon2Mode.SENSITIVE:
      return '2-5 seconds';
    case Argon2Mode.MODERATE:
      return '500ms - 1.5s';
    case Argon2Mode.INTERACTIVE:
      return '100-300ms';
    default:
      return 'unknown';
  }
}
