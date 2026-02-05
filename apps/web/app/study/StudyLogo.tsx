// Этот файл предназначен для использования stvor.jpeg как логотипа в разделе /study.
// Пожалуйста, убедитесь, что изображение stvor.jpeg находится в корне проекта.


import Image from 'next/image';

export default function StudyLogo() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', padding: 24 }}>
      <Image src="/stvor.jpeg" alt="STVOR Logo" width={200} height={200} style={{ borderRadius: 16 }} />
    </div>
  );
}
