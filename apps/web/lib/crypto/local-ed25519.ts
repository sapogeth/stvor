import { sign } from '@noble/ed25519';

export async function ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  // secretKey may be 64 bytes (secret + public) in libsodium format.
  // Noble expects a 32-byte private key (seed). Use the first 32 bytes.
  const sk = secretKey.length >= 32 ? secretKey.slice(0, 32) : secretKey;
  const sig = await sign(message, sk);
  return sig;
}
