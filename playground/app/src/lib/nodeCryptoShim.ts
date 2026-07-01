import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'

type HashEncoding = 'base64' | 'hex'
type HashInput = ArrayBuffer | ArrayBufferView | string

interface BrowserHash {
  update(data: HashInput): BrowserHash
  digest(encoding?: HashEncoding): string
}

function toBytes(data: HashInput): Uint8Array {
  if (typeof data === 'string') {
    return new TextEncoder().encode(data)
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data)
  }
  return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
  const output = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    output.set(chunk, offset)
    offset += chunk.byteLength
  }
  return output
}

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

export function createHash(algorithm: string): BrowserHash {
  if (algorithm !== 'sha256') {
    throw new Error(`unsupported hash algorithm: ${algorithm}`)
  }
  const chunks: Uint8Array[] = []
  return {
    update(data: HashInput) {
      chunks.push(toBytes(data))
      return this
    },
    digest(encoding: HashEncoding = 'hex') {
      const digest = sha256(concat(chunks))
      if (encoding === 'hex') {
        return bytesToHex(digest)
      }
      if (encoding === 'base64') {
        return toBase64(digest)
      }
      throw new Error(`unsupported hash encoding: ${encoding}`)
    },
  }
}
