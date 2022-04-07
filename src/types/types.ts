import { DidPublicKey, IEncryptedMessage } from '@kiltprotocol/sdk-js'

export type This = typeof globalThis
export interface PubSubSession {
  listen: (
    callback: (message: IEncryptedMessage) => Promise<void>
  ) => Promise<void>
  close: () => Promise<void>
  send: (message: IEncryptedMessage) => Promise<void>
  encryptionKeyId: DidPublicKey['id']
  encryptedChallenge: string
  nonce: string
}

export interface InjectedWindowProvider {
  signWithDid: (
    plaintext: string
  ) => Promise<{ signature: string; didKeyUri: string }>
  startSession: (
    dAppName: string,
    dAppEncryptionKeyId: DidPublicKey['id'],
    challenge: string
  ) => Promise<PubSubSession>
  specVersion: '0.1'
  version: string
}

export interface ApiWindow extends This {
  kilt: Record<string, InjectedWindowProvider>
}
