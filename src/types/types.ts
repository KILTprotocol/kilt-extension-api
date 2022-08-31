import {
  DidPublicKey,
  IEncryptedMessage,
  IIdentity,
  IRequestForAttestation,
} from '@kiltprotocol/sdk-js'
import { HexString } from '@polkadot/util/types'

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
  startSession: (
    dAppName: string,
    dAppEncryptionKeyId: DidPublicKey['id'],
    challenge: string
  ) => Promise<PubSubSession>
  name: string
  version: string
  specVersion: '1.0'
  signWithDid: (
    plaintext: string
  ) => Promise<{ signature: string; didKeyUri: DidPublicKey['id'] }>
  signExtrinsicWithDid: (
    extrinsic: HexString,
    signer: IIdentity['address']
  ) => Promise<{ signed: HexString; didKeyUri: DidPublicKey['id'] }>
}

export interface ApiWindow extends This {
  kilt: Record<string, InjectedWindowProvider>
}

// Shouldbe updated to DiDURI after
export interface CredentialSubject {
  id: string
  origin: string
  rootHash: string
}

export interface Proof {
  type: string
  created?: string
  proofPurpose?: string

  [key: string]: unknown
}

export interface DomainLinkageCredential {
  '@context': string[]
  type: string[]
  credentialSubject: CredentialSubject
  issuer: string
  issuanceDate: string
  expirationDate: string
  signedRequest: IRequestForAttestation
  proof: Proof
}
