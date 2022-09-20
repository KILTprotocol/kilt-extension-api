import {
  DidPublicKey,
  DidUri,
  IEncryptedMessage,
  IIdentity,
} from '@kiltprotocol/sdk-js'
import { HexString } from '@polkadot/util/types'
import { types as VC_TYPES } from '@kiltprotocol/vc-export'

export type This = typeof globalThis
const DEFAULT_VERIFIABLECREDENTIAL_CONTEXT =
  'https://www.w3.org/2018/credentials/v1'
export interface PubSubSession {
  listen: (
    callback: (message: IEncryptedMessage) => Promise<void>
  ) => Promise<void>
  close: () => Promise<void>
  send: (message: IEncryptedMessage) => Promise<void>
  encryptionKeyId: DidPublicKey['uri']
  encryptedChallenge: string
  nonce: string
}

export interface InjectedWindowProvider {
  startSession: (
    dAppName: string,
    dAppEncryptionKeyId: DidPublicKey['uri'],
    challenge: string
  ) => Promise<PubSubSession>
  name: string
  version: string
  specVersion: '1.0'
  signWithDid: (
    plaintext: string
  ) => Promise<{ signature: string; didKeyUri: DidPublicKey['uri'] }>
  signExtrinsicWithDid: (
    extrinsic: HexString,
    signer: IIdentity['address']
  ) => Promise<{ signed: HexString; didKeyUri: DidPublicKey['uri'] }>
}

export interface ApiWindow extends This {
  kilt: Record<string, InjectedWindowProvider>
}

export interface CredentialSubject {
  id: DidUri
  origin: string
  rootHash: string
}

const context = [
  DEFAULT_VERIFIABLECREDENTIAL_CONTEXT,
  'https://identity.foundation/.well-known/did-configuration/v1',
]
export interface DomainLinkageCredential
  extends Omit<
    VC_TYPES.VerifiableCredential,
    '@context' | 'id' | 'legitimationIds' | 'credentialSubject' | 'proof'
  > {
  '@context': typeof context
  credentialSubject: CredentialSubject
  proof: VC_TYPES.Proof
}

export interface VerifiableDomainLinkagePresentation {
  '@context': string
  linked_dids: [DomainLinkageCredential]
}
