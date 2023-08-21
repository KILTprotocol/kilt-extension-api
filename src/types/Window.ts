import { DidResourceUri, KiltAddress } from '@kiltprotocol/types'
import { HexString } from './Imported'
import { CredentialDigestProof, SelfSignedProof } from '@kiltprotocol/vc-export'

import { DomainLinkageCredential, PubSubSessionV1, PubSubSessionV2 } from '.'

export type This = typeof globalThis

export interface InjectedWindowProvider<T> {
  startSession: (dAppName: string, dAppEncryptionKeyId: DidResourceUri, challenge: string) => Promise<T>
  name: string
  version: string
  specVersion: '1.0' | '3.0'
  signWithDid: (plaintext: string) => Promise<{ signature: string; didKeyUri: DidResourceUri }>
  signExtrinsicWithDid: (
    extrinsic: HexString,
    signer: KiltAddress
  ) => Promise<{ signed: HexString; didKeyUri: DidResourceUri }>
  getSignedDidCreationExtrinsic: (submitter: KiltAddress) => Promise<{ signedExtrinsic: HexString }>
}

export interface ApiWindow extends This {
  kilt: Record<string, InjectedWindowProvider<PubSubSessionV1 | PubSubSessionV2>>
}

export type DomainLinkageProof = {
  type: Array<SelfSignedProof['type'] | CredentialDigestProof['type']>
  rootHash: string
} & Pick<SelfSignedProof, 'signature' | 'verificationMethod' | 'proofPurpose' | 'created'> &
  Pick<CredentialDigestProof, 'claimHashes' | 'nonces'>

export interface DidConfigResource {
  '@context': string
  linked_dids: [DomainLinkageCredential]
}
