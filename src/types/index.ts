/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { IEncryptedMessage, DidUri, KiltAddress, DidResourceUri } from '@kiltprotocol/types'
import type { HexString } from '@polkadot/util/types'
import type { CredentialDigestProof, SelfSignedProof, VerifiableCredential, constants } from '@kiltprotocol/vc-export'

export * from './Message.js'
export * from './Quote.js'
export * from './Imported.js'

export type This = typeof globalThis

export interface IEncryptedMessageV1 {
  /** ID of the key agreement key of the receiver DID used to encrypt the message */
  receiverKeyId: DidResourceUri

  /** ID of the key agreement key of the sender DID used to encrypt the message */
  senderKeyId: DidResourceUri

  /** ciphertext as hexadecimal */
  ciphertext: string

  /** 24 bytes nonce as hexadecimal */
  nonce: string
}

export interface PubSubSessionV1 {
  /** Configure the callback the extension must use to send messages to the dApp. Overrides previous values. */
  listen: (callback: (message: IEncryptedMessageV1) => Promise<void>) => Promise<void>

  /** send the encrypted message to the extension */
  send: (message: IEncryptedMessageV1) => Promise<void>

  /** close the session and stop receiving further messages */
  close: () => Promise<void>

  /** ID of the key agreement key of the temporary DID the extension will use to encrypt the session messages */
  encryptionKeyId: string

  /** bytes as hexadecimal */
  encryptedChallenge: string

  /** 24 bytes nonce as hexadecimal */
  nonce: string
}

export interface PubSubSessionV2 {
  /** Configure the callback the extension must use to send messages to the dApp. Overrides previous values. */
  listen: (callback: (message: IEncryptedMessage) => Promise<void>) => Promise<void>

  /** send the encrypted message to the extension */
  send: (message: IEncryptedMessage) => Promise<void>

  /** close the session and stop receiving further messages */
  close: () => Promise<void>

  /** ID of the key agreement key of the temporary DID the extension will use to encrypt the session messages */
  encryptionKeyUri: DidResourceUri

  /** bytes as hexadecimal */
  encryptedChallenge: string

  /** 24 bytes nonce as hexadecimal */
  nonce: string
}

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

export interface CredentialSubject {
  id: DidUri
  origin: string
}

type Contexts = [
  typeof constants.DEFAULT_VERIFIABLECREDENTIAL_CONTEXT,
  'https://identity.foundation/.well-known/did-configuration/v1',
]

export type DomainLinkageProof = {
  type: Array<SelfSignedProof['type'] | CredentialDigestProof['type']>
  rootHash: string
} & Pick<SelfSignedProof, 'signature' | 'verificationMethod' | 'proofPurpose' | 'created'> &
  Pick<CredentialDigestProof, 'claimHashes' | 'nonces'>

export interface DomainLinkageCredential
  extends Omit<VerifiableCredential, '@context' | 'legitimationIds' | 'credentialSubject' | 'proof' | 'id'> {
  '@context': Contexts
  credentialSubject: CredentialSubject
  proof: DomainLinkageProof
}

export interface DidConfigResource {
  '@context': string
  linked_dids: [DomainLinkageCredential]
}
