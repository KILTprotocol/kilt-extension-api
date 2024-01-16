/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { DidUrl, SignerInterface } from '@kiltprotocol/types'
import type { Signers } from '@kiltprotocol/utils'
import type { EncryptCallback, DecryptCallback, IEncryptedMessage } from './Message.js'

export interface ISessionRequest {
  name: string
  encryptionKeyUri: DidUrl
  challenge: string
}

export interface ISessionResponse {
  encryptionKeyUri: DidUrl
  encryptedChallenge: Uint8Array
  nonce: Uint8Array
}

export interface ISession {
  receiverEncryptionKeyUri: DidUrl
  senderEncryptionKeyUri: DidUrl
  encryptCallback: EncryptCallback
  decryptCallback: DecryptCallback
  authenticationSigner: SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>
}

export interface IEncryptedMessageV1 {
  /** ID of the key agreement key of the receiver DID used to encrypt the message */
  receiverKeyId: DidUrl

  /** ID of the key agreement key of the sender DID used to encrypt the message */
  senderKeyId: DidUrl

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
  encryptionKeyUri: DidUrl

  /** bytes as hexadecimal */
  encryptedChallenge: string

  /** 24 bytes nonce as hexadecimal */
  nonce: string
}
