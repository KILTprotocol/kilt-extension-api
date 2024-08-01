/**
 * Copyright (c) 2018-2023, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { DecryptCallback, DidResourceUri, EncryptCallback, SignCallback } from '@kiltprotocol/types'

import { IEncryptedMessage, IEncryptedMessageV1 } from './index.js'

export interface ISessionRequest {
  name: string
  encryptionKeyUri: DidResourceUri
  challenge: string
}

export interface ISessionResponse {
  encryptionKeyUri: DidResourceUri
  encryptedChallenge: Uint8Array
  nonce: Uint8Array
}

export interface ISession {
  receiverEncryptionKeyUri: DidResourceUri
  senderEncryptionKeyUri: DidResourceUri
  encryptCallback: EncryptCallback
  decryptCallback: DecryptCallback
  signCallback: SignCallback
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
