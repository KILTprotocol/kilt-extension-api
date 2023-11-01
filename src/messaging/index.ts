/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

/**
 * KILT participants can communicate via a 1:1 messaging system.
 *
 * All messages are **encrypted** with the encryption keys of the involved identities.
 * Messages are encrypted using authenticated encryption: the two parties authenticate to each other, but the message authentication provides repudiation possibilities.
 */

export { fromBody } from './utils.js'
export { encrypt, decrypt } from './MessageEnvelope.js'
export { assertKnownMessage } from './CredentialApiMessageType.js'
export * from './interface/index.js'
export * from './Error.js'
