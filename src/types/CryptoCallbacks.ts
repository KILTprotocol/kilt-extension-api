/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { DidResourceUri, DidUri } from './DidDocument.js'

/**
 * Base interface for encryption requests.
 */
export interface EncryptRequestData {
  /**
   * Data to be encrypted.
   */
  data: Uint8Array
  /**
   * The other party's public key to be used for x25519 Diffie-Hellman key agreement.
   */
  peerPublicKey: Uint8Array
  /**
   * The DID to be used for encryption.
   */
  did: DidUri
}

/**
 * Base interface for responses to encryption requests.
 */
export interface EncryptResponseData {
  /**
   * Result of the encryption.
   */
  data: Uint8Array
  /**
   * A random nonce generated in the encryption process.
   */
  nonce: Uint8Array
  /**
   * The did key uri used for the encryption.
   */
  keyUri: DidResourceUri
}

/**
 * Uses stored key material to encrypt a message encoded as u8a.
 *
 * @param requestData The data to be encrypted, the peers public key and the sender's DID.
 * @returns [[EncryptResponseData]] which additionally to the data contains a `nonce` randomly generated in the encryption process (required for decryption).
 */
export interface EncryptCallback {
  (requestData: EncryptRequestData): Promise<EncryptResponseData>
}

export interface DecryptRequestData {
  /**
   * Data to be encrypted.
   */
  data: Uint8Array
  /**
   * The other party's public key to be used for x25519 Diffie-Hellman key agreement.
   */
  peerPublicKey: Uint8Array
  /**
   * The random nonce generated during encryption as u8a.
   */
  nonce: Uint8Array
  /**
   * The did key uri, which should be used for decryption.
   */
  keyUri: DidResourceUri
}

export interface DecryptResponseData {
  /**
   * Result of the decryption.
   */
  data: Uint8Array
}

/**
 * Uses stored key material to decrypt a message encoded as u8a.
 *
 * @param requestData [[DecryptRequestData]] containing both our and their public keys, the nonce used for encryption, the data to be decrypted.
 * @param requestData.nonce The random nonce generated during encryption as u8a.
 * @returns A Promise resolving to [[DecryptResponseData]] containing the decrypted message or rejecting if a key is unknown or does not match.
 */
export interface DecryptCallback {
  (requestData: DecryptRequestData): Promise<DecryptResponseData>
}