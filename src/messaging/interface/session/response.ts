/**
 * Copyright (c) 2018-2023, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import {
  DidResourceUri,
  DidDocument,
  EncryptCallback,
  DecryptCallback,
  SignCallback,
  DidResolveKey,
} from '@kiltprotocol/types'
import { stringToU8a } from '@polkadot/util'
import { Did } from '@kiltprotocol/sdk-js'

import type { ISessionRequest, ISession, ISessionResponse } from '../../../types/index.js'

/**
 * Prepares and returns a session response along with the prepared session.
 * @param didDocument - The DID document of the responder associated with the session.
 * @param sessionRequest - The session request details.
 * @param encryptCallback - A callback function used for encryption.
 * @param decryptCallback - A callback function used for decryption.
 * @param signCallback - A callback function used for signing.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Used for testing only
 * @throws Error if keyAgreement is missing in the DID document.
 * @throws Error if receiverEncryptionKeyUri is not a valid DID URI.
 * @returns An object containing the prepared session and session response.
 */
export async function receiveSessionRequest(
  didDocument: DidDocument,
  { challenge, encryptionKeyUri: receiverEncryptionKeyUri }: ISessionRequest,
  encryptCallback: EncryptCallback,
  decryptCallback: DecryptCallback,
  signCallback: SignCallback,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<{ session: ISession; sessionResponse: ISessionResponse }> {
  if (!didDocument.keyAgreement) {
    throw new Error('keyAgreement is necessary')
  }
  const responseEncryptionKey = `${didDocument.uri}${didDocument.keyAgreement?.[0].id}` as DidResourceUri

  Did.validateUri(receiverEncryptionKeyUri)
  const receiverKey = await resolveKey(receiverEncryptionKeyUri, 'keyAgreement')

  const serializedChallenge = stringToU8a(challenge)

  const encrypted = await encryptCallback({
    did: didDocument.uri,
    data: serializedChallenge,
    peerPublicKey: receiverKey.publicKey,
  })

  const { data: encryptedChallenge, nonce } = encrypted

  return {
    sessionResponse: {
      encryptionKeyUri: responseEncryptionKey,
      encryptedChallenge,
      nonce,
    },
    session: {
      receiverEncryptionKeyUri,
      senderEncryptionKeyUri: responseEncryptionKey,
      encryptCallback,
      decryptCallback,
      signCallback,
    },
  }
}
