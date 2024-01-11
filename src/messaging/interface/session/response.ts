/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { DidUrl, DidDocument, VerificationMethod } from '@kiltprotocol/types'
import { stringToU8a } from '@polkadot/util'
import * as Did from '@kiltprotocol/did'

import type {
  ISessionRequest,
  ISession,
  ISessionResponse,
  EncryptCallback,
  DecryptCallback,
} from '../../../types/index.js'

/**
 * Prepares and returns a session response along with the prepared session.
 * @param didDocument - The DID document of the responder associated with the session.
 * @param sessionRequest - The session request details.
 * @param encryptCallback - A callback function used for encryption.
 * @param decryptCallback - A callback function used for decryption.
 * @param signCallback - A callback function used for signing.
 * @param options - Additional options for the function.
 * @param options.dereferenceDidUrl - An alternative function for resolving DIDs and verification methods (Optional).
 * @throws Error if keyAgreement is missing in the DID document.
 * @throws Error if receiverEncryptionKeyUri is not a valid DID URI.
 * @returns An object containing the prepared session and session response.
 */
export async function receiveSessionRequest(
  didDocument: DidDocument,
  { challenge, encryptionKeyUri: receiverEncryptionKeyUri }: ISessionRequest,
  encryptCallback: EncryptCallback,
  decryptCallback: DecryptCallback,
  authenticationSigner: ISession['authenticationSigner'],
  {
    dereferenceDidUrl = Did.dereference,
  }: {
    dereferenceDidUrl?: typeof Did.dereference
  } = {}
): Promise<{ session: ISession; sessionResponse: ISessionResponse }> {
  if (!didDocument.keyAgreement) {
    throw new Error('keyAgreement is necessary')
  }
  const responseEncryptionKey: DidUrl = `${didDocument.id}${didDocument.keyAgreement?.[0]}`

  Did.validateDid(receiverEncryptionKeyUri)
  const { contentStream: receiverKey } = await dereferenceDidUrl(receiverEncryptionKeyUri, {
    accept: 'application/did+json',
  })
  if ((receiverKey as any).type !== 'Multikey') {
    throw new Error('receiver key is expected to resolve to a Multikey verification method')
  }

  const serializedChallenge = stringToU8a(challenge)

  const encrypted = await encryptCallback({
    did: didDocument.id,
    data: serializedChallenge,
    peerPublicKey: Did.multibaseKeyToDidKey((receiverKey as VerificationMethod)?.publicKeyMultibase).publicKey,
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
      authenticationSigner,
    },
  }
}
