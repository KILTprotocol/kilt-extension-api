/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import * as Did from '@kiltprotocol/did'
import { DidDocument, DidUrl, SignerInterface, VerificationMethod } from '@kiltprotocol/types'
import { Signers } from '@kiltprotocol/utils'
import { stringToU8a } from '@polkadot/util'

import type {
  DecryptCallback,
  EncryptCallback,
  ISession,
  ISessionRequest,
  ISessionResponse,
} from '../../../types/index.js'

/**
 * Prepares and returns a session response along with the prepared session.
 * @param didDocument - The DID document of the responder associated with the session.
 * @param sessionRequest - The session request details.
 * @param encryptCallback - A callback function used for encryption.
 * @param decryptCallback - A callback function used for decryption.
 * @param signers - An array of signers linked to your DID, from which the authentication signer will be selected.
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
  signers: SignerInterface[],
  {
    dereferenceDidUrl = Did.dereference,
  }: {
    dereferenceDidUrl?: typeof Did.dereference
  } = {}
): Promise<{ session: ISession; sessionResponse: ISessionResponse }> {
  if (!didDocument.keyAgreement) {
    throw new Error('keyAgreement is necessary')
  }
  const authenticationSigner = Signers.selectSigner<SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>>(
    signers,
    Signers.select.byDid(didDocument, { verificationRelationship: 'authentication' }),
    Signers.select.verifiableOnChain()
  )
  if (!authenticationSigner) {
    throw new Error('a signer for the responder DID authentication method is required')
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
