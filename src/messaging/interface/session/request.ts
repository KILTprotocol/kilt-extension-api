/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import * as Did from '@kiltprotocol/did'
import type { DidDocument, DidUrl, SignerInterface, VerificationMethod } from '@kiltprotocol/types'
import { Signers } from '@kiltprotocol/utils'
import { u8aToString } from '@polkadot/util'
import { randomAsHex } from '@polkadot/util-crypto'
import { DecryptCallback, EncryptCallback } from '../../../types/Message.js'
import type { ISession, ISessionRequest, ISessionResponse } from '../../../types/index.js'
import { KeyError } from '../../Error.js'

/**
 * Requests a session with a given DID document and name.
 * @param didDocument - The DID document of the requester associated with the session.
 * @param name - The name of the session.
 * @throws KeyError if keyAgreement does not exist in the DID document.
 * @returns An object containing the session request details.
 */
export function requestSession(didDocument: DidDocument, name: string): ISessionRequest {
  if (typeof didDocument.keyAgreement === undefined || !didDocument.keyAgreement) {
    throw new KeyError('KeyAgreement does not exists')
  }

  const encryptionKeyUri = `${didDocument.id}${didDocument.keyAgreement?.[0]}` as DidUrl

  const challenge = randomAsHex(24)
  return {
    name,
    encryptionKeyUri,
    challenge,
  }
}

/**
 * Verifies a session response, decrypts the challenge, and prepares the session.
 * @param sessionRequest - The original session request details.
 * @param sessionResponse - The session response details.
 * @param decryptCallback - A callback function used for decryption.
 * @param encryptCallback - A callback function used for encryption.
 * @param signers - An array of signers linked to your DID, from which the authentication signer will be selected.
 * @param options - Additional options for the function.
 * @param options.dereferenceDidUrl - An alternative function for resolving DIDs and verification methods (Optional).
 * @param options.didDocument - The Did Document of the DID used by the requesting party. Optional, will be fetched if not passed.
 * @throws Error if encryption key is missing.
 * @throws Error if decrypted challenge doesn't match the original challenge.
 * @returns An object containing the prepared session information.
 */
export async function verifySession(
  { encryptionKeyUri, challenge }: ISessionRequest,
  { encryptedChallenge, nonce, encryptionKeyUri: receiverEncryptionKeyUri }: ISessionResponse,
  decryptCallback: DecryptCallback,
  encryptCallback: EncryptCallback,
  signers: SignerInterface[],
  {
    didDocument,
    dereferenceDidUrl = Did.dereference,
  }: {
    didDocument?: DidDocument
    dereferenceDidUrl?: typeof Did.dereference
  } = {}
): Promise<ISession> {
  const { contentStream: encryptionKey } = await dereferenceDidUrl(receiverEncryptionKeyUri, {
    accept: 'application/did+json',
  })
  if ((encryptionKey as VerificationMethod)?.type !== 'Multikey') {
    throw new Error('An encryption key is required')
  }
  if (!didDocument) {
    didDocument = (
      await dereferenceDidUrl(Did.parse(encryptionKeyUri).did, {
        accept: 'application/did+json',
      })
    ).contentStream as DidDocument
  }
  const authenticationSigner = Signers.selectSigner<SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>>(
    signers,
    Signers.select.byDid(didDocument, { verificationRelationship: 'authentication' }),
    Signers.select.verifiableOnChain()
  )
  if (!authenticationSigner) {
    throw new Error('a signer for the responder DID authentication method is required')
  }

  const decryptedBytes = await decryptCallback({
    data: encryptedChallenge,
    nonce,
    peerPublicKey: Did.multibaseKeyToDidKey((encryptionKey as VerificationMethod).publicKeyMultibase).publicKey,
    keyUri: encryptionKeyUri,
  })

  const decryptedChallenge = u8aToString(decryptedBytes.data)

  if (decryptedChallenge !== challenge) {
    throw new Error('Invalid challenge')
  }

  return {
    encryptCallback,
    decryptCallback,
    authenticationSigner,
    receiverEncryptionKeyUri,
    senderEncryptionKeyUri: encryptionKeyUri,
  }
}
