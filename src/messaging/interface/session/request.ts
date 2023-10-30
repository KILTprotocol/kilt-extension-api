import { DidDocument, DidResolveKey, DidResourceUri, SignCallback } from '@kiltprotocol/types'
import { Did } from '@kiltprotocol/sdk-js'
import { randomAsHex } from '@polkadot/util-crypto'
import { DecryptCallback, EncryptCallback } from '@kiltprotocol/types'

import { ISessionRequest, ISession, ISessionResponse } from '../../../types/index.js'
import { KeyError } from '../../Error.js'
import { u8aToString } from '@polkadot/util'

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

  const encryptionKeyUri = `${didDocument.uri}${didDocument.keyAgreement?.[0].id}` as DidResourceUri

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
 * @param signCallback - A callback function used for signing.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Used for testing only
 * @throws Error if encryption key is missing.
 * @throws Error if decrypted challenge doesn't match the original challenge.
 * @returns An object containing the prepared session information.
 */
export async function verifySession(
  { encryptionKeyUri, challenge }: ISessionRequest,
  { encryptedChallenge, nonce, encryptionKeyUri: receiverEncryptionKeyUri }: ISessionResponse,
  decryptCallback: DecryptCallback,
  encryptCallback: EncryptCallback,
  signCallback: SignCallback,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<ISession> {
  const encryptionKey = await resolveKey(receiverEncryptionKeyUri, 'keyAgreement')
  if (!encryptionKey) {
    throw new Error('An encryption key is required')
  }

  const decryptedBytes = await decryptCallback({
    data: encryptedChallenge,
    nonce,
    peerPublicKey: encryptionKey.publicKey,
    keyUri: encryptionKeyUri,
  })

  const decryptedChallenge = u8aToString(decryptedBytes.data)

  if (decryptedChallenge !== challenge) {
    throw new Error('Invalid challenge')
  }

  return {
    encryptCallback,
    decryptCallback,
    signCallback,
    receiverEncryptionKeyUri,
    senderEncryptionKeyUri: encryptionKeyUri,
  }
}
