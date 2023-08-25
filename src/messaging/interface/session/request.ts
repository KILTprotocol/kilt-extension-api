import { DidDocument, DidResolveKey, DidResourceUri, SignCallback } from '@kiltprotocol/types'
import { Did } from '@kiltprotocol/sdk-js'
import { randomAsHex } from '@polkadot/util-crypto'
import { DecryptCallback, EncryptCallback } from '@kiltprotocol/types'

import { ISessionRequest, ISession, ISessionResponse } from '../../../types'
import { KeyError } from '../../Error'
import { u8aToString } from '@polkadot/util'

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
