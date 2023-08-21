import { DidDocument, DidResourceUri, SignCallback } from '@kiltprotocol/types'
import { Did, Utils } from '@kiltprotocol/sdk-js'
import { randomAsHex } from '@polkadot/util-crypto'
import { stringToU8a } from '@polkadot/util'
import { DecryptCallback, EncryptCallback } from '@kiltprotocol/types'

import { IRequestSession, ISession, ISessionResponse } from '../../../types'
import { getDefaultDecryptCallback, getDefaultEncryptCallback, getDefaultSignCallback } from '../../../utils'
import { KeyError } from '../../Error'

export function requestSession(didDocument: DidDocument, name: string): IRequestSession {
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
  { encryptionKeyUri, challenge }: IRequestSession,
  { encryptedChallenge, nonce, encryptionKeyUri: receiverEncryptionKeyUri }: ISessionResponse,
  mnemonic: string,
  decryptCallback: DecryptCallback = getDefaultDecryptCallback(mnemonic),
  encryptCallback: EncryptCallback = getDefaultEncryptCallback(encryptionKeyUri, mnemonic),
  signCallback: SignCallback = getDefaultSignCallback(mnemonic)
): Promise<ISession> {
  const encryptionKey = await Did.resolveKey(receiverEncryptionKeyUri)
  if (!encryptionKey) {
    throw new Error('an encryption key is required')
  }

  const decryptedBytes = await decryptCallback({
    data: stringToU8a(encryptedChallenge),
    nonce: stringToU8a(nonce),
    peerPublicKey: encryptionKey.publicKey,
    keyUri: encryptionKeyUri,
  })

  if (!decryptedBytes) {
    throw new Error('Could not decode/decrypt the challenge from the extension')
  }

  const decryptedChallenge = Utils.Crypto.u8aToHex(decryptedBytes.data)

  if (decryptedChallenge !== challenge) {
    throw new Error('Invalid challenge')
  }

  return {
    encryptCallback,
    decryptCallback,
    signCallback,
    receiverEncryptionKeyUri,
    encryptedChallenge,
    nonce,
    senderEncryptionKeyUri: encryptionKeyUri,
  }
}
