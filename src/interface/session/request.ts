import { DidDocument, DidResourceUri } from '@kiltprotocol/types'
import { Did, Utils } from '@kiltprotocol/sdk-js'
import { randomAsHex } from '@polkadot/util-crypto'
import { stringToU8a } from '@polkadot/util'
import { DecryptCallback, EncryptCallback } from '@kiltprotocol/types'

import { KeyError } from '../../messaging/Error'
import { IRequestSession, ISession, ISessionResponse } from '../../types/Session'
import { getDefaultDecryptCallback, getDefaultEncryptCallback } from '../../utils/Crypto'

export function requestSession(didDocument: DidDocument, name: string): IRequestSession {
  if (typeof didDocument.keyAgreement === undefined) {
    throw new KeyError('Key missing')
  }

  const encryptionKeyUri = `${didDocument.uri}#${didDocument.keyAgreement?.[0].id}` as DidResourceUri

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
  encryptCallback: EncryptCallback = getDefaultEncryptCallback(encryptionKeyUri, mnemonic)
): Promise<ISession> {
  const encryptionKey = await Did.resolveKey(encryptionKeyUri)
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
    receiverEncryptionKeyUri,
    encryptedChallenge,
    nonce,
    senderEncryptionKeyUri: encryptionKeyUri,
  }
}
