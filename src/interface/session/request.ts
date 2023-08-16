import { DidDocument, DidResourceUri } from '@kiltprotocol/types'
import { KeyError } from '../../messaging/Error'
import * as Kilt from '@kiltprotocol/sdk-js'
import { randomAsHex } from '@polkadot/util-crypto'

import { IRequestSession, Session } from './types'
import { calculateKeyAgreementKeyFromMnemonic } from '../../utils/Crypto'

export function requestSession(didDocument: DidDocument, name: string): IRequestSession {
  if (typeof didDocument.keyAgreement === undefined) {
    throw new KeyError('Key missing')
  }

  const senderEncryptionKeyUri = `${didDocument.uri}${didDocument.keyAgreement?.[0].id}` as DidResourceUri

  const challenge = randomAsHex(24)

  return {
    name,
    senderEncryptionKeyUri,
    challenge,
  }
}

export async function verifySession(mnemonic: string, challenge: string, session: Session): Promise<Session> {
  const { encryptedChallenge, nonce, encryptionKeyUri } = session

  const encryptionKey = await Kilt.Did.resolveKey(encryptionKeyUri)
  if (!encryptionKey) {
    throw new Error('an encryption key is required')
  }

  const keyAgreement = calculateKeyAgreementKeyFromMnemonic(mnemonic)

  const decryptedBytes = Kilt.Utils.Crypto.decryptAsymmetric(
    { box: encryptedChallenge, nonce },
    encryptionKey.publicKey,
    keyAgreement.secretKey
  )

  if (!decryptedBytes) {
    throw new Error('Could not decode/decrypt the challenge from the extension')
  }

  const decryptedChallenge = Kilt.Utils.Crypto.u8aToHex(decryptedBytes)

  if (decryptedChallenge !== challenge) {
    throw new Error('Invalid challenge')
  }

  return session
}
