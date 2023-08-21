import { DidResourceUri, DidDocument, EncryptCallback, DecryptCallback, SignCallback } from '@kiltprotocol/types'
import { stringToU8a, u8aToHex } from '@polkadot/util'
import { Did } from '@kiltprotocol/sdk-js'

import { IRequestSession, ISession, ISessionResponse } from 'types/index'
import { getDefaultDecryptCallback, getDefaultEncryptCallback, getDefaultSignCallback } from 'src/utils'

export async function receiveSessionRequest(
  didDocument: DidDocument,
  mnemonic: string,
  { challenge, encryptionKeyUri }: IRequestSession,
  encryptCallback: EncryptCallback = getDefaultEncryptCallback(mnemonic),
  decryptCallback: DecryptCallback = getDefaultDecryptCallback(mnemonic),
  signCallback: SignCallback = getDefaultSignCallback(mnemonic)
): Promise<{ session: ISession; sessionResponse: ISessionResponse }> {
  if (!didDocument.keyAgreement) {
    throw new Error('keyAgreement is necessary')
  }
  const senderEncryptionKeyUri = `${didDocument.uri}${didDocument.keyAgreement?.[0].id}` as DidResourceUri

  const receiverKey = await Did.resolveKey(encryptionKeyUri)

  const serializedChallenge = stringToU8a(challenge)

  const encrypted = await encryptCallback({
    did: didDocument.uri,
    data: serializedChallenge,
    peerPublicKey: receiverKey.publicKey,
  })

  const encryptedChallenge = u8aToHex(encrypted.data)
  const nonce = u8aToHex(encrypted.nonce)

  return {
    sessionResponse: {
      encryptionKeyUri,
      encryptedChallenge,
      nonce,
    },
    session: {
      receiverEncryptionKeyUri: encryptionKeyUri,
      senderEncryptionKeyUri,
      nonce,
      encryptedChallenge,
      encryptCallback,
      decryptCallback,
      signCallback,
    },
  }
}
