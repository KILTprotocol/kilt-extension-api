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

import { ISessionRequest, ISession, ISessionResponse } from '../../../types'

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
