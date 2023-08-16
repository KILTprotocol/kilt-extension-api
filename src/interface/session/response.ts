import { DidDocument, EncryptCallback } from '@kiltprotocol/types'
import { IRequestSession, Session } from './types'
import * as Kilt from '@kiltprotocol/sdk-js'
import { stringToU8a, u8aToHex } from '@polkadot/util'
import { IEncryptedMessage } from '../../types'

export async function receiveSessionRequest(
  didDocument: DidDocument,
  sessionRequest: IRequestSession,
  // TODO: meaningfull default?
  encryptCallback: EncryptCallback,
  listen?: (callback: (message: IEncryptedMessage) => Promise<void>) => Promise<void>,
  send?: (message: IEncryptedMessage) => Promise<void>,
  close?: () => Promise<void>
): Promise<Session> {
  const encryptionKeyUri = `${didDocument.uri}${didDocument.keyAgreement?.[0].id}` as Kilt.DidResourceUri

  const { challenge, senderEncryptionKeyUri } = sessionRequest

  const receiverDid = await Kilt.Did.resolve(senderEncryptionKeyUri)

  if (
    receiverDid === null ||
    receiverDid.document === undefined ||
    receiverDid.document.keyAgreement === undefined ||
    receiverDid.document.keyAgreement.length === 0
  ) {
    throw new Error('No keyagreement')
  }

  const receiverKey = receiverDid.document.keyAgreement[0]

  const serializedChallenge = stringToU8a(challenge)

  const encrypted = await encryptCallback({
    did: didDocument.uri,
    data: serializedChallenge,
    peerPublicKey: receiverKey.publicKey,
  })

  const encryptedChallenge = u8aToHex(encrypted.data)
  const nonce = u8aToHex(encrypted.nonce)

  if (listen && send && close) {
    return {
      listen,
      send,
      close,
      nonce,
      encryptedChallenge,
      encryptionKeyUri,
    }
  }

  return { encryptionKeyUri, nonce, encryptedChallenge }
}
