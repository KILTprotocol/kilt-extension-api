import { Did } from '@kiltprotocol/sdk-js'

import { IEncryptedMessage, IError, IReject, ISession } from '../../../types'
import { fromBody } from '../../utils'
import { encrypt } from '../../MessageEnvelope.'

export async function createErrorMessage(
  content: { name?: string; message?: string },
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback }: ISession
): Promise<IEncryptedMessage> {
  const body: IError = {
    content,
    type: 'error',
  }
  const { did: sender } = Did.parse(senderEncryptionKeyUri)
  const { did: receiver } = Did.parse(receiverEncryptionKeyUri)
  const message = fromBody(body, sender, receiver)
  return await encrypt(message, encryptCallback, receiverEncryptionKeyUri)
}

export async function createRejectMessage(
  content: { name?: string; message?: string },
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback }: ISession
): Promise<IEncryptedMessage> {
  const body: IReject = {
    content,
    type: 'reject',
  }
  const { did: sender } = Did.parse(senderEncryptionKeyUri)
  const { did: receiver } = Did.parse(receiverEncryptionKeyUri)
  const message = fromBody(body, sender, receiver)
  return await encrypt(message, encryptCallback, receiverEncryptionKeyUri)
}
