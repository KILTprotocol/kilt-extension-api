import { Did } from '@kiltprotocol/sdk-js'

import { IEncryptedMessage, IError, IReject, ISession } from '../../../types/index.js'
import { fromBody } from '../../utils.js'
import { encrypt } from '../../MessageEnvelope.js'

/**
 * Creates an encrypted error message.
 * @param content - The content of the error message.
 * @param session - An object containing session information.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @returns A promise that resolves to an encrypted error message.
 */
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

/**
 * Creates an encrypted reject message.
 * @param content - The content of the reject message.
 * @param session - An object containing session information.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @returns A promise that resolves to an encrypted reject message.
 */
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
