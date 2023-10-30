import { Credential, Did } from '@kiltprotocol/sdk-js'
import { DidResolveKey, ICredential } from '@kiltprotocol/types'

import { ISession, IEncryptedMessage, ISubmitCredential } from '../../../types/index.js'
import { decrypt, encrypt, assertKnownMessage, fromBody } from '../../index.js'
import { isIRequestCredential } from '../../../utils/index.js'

/**
 * Submits credentials as a response to a request credential message.
 * @param credentials - An array of credentials to be submitted.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param session - An object containing session information.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @param session.signCallback - A callback function used for signing.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Used for tests only.
 * @throws Error if the decrypted message is not a request credential message.
 * @throws Error if credentials do not match.
 * @returns A promise that resolves to an encrypted message containing the submitted credentials.
 */
export async function submitCredential(
  credentials: ICredential[],
  encryptedMessage: IEncryptedMessage,
  { decryptCallback, senderEncryptionKeyUri, receiverEncryptionKeyUri, encryptCallback, signCallback }: ISession,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<IEncryptedMessage<ISubmitCredential>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })
  assertKnownMessage(decryptedMessage)

  if (!isIRequestCredential(decryptedMessage)) {
    throw new Error('Wrong message. Expected request credential message')
  }

  const { challenge, cTypes, owner } = decryptedMessage.body.content

  const content = await Promise.all(
    cTypes.map(async (ctype) => {
      const filteredCredential = credentials.filter(
        (c) => c.claim.cTypeHash === ctype.cTypeHash && (owner ? c.claim.owner === owner : true)
      )

      if (filteredCredential.length === 0) {
        throw new Error('Credentials do not match')
      }

      return await Credential.createPresentation({
        credential: filteredCredential[0],
        signCallback,
        selectedAttributes: ctype.requiredProperties,
        challenge,
      })
    })
  )

  const body: ISubmitCredential = {
    content,
    type: 'submit-credential',
  }

  const { did: sender } = Did.parse(senderEncryptionKeyUri)
  const { did: receiver } = Did.parse(receiverEncryptionKeyUri)

  const message = fromBody(body, sender, receiver)
  message.inReplyTo = decryptedMessage.messageId
  return encrypt(message, encryptCallback, receiverEncryptionKeyUri, { resolveKey })
}
