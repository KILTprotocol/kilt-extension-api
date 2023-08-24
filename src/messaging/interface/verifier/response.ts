import { Credential, Did } from '@kiltprotocol/sdk-js'
import { DidResolveKey, ICredential } from '@kiltprotocol/types'

import { ISession, IEncryptedMessage, ISubmitCredential } from 'types/index'
import { decrypt, encrypt, assertKnownMessage, fromBody } from '../../index'
import { isIRequestCredential } from '../../../utils'

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
    throw new Error('Wrong message')
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
