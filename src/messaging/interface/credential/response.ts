import { Credential } from '@kiltprotocol/sdk-js'
import { ICredential } from '@kiltprotocol/types'

import { ISession, IEncryptedMessage, ISubmitCredential } from 'types/index'
import { decrypt, encrypt, assertKnownMessage, fromBody } from 'message/index'
import { isIRequestCredential, getDidUriFromDidResourceUri } from 'utils/index'

export async function submitCredential(
  credentials: ICredential[],
  encryptedMessage: IEncryptedMessage,
  { decryptCallback, senderEncryptionKeyUri, receiverEncryptionKeyUri, encryptCallback, signCallback }: ISession
): Promise<IEncryptedMessage<ISubmitCredential>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  assertKnownMessage(decryptedMessage)

  if (!isIRequestCredential(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  const { challenge, cTypes, owner } = decryptedMessage.body.content

  const content = await Promise.all(
    cTypes.map(async (ctype) => {
      const filteredCredential = credentials.filter(
        //TODO: check if I really have to filter against ctypeHash.
        (c) => c.claim.cTypeHash === ctype.cTypeHash && (owner ? c.claim.owner === owner : true)
      )

      if (!filteredCredential) {
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

  const sender = getDidUriFromDidResourceUri(senderEncryptionKeyUri)
  const receiver = getDidUriFromDidResourceUri(receiverEncryptionKeyUri)

  const message = fromBody(body, sender, receiver)
  message.inReplyTo = decryptedMessage.messageId

  return encrypt(message, encryptCallback, receiverEncryptionKeyUri)
}
