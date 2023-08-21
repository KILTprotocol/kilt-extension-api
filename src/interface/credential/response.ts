import { Credential } from '@kiltprotocol/sdk-js'
import { ICredential, SignCallback } from '@kiltprotocol/types'

import { IEncryptedMessage, ISubmitCredential } from '../../types'
import { ISession } from '../../types/Session'
import { decrypt, encrypt } from '../../messaging/Crypto'
import { isIRequestCredential } from '../../utils/TypeGuards'
import { fromBody } from '../../messaging/utils'
import { getDidUriFromDidResourceUri } from '../../utils/Crypto'
import { assertKnownMessage } from '../../messaging/CredentialApiMessageType'

export async function submitCredential(
  credentials: ICredential[],
  signCallback: SignCallback,
  encryptedMessage: IEncryptedMessage,
  { decryptCallback, senderEncryptionKeyUri, receiverEncryptionKeyUri, encryptCallback }: ISession
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
