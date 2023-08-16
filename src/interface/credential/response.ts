import { DecryptCallback } from '@kiltprotocol/types'
import { IEncryptedMessage, ISubmitCredential } from '../../types'
import { Session } from '../session/types'
import * as Kilt from '@kiltprotocol/sdk-js'
import { decrypt, encrypt } from '../../messaging/Crypto'
import { isIRequestCredential } from '../../utils/TypeGuards'
import { fromBody } from '../../messaging/utils'

export async function submitCredential(
  sender: Kilt.DidUri,
  encryptedMessage: IEncryptedMessage,
  session: Session,
  credentials: Kilt.ICredential[],
  decryptCallback: DecryptCallback,
  encryptCallback: Kilt.EncryptCallback,
  signCallback: Kilt.SignCallback
): Promise<IEncryptedMessage> {
  const request = await decrypt(encryptedMessage, decryptCallback)
  if (!isIRequestCredential(request)) {
    throw new Error('Wrong message')
  }

  const { challenge, cTypes } = request.body.content

  const content = await Promise.all(
    cTypes.map(async (ctype) => {
      const filteredCredential = credentials.filter((c) => c.claim.cTypeHash === ctype.cTypeHash)

      if (filteredCredential.length === 0) {
        throw new Error('Credentials do not match')
      }

      return await Kilt.Credential.createPresentation({
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

  const receiverDidDocument = await Kilt.Did.resolve(session.encryptionKeyUri)
  if (receiverDidDocument === null || receiverDidDocument.document === undefined) {
    throw new Kilt.SDKErrors.DidNotFoundError('Receiver does not exists')
  }

  const message = fromBody(body, sender, receiverDidDocument.document.uri)
  return encrypt(message, encryptCallback, session.encryptionKeyUri)
}
