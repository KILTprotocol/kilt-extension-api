import { randomAsHex } from '@polkadot/util-crypto'
import { CTypeHash, DidUri } from '@kiltprotocol/types'
import { CType, Credential } from '@kiltprotocol/sdk-js'

import { ISession } from '../../types/Session'
import { ICredentialRequest, IEncryptedMessage, IMessage, IRequestCredential, ISubmitCredential } from '../../types'
import { isIRequestCredential, isSubmitCredential } from '../../utils/TypeGuards'
import { decrypt, encrypt } from '../../messaging/Crypto'
import { fromBody } from '../../messaging/utils'
import { getDidUriFromDidResourceUri } from '../../utils/Crypto'
import { assertKnownMessage } from '../../messaging/CredentialApiMessageType'

export async function requestCredential(
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback }: ISession,
  cTypes: Array<{
    cTypeHash: CTypeHash
    trustedAttesters?: DidUri[]
    requiredProperties?: string[]
  }>,
  owner?: DidUri
): Promise<ICredentialRequest> {
  const challenge = randomAsHex(24)
  const body: IRequestCredential = {
    content: {
      cTypes,
      challenge,
      owner,
    },
    type: 'request-credential',
  }

  const sender = getDidUriFromDidResourceUri(senderEncryptionKeyUri)
  const receiver = getDidUriFromDidResourceUri(receiverEncryptionKeyUri)

  const message = fromBody(body, sender, receiver)
  return { encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri), message, challenge }
}

export async function verifySubmitedCredentialMessage(
  encryptedMessage: IEncryptedMessage<ISubmitCredential>,
  { decryptCallback }: ISession,
  { message: requestMessage, challenge }: ICredentialRequest
): Promise<IMessage<ISubmitCredential>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  assertKnownMessage(decryptedMessage)
  assertKnownMessage(requestMessage)

  if (decryptedMessage.inReplyTo === requestMessage.messageId) {
    throw new Error('Wrong Reply to')
  }

  if (!isSubmitCredential(decryptedMessage) || !isIRequestCredential(requestMessage)) {
    throw new Error('Wrong message received.')
  }

  await validateMessageBody(decryptedMessage, requestMessage, challenge)

  return decryptedMessage
}

async function validateMessageBody(
  decryptedMessage: IMessage<ISubmitCredential>,
  originalMessage: IMessage<IRequestCredential>,
  challenge: string
) {
  decryptedMessage.body.content.map(async (credentialPresentation) => {
    const requestedCtype = originalMessage.body.content.cTypes.filter(
      (ctype) => ctype.cTypeHash === credentialPresentation.claim.cTypeHash
    )

    if (!requestedCtype) {
      throw new Error('Ctype does not match')
    }

    const ctypeDetails: CType.ICTypeDetails = await CType.fetchFromChain(`kilt:ctype:${requestedCtype[0].cTypeHash}`)

    const { $id, $schema, title, properties, type } = ctypeDetails
    const ctype = { $id, $schema, title, properties, type }

    Credential.verifyPresentation(credentialPresentation, { ctype, challenge })
  })
}
