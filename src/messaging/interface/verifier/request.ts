import { randomAsHex } from '@polkadot/util-crypto'
import { CTypeHash, DidResolveKey, DidUri } from '@kiltprotocol/types'
import { CType, Credential, Did } from '@kiltprotocol/sdk-js'

import {
  ISession,
  ICredentialRequest,
  IEncryptedMessage,
  IMessage,
  IRequestCredential,
  ISubmitCredential,
} from '../../../types'
import { getDidUriFromDidResourceUri, isIRequestCredential, isSubmitCredential } from '../../../utils'
import { decrypt, encrypt, fromBody } from '../../index'

export async function requestCredential(
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback }: ISession,
  cTypes: Array<{
    cTypeHash: CTypeHash
    trustedAttesters?: DidUri[]
    requiredProperties?: string[]
  }>,
  owner?: DidUri,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
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

  const message = fromBody(body, sender, receiver) as IMessage<IRequestCredential>

  return {
    encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri, { resolveKey }),
    message,
    challenge,
  }
}

export async function verifySubmitedCredentialMessage(
  encryptedMessage: IEncryptedMessage<ISubmitCredential>,
  { decryptCallback }: ISession,
  { message: requestMessage, challenge }: ICredentialRequest,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<IMessage<ISubmitCredential>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })

  if (decryptedMessage.inReplyTo !== requestMessage.messageId) {
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

    if (requestedCtype.length === 0) {
      throw new Error('Ctype does not match')
    }

    if (
      originalMessage.body.content.owner &&
      originalMessage.body.content.owner !== credentialPresentation.claim.owner
    ) {
      throw new Error('Users do not match')
    }

    const ctypeDetails: CType.ICTypeDetails = await CType.fetchFromChain(`kilt:ctype:${requestedCtype[0].cTypeHash}`)

    const { $id, $schema, title, properties, type } = ctypeDetails
    const ctype = { $id, $schema, title, properties, type }

    Credential.verifyPresentation(credentialPresentation, { ctype, challenge })
  })
}
