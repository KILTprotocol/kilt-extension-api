/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { randomAsHex } from '@polkadot/util-crypto'
import { CTypeHash, Did } from '@kiltprotocol/types'
import { Credential } from '@kiltprotocol/legacy-credentials'
import { CType } from '@kiltprotocol/credentials'
import { dereference, parse } from '@kiltprotocol/did'

import type {
  ISession,
  ICredentialRequest,
  IEncryptedMessage,
  IMessage,
  IRequestCredential,
  ISubmitCredential,
} from '../../../types/index.js'
import { isIRequestCredential, isSubmitCredential } from '../../../utils/index.js'
import { decrypt, encrypt, fromBody } from '../../index.js'

/**
 * Requests a credential issuance with specified parameters.
 * @param session - An object containing session information.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @param cTypes - An array of credential type information. Normally a single one is enough. For nested cTypes an array has to be provided.
 * @param cTypes[].cTypeHash - The hash of the  Ctype on chain.
 * @param cTypes[].trustedAttesters - An optional array of trusted attester DIDs.
 * @param cTypes[].requiredProperties - An optional array of required property names.
 * @param owner - An optional owner DID for the credential.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Only used for tests
 * @returns A promise that resolves to an object containing the encrypted request message, the request message itself, and the challenge.
 */
export async function requestCredential(
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback }: ISession,
  cTypes: Array<{
    cTypeHash: CTypeHash
    trustedAttesters?: Did[]
    requiredProperties?: string[]
  }>,
  owner?: Did,
  {
    resolveKey,
  }: {
    resolveKey?: typeof dereference
  } = {}
): Promise<ICredentialRequest> {
  const challenge = randomAsHex(24)

  cTypes.map(async (ctype) => {
    await CType.fetchFromChain(`kilt:ctype:${ctype.cTypeHash}`)
  })

  const body: IRequestCredential = {
    content: {
      cTypes,
      challenge,
      owner,
    },
    type: 'request-credential',
  }

  const { did: sender } = parse(senderEncryptionKeyUri)
  const { did: receiver } = parse(receiverEncryptionKeyUri)

  const message = fromBody(body, sender, receiver) as IMessage<IRequestCredential>

  return {
    encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri, { resolveKey }),
    message,
    challenge,
  }
}

/**
 * Verifies a submitted credential message, ensuring its validity.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param session - An object containing session information.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param requestMessage - The previous request message.
 * @param challenge - The challenge associated with the credential request.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional)
 * @throws Error if the decrypted message points to the wrong previous message.
 * @throws Error if the original message is not a request credential message.
 * @throws Error if the decrypted message is not a submit credential message.
 * @throws Error if the message body validation fails.
 * @returns The decrypted message containing the submitted credential.
 */
export async function verifySubmittedCredentialMessage(
  encryptedMessage: IEncryptedMessage<ISubmitCredential>,
  { decryptCallback }: ISession,
  { message: requestMessage, challenge }: ICredentialRequest,
  {
    resolveKey,
  }: {
    resolveKey?: typeof dereference
  } = {}
): Promise<IMessage<ISubmitCredential>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })

  if (decryptedMessage.inReplyTo !== requestMessage.messageId) {
    throw new Error('Wrong Reply. Decrypted message points to wrong previous message')
  }

  if (!isIRequestCredential(requestMessage)) {
    throw new Error('Wrong message. Expected request credential message')
  }

  if (!isSubmitCredential(decryptedMessage)) {
    throw new Error('Wrong message. Expected submit credential message')
  }

  await validateMessageBody(decryptedMessage, requestMessage, challenge)

  return decryptedMessage
}

/**
 * Validates the message body of a submitted credential message.
 * @param decryptedMessage - The decrypted message containing the submitted credential.
 * @param originalMessage - The original request message.
 * @param challenge - The challenge associated with the credential request.
 * @throws Error if the ctype or user doesn't match.
 * @throws Error if credential presentation verification fails.
 */
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

    await Credential.verifyPresentation(credentialPresentation, { challenge })
  })
}
