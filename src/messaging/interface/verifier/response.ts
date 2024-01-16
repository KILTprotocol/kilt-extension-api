/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { CType } from '@kiltprotocol/credentials'
import { Credential } from '@kiltprotocol/legacy-credentials'
import { dereference, parse } from '@kiltprotocol/did'

import { ICredential } from '@kiltprotocol/types'

import type { ISession, IEncryptedMessage, ISubmitCredential } from '../../../types/index.js'
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
 * @param session.authenticationSigner - A signer interface for signing with your DID's authentication method.
 * @param options - Additional options for the function.
 * @param options.dereferenceDidUrl - An alternative function for resolving DIDs and verification methods (Optional).
 * @throws Error if the decrypted message is not a request credential message.
 * @throws Error if credentials do not match.
 * @returns A promise that resolves to an encrypted message containing the submitted credentials.
 */
export async function submitCredential(
  credentials: ICredential[],
  encryptedMessage: IEncryptedMessage,
  {
    decryptCallback,
    senderEncryptionKeyUri,
    receiverEncryptionKeyUri,
    encryptCallback,
    authenticationSigner,
  }: ISession,
  {
    dereferenceDidUrl,
  }: {
    dereferenceDidUrl?: typeof dereference
  } = {}
): Promise<IEncryptedMessage<ISubmitCredential>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { dereferenceDidUrl })
  assertKnownMessage(decryptedMessage)

  if (!isIRequestCredential(decryptedMessage)) {
    throw new Error('Wrong message. Expected request credential message')
  }

  const { challenge, cTypes, owner } = decryptedMessage.body.content

  const content = await Promise.all(
    cTypes.map(async (ctype) => {
      await CType.fetchFromChain(`kilt:ctype:${ctype.cTypeHash}`)
      const filteredCredential = credentials.filter(
        (c) => c.claim.cTypeHash === ctype.cTypeHash && (owner ? c.claim.owner === owner : true)
      )

      if (filteredCredential.length === 0) {
        throw new Error('Credentials do not match')
      }

      return await Credential.createPresentation({
        credential: filteredCredential[0],
        signers: [authenticationSigner],
        selectedAttributes: ctype.requiredProperties,
        challenge,
      })
    })
  )

  const body: ISubmitCredential = {
    content,
    type: 'submit-credential',
  }

  const { did: sender } = parse(senderEncryptionKeyUri)
  const { did: receiver } = parse(receiverEncryptionKeyUri)

  const message = fromBody(body, sender, receiver)
  message.inReplyTo = decryptedMessage.messageId
  return encrypt(message, encryptCallback, receiverEncryptionKeyUri, { dereferenceDidUrl })
}
