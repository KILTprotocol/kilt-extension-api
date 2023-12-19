/**
 * Copyright (c) 2018-2023, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { DecryptCallback, DidResolveKey, DidResourceUri, EncryptCallback } from '@kiltprotocol/types'
import * as Did from '@kiltprotocol/did'
import * as MessageError from './Error.js'
import { hexToU8a, stringToU8a, u8aToHex, u8aToString } from '@polkadot/util'

import type { IEncryptedMessage, IEncryptedMessageContents, IMessage } from '../types/index.js'

/**
 * Checks if the message object is well-formed.
 *
 * @param message The message object.
 */
export function verifyMessageEnvelope(message: IMessage): void {
  const { messageId, createdAt, receiver, sender, receivedAt, inReplyTo } = message
  if (messageId !== undefined && typeof messageId !== 'string') {
    throw new TypeError('Message id is expected to be a string')
  }
  if (createdAt !== undefined && typeof createdAt !== 'number') {
    throw new TypeError('Created at is expected to be a number')
  }
  if (receivedAt !== undefined && typeof receivedAt !== 'number') {
    throw new TypeError('Received at is expected to be a number')
  }
  Did.validateUri(sender, 'Did')
  Did.validateUri(receiver, 'Did')
  if (inReplyTo && typeof inReplyTo !== 'string') {
    throw new TypeError('In reply to is expected to be a string')
  }
}

/**
 * Symmetrically decrypts the result of [[encrypt]].
 *
 * @param encrypted The encrypted message.
 * @param decryptCallback The callback to decrypt with the secret key.
 * @param decryptionOptions Options to perform the decryption operation.
 * @param decryptionOptions.resolveKey The DID key resolver to use.
 * @returns The original [[Message]].
 */
export async function decrypt(
  encrypted: IEncryptedMessage,
  decryptCallback: DecryptCallback,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<IMessage> {
  const { senderKeyUri, receiverKeyUri, ciphertext, nonce, receivedAt } = encrypted

  const senderKeyDetails = await resolveKey(senderKeyUri, 'keyAgreement')

  const { fragment } = Did.parse(receiverKeyUri)
  if (!fragment) {
    throw new MessageError.DidError(`No fragment for the receiver key ID "${receiverKeyUri}"`)
  }

  let data: Uint8Array
  try {
    data = (
      await decryptCallback({
        peerPublicKey: senderKeyDetails.publicKey,
        data: hexToU8a(ciphertext),
        nonce: hexToU8a(nonce),
        keyUri: receiverKeyUri,
      })
    ).data
  } catch (cause) {
    throw new MessageError.DecodingMessageError(cause as string)
  }

  const decoded = u8aToString(data)

  const { body, createdAt, messageId, inReplyTo, references, sender, receiver } = JSON.parse(
    decoded
  ) as IEncryptedMessageContents
  const decrypted: IMessage = {
    receiver,
    sender,
    createdAt,
    body,
    messageId,
    receivedAt,
    inReplyTo,
    references,
  }

  verifyMessageEnvelope(decrypted)
  if (sender !== senderKeyDetails.controller) {
    throw new MessageError.IdentityMismatchError(
      'Encryption key',
      `Sender: ${sender}, found: ${senderKeyDetails.controller}`
    )
  }

  return decrypted
}

/**
 * Encrypts the [[Message]] as a string.
 *
 * @param message The message to encrypt.
 * @param encryptCallback The callback to encrypt with the secret key.
 * @param receiverKeyUri The key URI of the receiver.
 * @param encryptionOptions Options to perform the encryption operation.
 * @param encryptionOptions.resolveKey The DID key resolver to use.
 *
 * @returns The encrypted version of the original [[Message]], see [[IEncryptedMessage]].
 */
export async function encrypt(
  message: IMessage,
  encryptCallback: EncryptCallback,
  receiverKeyUri: DidResourceUri,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<IEncryptedMessage> {
  verifyMessageEnvelope(message)
  const receiverKey = await resolveKey(receiverKeyUri, 'keyAgreement')
  if (message.receiver !== receiverKey.controller) {
    throw new MessageError.IdentityMismatchError('receiver public key', 'receiver')
  }

  const toEncrypt: IEncryptedMessageContents = {
    body: message.body,
    createdAt: message.createdAt,
    sender: message.sender,
    receiver: message.receiver,
    messageId: message.messageId,
    inReplyTo: message.inReplyTo,
    references: message.references,
  }

  const serialized = stringToU8a(JSON.stringify(toEncrypt))

  const encrypted = await encryptCallback({
    did: message.sender,
    data: serialized,
    peerPublicKey: receiverKey.publicKey,
  })

  const ciphertext = u8aToHex(encrypted.data)
  const nonce = u8aToHex(encrypted.nonce)

  return {
    receivedAt: message.receivedAt,
    ciphertext,
    nonce,
    senderKeyUri: encrypted.keyUri,
    receiverKeyUri: receiverKey.id,
  }
}
